"""Rule 14: keep only nodes that actually carry traffic.

Reimplements the criterion the upstream project publishes in its own header --
"a real proxied request to https://cp.cloudflare.com/generate_204 succeeded in
ALL 3 independent runs" -- directly against Xray-core rather than a wrapper, so
the ``fp=unsafe`` and ``cs`` parameters in the emitted links are the ones being
exercised.

The nodes reaching this stage deliberately carry no ``fm`` or ``dialMode``:
those change how a connection is made rather than whether the node works, and
transform.finalise adds them to the survivors afterwards. :func:`preflight`
therefore validates the published shape as well as the tested one, because
nothing else in the pipeline ever feeds an ``fm`` to the core.

Shape of a round: nodes are grouped into batches; each batch becomes one Xray
process with one loopback HTTP inbound per node, routed to that node's outbound.
Every node is then probed concurrently through its own inbound. Three rounds run
and only the intersection survives, because a single run misgrades a substantial
fraction of nodes -- upstream measured 25-64% of working nodes as flaky.

The default outbound is a blackhole, so a node whose routing rule somehow fails
to match cannot fall through to a direct connection and report itself healthy.

Two comparable projects were reviewed for ideas. Delta-Kronecker/V2ray-Config
(src/validator.go) also runs a real proxied request, and its list of test URLs
is where TEST_ENDPOINTS below comes from. itsyebekhe/PSG (main.py) does not
proxy at all -- it checks DNS plus a TCP connect, which cannot tell a live
proxy from any host with an open port.

Three of their techniques are deliberately not used here:

* A TCP-ping prefilter (both projects). Rule 10 points every node at the same
  Cloudflare address, so a TCP connect always succeeds and filters nothing.
* Retrying failed configs (Delta-Kronecker retries in rounds). That is the
  opposite of requiring 3 of 3: a retry hands a flaky node extra chances to
  pass, which is what the intersection exists to stop.
* Static per-protocol field validation (PSG). Already covered -- xray run -test
  validates every config first and the bisect isolates whatever it rejects.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import statistics
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from typing import NamedTuple

import transform
from nodes import Node


class TestEndpoint(NamedTuple):
    host: str
    path: str
    statuses: tuple[int, ...]


# One endpoint per round, rotating, so a node has to satisfy three independent
# operators rather than the same target three times. Testing only Cloudflare
# would mean every node both exits through Cloudflare and is judged by it, and
# a single endpoint being blocked or down would read as "every node is dead".
# Borrowed from Delta-Kronecker/V2ray-Config, which tests against a list of
# URLs; the per-round rotation is the adaptation that keeps the cost identical.
TEST_ENDPOINTS: tuple[TestEndpoint, ...] = (
    TestEndpoint("cp.cloudflare.com", "/generate_204", (204,)),
    TestEndpoint("www.gstatic.com", "/generate_204", (204,)),
    TestEndpoint("captive.apple.com", "/hotspot-detect.html", (200,)),
)
ENDPOINT_CHECK_TIMEOUT = 10.0
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"

ROUNDS = 3                 # a node must pass every round
REQUEST_TIMEOUT = 5.0      # seconds, matches upstream's 5000ms budget
# These two are independent, and were measured separately on 192 nodes.
#
# BATCH_SIZE is how many nodes share one Xray process. The fixed cost of a
# round is starting and stopping Xray, so fewer, larger batches are simply
# cheaper: 32 took 52s, 64 took 38s, 96 took 36s, and 96 reproduced every pass
# that 32 found. No accuracy is traded away for this.
#
# PROBE_WORKERS is how many nodes are probed at once, so it is the one that
# could cause spurious timeouts under contention. Lowering it does NOT recover
# nodes: at batch 96, workers 96/32/12/4 passed 83/88/80/79 while taking
# 29s/41s/75s/194s. Across those four runs the union was 90 and the
# intersection 66, so about 27% of results move run to run no matter what --
# node flakiness, larger than any gap between the settings. 32 keeps
# simultaneous network load modest without paying the 6x that 4 costs.
BATCH_SIZE = 96            # nodes per Xray process
PROBE_WORKERS = 32         # concurrent probes within a batch
# Loopback ports are asked of the OS rather than fixed. A hardcoded range
# fails wholesale if anything else on the machine already listens in it, and
# the failure looks like "every node in this batch is dead". Idea taken from
# 4n0nymou3/multi-proxy-config-fetcher, which allocates per config; this
# reserves the whole batch at once so no two inbounds can collide.
PORT_RESERVE_ATTEMPTS = 3
STARTUP_TIMEOUT = 15.0     # seconds to wait for Xray to bind its inbounds
SHUTDOWN_TIMEOUT = 5.0
PAUSE_BETWEEN_ROUNDS = 3.0


class HealthCheckError(RuntimeError):
    pass


def _build_config(batch: list[Node], ports: list[int]) -> dict:
    inbounds: list[dict] = []
    # The blackhole is listed first so it is Xray's default outbound: anything
    # not matched by an explicit rule is dropped rather than sent out directly.
    outbounds: list[dict] = [{"tag": "block", "protocol": "blackhole"}]
    rules: list[dict] = []

    for index, node in enumerate(batch):
        in_tag = f"in-{index}"
        out_tag = f"out-{index}"
        inbounds.append(
            {
                "tag": in_tag,
                "listen": "127.0.0.1",
                "port": ports[index],
                "protocol": "http",
                "settings": {},
            }
        )
        outbounds.append(node.to_outbound(out_tag))
        rules.append({"type": "field", "inboundTag": [in_tag], "outboundTag": out_tag})

    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "block"})
    return {
        "log": {"loglevel": "error"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules},
    }


def _placeholder_ports(count: int) -> list[int]:
    """Port numbers for configs that are only validated, never run. ``xray run
    -test`` binds nothing, so these need to be well-formed, not free."""
    return list(range(21080, 21080 + count))


def reserve_ports(count: int) -> list[int]:
    """Ask the OS for ``count`` free loopback ports.

    Every socket is held open until the whole set is chosen, so the OS cannot
    hand the same port out twice within one batch. They are released just
    before Xray binds them: a foreign process could still take one in that
    window, which is why a batch that fails to come up is reported rather than
    silently counted as dead nodes.
    """
    for attempt in range(PORT_RESERVE_ATTEMPTS):
        holders: list[socket.socket] = []
        try:
            for _ in range(count):
                holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                holder.bind(("127.0.0.1", 0))
                holders.append(holder)
            ports = [h.getsockname()[1] for h in holders]
            if len(set(ports)) == count:
                return ports
        except OSError:
            if attempt == PORT_RESERVE_ATTEMPTS - 1:
                raise
        finally:
            for holder in holders:
                holder.close()
    raise HealthCheckError(f"could not reserve {count} free ports")


def _write_config(config: dict, directory: str, name: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False)
    return path


def _config_accepted(xray: str, config: dict, directory: str) -> bool:
    """True when Xray parses and builds this config. ``run -test`` validates
    without binding anything, so it is safe to call on overlapping ports."""
    path = _write_config(config, directory, "validate.json")
    try:
        result = subprocess.run(
            [xray, "run", "-test", "-c", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def validate_nodes(
    xray: str, nodes: list[Node], directory: str
) -> tuple[list[Node], list[Node]]:
    """Split ``nodes`` into those Xray accepts and those it rejects.

    Validating a whole group at once costs one process; only when a group fails
    is it bisected, so one malformed node cannot take a whole batch down with it.
    """

    def group_builds(group: list[Node]) -> bool:
        try:
            config = _build_config(group, _placeholder_ports(len(group)))
        except Exception:
            # A node whose outbound cannot even be rendered -- unparseable fm,
            # say -- is a node to reject, not a reason to abandon the run. The
            # bisect below then narrows it down to the one at fault.
            return False
        return _config_accepted(xray, config, directory)

    def recurse(group: list[Node]) -> tuple[list[Node], list[Node]]:
        if not group:
            return [], []
        if group_builds(group):
            return list(group), []
        if len(group) == 1:
            return [], list(group)
        middle = len(group) // 2
        left_ok, left_bad = recurse(group[:middle])
        right_ok, right_bad = recurse(group[middle:])
        return left_ok + right_ok, left_bad + right_bad

    accepted: list[Node] = []
    rejected: list[Node] = []
    for start in range(0, len(nodes), BATCH_SIZE):
        chunk_ok, chunk_bad = recurse(nodes[start : start + BATCH_SIZE])
        accepted.extend(chunk_ok)
        rejected.extend(chunk_bad)
    return accepted, rejected


def preflight(xray: str) -> list[str]:
    """Check that this core understands everything the emitted links rely on.

    Without this, an unsupported parameter shows up as "every node is dead"
    three rounds later, with nothing pointing at the cause. Each probe uses the
    same config shape the health check builds, so a core that accepts these
    accepts the real thing.

    ``cs`` maps to Xray's ``cipherSuites``, which is undocumented, and the
    ``fm`` fragment's ``lengths``/``delays`` arrays only exist in cores based on
    v26.6.22 or newer -- both are worth proving rather than assuming.
    """
    try:
        version = subprocess.run(
            [xray, "version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        # Every later check shells out to this binary, and a failure there would
        # look like "no node works" rather than "the binary is unusable".
        return [f"running '{xray} version' failed: {error}"]
    if version.returncode != 0:
        return [f"'{xray} version' exited {version.returncode}"]
    print(f"  core: {version.stdout.decode('utf-8', 'replace').splitlines()[0]}")

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="xray-preflight-") as directory:
        for description, node in preflight_probes():
            config = _build_config([node], _placeholder_ports(1))
            if not _config_accepted(xray, config, directory):
                failures.append(description)
    return failures


def preflight_probes() -> list[tuple[str, Node]]:
    """The two shapes this pipeline produces: what the health check runs, and
    what the subscription publishes.

    They differ, so both are worth proving. The tested shape carries ``fp`` and
    ``cs``; each published shape adds one variant's ``fm`` and ``dialMode`` on
    top and points at the output endpoint. Every variant gets its own probe,
    because an unusable ``fm`` would otherwise reach configs.txt unchallenged --
    the health check never sees one.

    Both take their address, port and parameter values from transform's own
    constants rather than writing them out again, so repointing an endpoint or
    retuning a mask repoints and retunes what the preflight tests.
    """

    def probe(address: str, port: str, **extra: str) -> Node:
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": "example.com",
            "path": "/",
            "sni": "example.com",
            "fp": transform.FP,
            "cs": transform.CS,
        }
        params.update({k: v for k, v in extra.items() if v})
        return Node(
            scheme="vless",
            uid="00000000-0000-0000-0000-000000000000",
            address=address,
            port=str(port),
            params=params,
        )

    probes = [
        (
            "tested shape (fp=unsafe + cs cipherSuites)",
            probe(transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT),
        )
    ]
    total = len(transform.VARIANTS)
    for index, variant in enumerate(transform.VARIANTS):
        carries = "fm fragment" if variant.fm else "no fm"
        if variant.dial_mode:
            carries += f" + dialMode {variant.dial_mode}"
        where = f" {index + 1}/{total}" if total > 1 else ""
        probes.append(
            (
                f"published shape{where} ({carries})",
                probe(
                    transform.OUTPUT_ADDRESS,
                    transform.OUTPUT_PORT,
                    fm=variant.fm,
                    dialMode=variant.dial_mode,
                ),
            )
        )
    return probes


def _wait_until_listening(
    ports: list[int], deadline: float, process: subprocess.Popen | None = None
) -> bool:
    for port in ports:
        while True:
            if process is not None and process.poll() is not None:
                return False  # Xray exited; no point waiting out the deadline
            if time.monotonic() > deadline:
                return False
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.05)
    return True


def _log_tail(path: str, lines: int = 6) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            tail = [l.rstrip() for l in handle if l.strip()][-lines:]
        return "\n".join("      " + l[:200] for l in tail)
    except OSError:
        return "      (no log)"


def usable_endpoints() -> list[TestEndpoint]:
    """Drop endpoints this machine cannot reach directly.

    A blocked or broken target would otherwise fail every node in its round and
    read as "the whole list is dead". Checked without a proxy, so it measures
    the endpoint rather than any node.
    """
    usable: list[TestEndpoint] = []
    for endpoint in TEST_ENDPOINTS:
        connection = http.client.HTTPSConnection(
            endpoint.host, 443, timeout=ENDPOINT_CHECK_TIMEOUT
        )
        try:
            connection.request(
                "GET", endpoint.path,
                headers={"User-Agent": USER_AGENT, "Connection": "close"},
            )
            response = connection.getresponse()
            response.read()
            if response.status in endpoint.statuses:
                usable.append(endpoint)
            else:
                print(f"  ! {endpoint.host} answered {response.status}; not testing against it")
        except Exception as error:
            print(f"  ! {endpoint.host} unreachable ({type(error).__name__});"
                  " not testing against it")
        finally:
            try:
                connection.close()
            except Exception:
                pass
    return usable


def _probe(port: int, endpoint: TestEndpoint) -> tuple[bool, float]:
    """Fetch the endpoint through the loopback proxy on ``port``.

    ``HTTPSConnection`` + ``set_tunnel`` issues a CONNECT to Xray's HTTP inbound
    and then completes TLS end-to-end with the target, so a node that cannot
    carry a real TLS session cannot pass.
    """
    started = time.monotonic()
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=REQUEST_TIMEOUT)
    try:
        connection.set_tunnel(endpoint.host, 443)
        connection.request(
            "GET", endpoint.path, headers={"User-Agent": USER_AGENT, "Connection": "close"}
        )
        response = connection.getresponse()
        response.read()
        elapsed = (time.monotonic() - started) * 1000.0
        return response.status in endpoint.statuses, elapsed
    except Exception:
        return False, (time.monotonic() - started) * 1000.0
    finally:
        try:
            connection.close()
        except Exception:
            pass


def _run_batch(
    xray: str, batch: list[Node], directory: str, label: str, endpoint: TestEndpoint
) -> dict[int, float]:
    """Return ``{index within batch: latency ms}`` for the nodes that passed."""
    if not batch:
        return {}
    try:
        ports = reserve_ports(len(batch))
    except (OSError, HealthCheckError) as error:
        # One batch failing to get ports is not a reason to abandon the run and
        # lose the rounds already completed. Report it and treat the batch as
        # untested, exactly as a failed Xray start is treated below.
        print(f"  ! {label}: could not reserve {len(batch)} ports ({error});"
              f" {len(batch)} nodes not tested this round")
        return {}
    config = _build_config(batch, ports)
    config_path = _write_config(config, directory, f"{label}.json")
    log_path = os.path.join(directory, f"{label}.log")

    with open(log_path, "wb") as log_handle:
        process = subprocess.Popen(
            [xray, "run", "-c", config_path],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + STARTUP_TIMEOUT
            if not _wait_until_listening([ports[0], ports[-1]], deadline, process):
                # Distinguish "Xray never came up" from "every node failed" --
                # otherwise a bind error silently reads as 32 dead nodes.
                print(
                    f"  ! {label}: Xray did not start (exit={process.poll()});"
                    f" {len(batch)} nodes not tested this round"
                )
                print(_log_tail(log_path))
                return {}
            with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
                results = list(
                    pool.map(lambda i: _probe(ports[i], endpoint), range(len(batch)))
                )
        finally:
            process.terminate()
            try:
                process.wait(timeout=SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    return {i: latency for i, (ok, latency) in enumerate(results) if ok}


def check(
    xray: str, nodes: list[Node], stats: dict | None = None, rounds: int = ROUNDS
) -> list[Node]:
    """Return the nodes that passed a real proxied request in every round,
    ordered fastest-first by median latency across the rounds."""
    counts: dict = stats if stats is not None else {}
    if not nodes:
        counts["healthy"] = 0
        return []

    endpoints = usable_endpoints()
    if not endpoints:
        raise HealthCheckError(
            "no test endpoint is reachable, so nothing can be measured; "
            "leaving the previous list in place"
        )
    counts["endpoints"] = [e.host for e in endpoints]

    with tempfile.TemporaryDirectory(prefix="xray-healthcheck-") as directory:
        accepted, rejected = validate_nodes(xray, nodes, directory)
        counts["rejected_by_xray"] = len(rejected)
        counts["validated"] = len(accepted)
        for node in rejected:
            print(f"  ! Xray rejected: {node.tag or node.to_link()[:80]}")
        if not accepted:
            counts["healthy"] = 0
            return []

        latencies: dict[int, list[float]] = {i: [] for i in range(len(accepted))}
        survivors = set(range(len(accepted)))

        for round_number in range(1, rounds + 1):
            # Rotate: three rounds against three operators is a stronger claim
            # than three rounds against one, at identical cost.
            endpoint = endpoints[(round_number - 1) % len(endpoints)]
            passed: set[int] = set()
            for start in range(0, len(accepted), BATCH_SIZE):
                batch = accepted[start : start + BATCH_SIZE]
                label = f"r{round_number}-b{start // BATCH_SIZE}"
                batch_result = _run_batch(xray, batch, directory, label, endpoint)
                for offset, latency in batch_result.items():
                    index = start + offset
                    passed.add(index)
                    latencies[index].append(latency)
            counts[f"round_{round_number}_passed"] = len(passed)
            survivors &= passed
            print(
                f"  round {round_number}/{rounds} via {endpoint.host}: "
                f"{len(passed)}/{len(accepted)} passed, {len(survivors)} still perfect"
            )
            if round_number < rounds:
                time.sleep(PAUSE_BETWEEN_ROUNDS)

    ever_passed = sum(1 for values in latencies.values() if values)
    if ever_passed:
        counts["flaky_percent"] = round(
            100.0 * (ever_passed - len(survivors)) / ever_passed, 2
        )
    counts["healthy"] = len(survivors)

    ordered = sorted(survivors, key=lambda i: (statistics.median(latencies[i]), i))
    for index in ordered:
        accepted[index].latency_ms = round(statistics.median(latencies[index]))
    return [accepted[i] for i in ordered]
