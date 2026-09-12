"""Rules 14-15: fetch, transform, health-check and publish the subscription.

    python scripts/build.py

Sources come from sources.txt in the repository root, one URL per line. Both
plain-text and base64-encoded subscription lists work; the format is detected.

Environment overrides:
    SOURCE_URLS       one or more URLs (comma- or whitespace-separated),
                      overriding sources.txt. SOURCE_URL is accepted too.
    XRAY_BIN          path to the Xray-core binary (default: search PATH, then bin/xray)
    OUTPUT_DIR        where configs.txt is written (default: repository root)
    SKIP_HEALTHCHECK  set to 1 to skip rule 14, for local dry runs
    HEALTHCHECK_ROUNDS number of independent rounds a node must pass (default 3)
    MAX_NODES_TO_TEST most nodes the health check may test (default 50000)
"""

from __future__ import annotations

import base64
import binascii
import http.client
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import healthcheck  # noqa: E402
import transform  # noqa: E402
from nodes import parse_line  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Change or add sources by editing sources.txt -- one URL per line, no code
# change needed. Used only if that file is missing or has no usable lines.
SOURCES_FILE = os.path.join(REPO_ROOT, "sources.txt")
DEFAULT_SOURCES = (
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
)
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", REPO_ROOT)
OUTPUT_FILE = "configs.txt"
OUTPUT_FILE_BASE64 = "configs_base64.txt"

PROFILE_TITLE = "Free-Configs"
PROFILE_PAGE = "https://github.com/patterniha/Free-Configs"
# How often a client should re-fetch, in days, matching the workflow's cadence.
UPDATE_INTERVAL_DAYS = 1

FETCH_ATTEMPTS = 4
FETCH_TIMEOUT = 45

# Transient fetch failures worth another attempt. http.client.HTTPException is
# here for IncompleteRead and BadStatusLine, which are not OSError subclasses:
# a truncated response is the most likely partial-data failure, and without it
# the retry loop is bypassed and the error escapes as a traceback.
RETRYABLE_FETCH_ERRORS = (urllib.error.URLError, OSError, http.client.HTTPException)

# An unattended daily job must never publish an empty subscription: if a run
# yields fewer than this, the previous configs.txt is left in place and the
# workflow fails loudly instead.
MIN_HEALTHY_NODES = 1

# Ceiling on how many nodes the health check is allowed to test. The pool grows
# every time a source is added, and the health check is the expensive stage, so
# this is what stops a run from outgrowing the workflow timeout. Nodes beyond
# the cap are discarded before testing, never published untested.
MAX_NODES_TO_TEST = int(os.environ.get("MAX_NODES_TO_TEST", "50000"))


def is_permanent_http_error(error: BaseException) -> bool:
    """True for a client error that will not change on a retry. 408 and 429 are
    excluded: those explicitly mean "try again"."""
    return (
        isinstance(error, urllib.error.HTTPError)
        and 400 <= error.code < 500
        and error.code not in (408, 429)
    )


def load_sources() -> list[str]:
    """Where the upstream lists come from, in order of precedence:
    the SOURCE_URLS/SOURCE_URL environment variables, then sources.txt, then
    the built-in default."""
    from_env = os.environ.get("SOURCE_URLS") or os.environ.get("SOURCE_URL")
    if from_env:
        # Accept commas, whitespace or newlines as separators.
        urls = _clean(from_env.replace(",", "\n").split())
        if urls:
            return urls

    if os.path.exists(SOURCES_FILE):
        # utf-8-sig, not utf-8: Notepad writes a BOM by default, and it would
        # otherwise end up glued to the first URL as ﻿https://...
        with open(SOURCES_FILE, encoding="utf-8-sig") as handle:
            urls = _clean(
                line for line in handle if not line.lstrip().lstrip("﻿").startswith("#")
            )
        if urls:
            return urls

    return list(DEFAULT_SOURCES)


def _clean(lines) -> list[str]:
    """Trim, drop blanks, strip any stray BOM, and drop repeats while keeping
    the original order -- listing a URL twice should not fetch it twice."""
    seen: set[str] = set()
    cleaned: list[str] = []
    for line in lines:
        url = line.strip().lstrip("﻿").strip()
        if url and url not in seen:
            seen.add(url)
            cleaned.append(url)
    return cleaned


def decode_if_base64(text: str) -> str:
    """Many subscription URLs serve the list base64-encoded. Detect that and
    decode, so adding a source does not mean caring which form it uses."""
    # Scan the whole body, not a prefix: a list can open with a long comment
    # header. Base64's alphabet has no ":", so a "://" anywhere proves the
    # body is already plain text.
    if "://" in text:
        return text
    compact = "".join(text.split())
    if not compact:
        return text
    try:
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)
    except (ValueError, binascii.Error):
        return text
    candidate = decoded.decode("utf-8", "replace")
    return candidate if "://" in candidate else text


def fetch_all(urls: list[str]) -> tuple[list[str], list[str]]:
    """Fetch every source and return (lines, failed_urls).

    A source that fails does not sink the build -- the others still publish --
    but it is reported, and main() stops if every source failed.
    """
    lines: list[str] = []
    failed: list[str] = []
    for url in urls:
        try:
            body = decode_if_base64(fetch(url))
        except SystemExit as error:
            print(f"  ! {url}: {error}")
            failed.append(url)
            continue
        found = body.splitlines()
        usable = sum(1 for line in found if parse_line(line) is not None)
        print(f"  {url}\n      {len(found)} lines, {usable} usable configs")
        lines.extend(found)
    return lines, failed


def fetch(url: str) -> str:
    last_error: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "Free-Configs/1.0 (+https://github.com/patterniha)"}
            )
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
                return response.read().decode("utf-8", "replace")
        except ValueError as error:
            # urllib raises ValueError, not URLError, for a URL with no scheme
            # -- the likeliest typo in a hand-edited sources.txt. Left to
            # escape it would kill the whole build, taking the healthy sources
            # with it, and print a traceback instead of naming the bad line.
            raise SystemExit(f"could not fetch {url}: {error}") from None
        except RETRYABLE_FETCH_ERRORS as error:
            if is_permanent_http_error(error):
                # A wrong or removed URL will answer the same way every time;
                # retrying it just delays the other sources.
                raise SystemExit(f"could not fetch {url}: {error}") from None
            last_error = error
            print(f"  fetch attempt {attempt}/{FETCH_ATTEMPTS} failed: {error}")
            if attempt < FETCH_ATTEMPTS:
                time.sleep(3 * attempt)
    raise SystemExit(f"could not fetch {url}: {last_error}")


def cap_nodes(nodes: list, limit: int) -> list:
    """Trim the pool to ``limit`` nodes.

    This used to interleave two port buckets and rank source nodes above the
    twins rule 9 invented. Rule 9 converts rather than duplicates now, so every
    node is an original on port 443 and there is nothing left to balance or
    rank -- the first ``limit`` will do, and keeping input order makes the
    choice deterministic.
    """
    return nodes if len(nodes) <= limit else nodes[:limit]


def locate_xray() -> str:
    explicit = os.environ.get("XRAY_BIN")
    if explicit:
        if not os.path.exists(explicit):
            raise SystemExit(f"XRAY_BIN points at a missing file: {explicit}")
        return explicit
    found = shutil.which("xray")
    if found:
        return found
    for candidate in (
        os.path.join(REPO_ROOT, "bin", "xray"),
        os.path.join(REPO_ROOT, "bin", "xray.exe"),
    ):
        if os.path.exists(candidate):
            return candidate
    raise SystemExit(
        "Xray-core binary not found. Set XRAY_BIN, or place it at bin/xray. "
        "v26.6.22 or newer is required: earlier builds reject the fragment "
        "'lengths'/'delays' arrays used by the fm parameter."
    )


def existing_links(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def render(links: list[str], counts: dict, sources: list[str]) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        f"#profile-title: {PROFILE_TITLE}",
        f"#profile-update-interval: {UPDATE_INTERVAL_DAYS}",
        f"#profile-web-page-url: {PROFILE_PAGE}",
        (
            f"# {len(links)} configs from {len(links) // counts['published_variants']} healthy nodes"
            f" x {counts['published_variants']} fm/dialMode variants,"
            f" tested from {counts.get('final_total', 0)}"
            if counts.get("published_variants", 1) > 1
            else f"# {len(links)} nodes, from {counts.get('final_total', 0)} tested"
        ),
        f"# generated {stamp} from {len(sources)} source(s):",
        *(f"#   {url}" for url in sources),
        f"# criterion: a real proxied request succeeded in all"
        f" {counts.get('rounds', healthcheck.ROUNDS)} independent runs,"
        " one per endpoint:",
        *(
            f"#   https://{host}"
            for host in counts.get(
                "endpoints", [e.host for e in healthcheck.TEST_ENDPOINTS]
            )
        ),
    ]
    # Say plainly what was tested and what was not: fm and dialMode go on after
    # the check, so the criterion above is a claim about the nodes, not about
    # the masking they ship with.
    deferred = [
        name
        for name, key in (("fm", "published_with_fm"), ("dialMode", "published_with_dial_mode"))
        if counts.get(key)
    ]
    if deferred:
        header.append(
            f"# {' and '.join(deferred)} applied after testing, to nodes that had already passed"
        )
    if "flaky_percent" in counts:
        header.append(
            f"# {counts['flaky_percent']}% of nodes that worked at least once"
            " failed at least one run"
        )
    return "\n".join(header + links) + "\n"


def main() -> int:
    counts: dict = {}

    sources = load_sources()
    print(f"Fetching {len(sources)} source(s)")
    lines, failed = fetch_all(sources)
    counts["sources"] = len(sources)
    counts["sources_failed"] = len(failed)

    if failed and len(failed) == len(sources):
        print(
            f"ERROR: every source failed ({len(failed)}/{len(sources)});"
            f" leaving {OUTPUT_FILE} untouched",
            file=sys.stderr,
        )
        return 1
    if failed:
        print(f"  ! continuing without {len(failed)} unreachable source(s)")

    # Sources overlap heavily, so drop repeats before anything expensive runs.
    # Comparing raw text would miss most of them: the same node routinely
    # appears under a different #comment, or with its query parameters in a
    # different order. Both are cosmetic. Node.identity() compares what the
    # node actually is -- protocol, credentials, address, port and parameters
    # as a sorted set, with the display name excluded -- so reordered fields
    # and renamed copies collapse together. The comment is kept on the copy
    # that survives and is carried through to configs.txt.
    seen: set = set()
    nodes = []
    duplicates = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        node = parse_line(stripped)
        if node is None:
            continue
        key = node.identity()
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        nodes.append(node)
    counts["parsed"] = len(nodes)
    counts["duplicates_dropped"] = duplicates
    print(
        f"  {len(nodes)} distinct configs parsed"
        f" ({duplicates} duplicates dropped, ignoring name and field order)"
    )

    if not nodes:
        # A 200 response can still be the wrong thing -- an error page, or a
        # source that changed format. Say so now rather than after a health
        # check that had nothing to test.
        print(
            f"ERROR: no usable configs parsed from {len(sources)} source(s);"
            f" leaving {OUTPUT_FILE} untouched",
            file=sys.stderr,
        )
        return 1

    print("Applying rules 1-12 (pre-health-check)")
    transformed = transform.transform(nodes, counts)
    for key in (
        "dropped_vmess_cannot_carry_fm",
        "dropped_rule_1_security",
        "dropped_rule_2_transport",
        "dropped_rule_3_no_host",
        "dropped_rule_4_port",
        "dropped_rule_7_8080_with_tls",
        "converted_to_tls_rule_9",
        "dropped_rule_8_443_without_tls",
        "kept_after_rules_1_to_8",
        "dropped_duplicate",
    ):
        if counts.get(key):
            print(f"  {key}: {counts[key]}")
    print(f"  {counts['final_total']} nodes to test")

    if len(transformed) > MAX_NODES_TO_TEST:
        dropped = len(transformed) - MAX_NODES_TO_TEST
        transformed = cap_nodes(transformed, MAX_NODES_TO_TEST)
        counts["dropped_over_cap"] = dropped
        counts["final_total"] = len(transformed)
        print(f"  capped to {MAX_NODES_TO_TEST} nodes for the health check"
              f" ({dropped} dropped)")

    if os.environ.get("SKIP_HEALTHCHECK") == "1":
        print("Skipping rule 14 (SKIP_HEALTHCHECK=1)")
        healthy = transformed
    else:
        rounds = int(os.environ.get("HEALTHCHECK_ROUNDS", healthcheck.ROUNDS))
        counts["rounds"] = rounds
        xray = locate_xray()
        print(f"Health check via {xray} ({rounds} rounds)")
        unsupported = healthcheck.preflight(xray)
        if unsupported:
            print("ERROR: this Xray-core build does not support:", file=sys.stderr)
            for item in unsupported:
                print(f"  - {item}", file=sys.stderr)
            print(
                "Use a build of https://github.com/patterniha/Xray-core based on"
                " v26.6.22 or newer.",
                file=sys.stderr,
            )
            return 1
        healthy = healthcheck.check(xray, transformed, counts, rounds=rounds)
        print(f"  {len(healthy)} healthy")

    if len(healthy) < MIN_HEALTHY_NODES:
        print(
            f"ERROR: only {len(healthy)} healthy nodes"
            f" (minimum {MIN_HEALTHY_NODES}); leaving {OUTPUT_FILE} untouched",
            file=sys.stderr,
        )
        return 1

    # Only now do the survivors become publishable links: fm and dialMode were
    # withheld so the health check measured the nodes rather than the masking,
    # and the output endpoint is a separate setting from the tested one. One
    # survivor becomes one config per FM/DIAL_MODE pair, so this is also where
    # the published list can grow past the number of nodes tested.
    published = transform.finalise(healthy, counts)
    variants = counts.get("published_variants", 1)
    print(
        f"Finalising {len(healthy)} healthy nodes"
        + (f" x {variants} fm/dialMode variants = {len(published)} configs" if variants > 1 else "")
        + f", publishing on {transform.OUTPUT_ADDRESS}:{transform.OUTPUT_PORT}"
    )

    links = [node.to_link() for node in published]
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    base64_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE_BASE64)

    # Compared as a set, not a list: the health check orders by measured
    # latency, which drifts run to run, so an order-sensitive comparison would
    # rewrite the file and commit every day even when nothing actually changed.
    # The base64 file must exist too, or a deleted one would never come back.
    if set(links) == set(existing_links(output_path)) and os.path.exists(base64_path):
        print(f"{OUTPUT_FILE} already up to date ({len(links)} nodes); not rewriting")
        return 0

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    document = render(links, counts, sources)
    with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(document)
    with open(base64_path, "w", encoding="ascii", newline="\n") as handle:
        handle.write(base64.b64encode(document.encode("utf-8")).decode("ascii") + "\n")

    print(f"Wrote {output_path} ({len(links)} nodes) and {base64_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
