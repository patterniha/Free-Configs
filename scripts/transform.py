"""Rules 1-12: turn the upstream lists into the Cloudflare-fronted node set.

Every numbered rule from the spec is its own function below, named after its
number. The rules run in two phases, and which rule lands in which phase is the
shape of this whole file:

* :func:`transform` runs *before* the health check. It filters (rules 1-8),
  converts plaintext nodes to TLS (rule 9), points every node at the
  health-check endpoint (rule 10), strips what must not be tested (rule 11 and
  :func:`strip_deferred_params`) and applies the masking the check is meant to
  exercise (rule 12: ``fp`` and ``cs``).

* :func:`finalise` runs on the survivors. It adds the parameters that were
  deliberately withheld -- ``fm`` and ``dialMode`` -- and repoints each node at
  the published endpoint, which need not be the one it was tested through.

The split exists because ``fm`` (finalmask) and ``dialMode`` change *how* the
connection is made, not *whether* the node carries traffic. Testing without
them measures the node itself, and adding them afterwards is a client-side
choice that can be retuned without re-testing anything. A node arriving from a
source carrying its own ``fm`` or ``dialMode`` therefore has them removed
before the check, whatever they said, so no source can smuggle its own
fragmentation into the run.

Everything published is TLS on port 443. Nodes arriving on a plaintext
Cloudflare port are converted rather than kept alongside a TLS twin: the ISP
this list is built for blocks unencrypted connections to Cloudflare, so a
port 8080 node is untestable and unusable.

Two normalisations are applied on top of the numbered rules, each marked
NORMALISATION where it happens:

* rule 9 sets ``sni`` to ``host`` when converting, because the node is being
  moved onto TLS and Cloudflare selects the origin by SNI;
* every node gets ``sni`` set to its ``host``, because rule 10 replaces the
  address with a Cloudflare IP -- an ``sni`` still naming the origin server
  would never connect.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import quote, unquote

from nodes import ECH_KEYS, INSECURE_KEYS, Node

# --- rule 10: where nodes point -------------------------------------------
# Two independent pairs. The endpoint a node is *tested* through does not have
# to be the endpoint it is *published* on: the health check proves the node
# answers behind Cloudflare, and which Cloudflare address the published link
# names is a separate decision that can be changed without re-testing. Set both
# pairs to the same values for the old single-endpoint behaviour, which is
# what they hold today.
HEALTHCHECK_ADDRESS = "104.21.33.59"
HEALTHCHECK_PORT = "443"
OUTPUT_ADDRESS = "104.21.33.59"
OUTPUT_PORT = "443"

# --- rules 4-6: port buckets ---------------------------------------------
PORTS_MAPPED_TO_443 = ("443", "2053", "2083", "2087", "2096", "8443")
PORTS_MAPPED_TO_8080 = ("80", "8080", "8880", "2052", "2082", "2086", "2095")

# --- rules 1-2: accepted values ------------------------------------------
ALLOWED_SECURITY = ("", "tls", "none")
ALLOWED_TRANSPORTS = ("ws", "xhttp", "websocket", "httpupgrade", "grpc")

# --- rule 12: masking applied BEFORE the health check ---------------------
# These two describe the TLS handshake itself, so the check has to run with
# them: a node that cannot complete a handshake with this fingerprint and this
# cipher list is not a node this subscription can publish. Stored exactly as
# supplied (percent-encoded) and decoded once at import. The self-check below
# proves re-encoding reproduces these strings byte for byte, so what lands in
# configs.txt is what was asked for.
FP_ENCODED = "unsafe"
CS_ENCODED = (
    "TLS_AES_256_GCM_SHA384%3ATLS_CHACHA20_POLY1305_SHA256%3ATLS_AES_128_GCM_SHA256%3A"
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384%3ATLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384%3A"
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256%3ATLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256%3A"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256%3ATLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    "%3ATLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA%3ATLS_ECDHE_RSA_WITH_AES_256_CBC_SHA%3A"
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256%3ATLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
)

# --- parameters applied AFTER the health check ----------------------------
# fm (finalmask) splits the outgoing packets; dialMode selects which dialing
# code the core runs (streamSettings.sockopt.dialMode, added to the fork in
# a3261029). Neither decides whether a node carries traffic, so both are
# withheld from the check and put on the survivors. Set either to "" to publish
# without it. DIAL_MODE is "" today, and an absent dialMode and dialMode="" are
# the same thing to the core -- both run the default dialer -- so nothing is
# emitted for it and nothing is lost by that.
#
# Note what the split costs: a value here is never exercised by the health
# check. An unusable fm is at least caught by the preflight, which validates
# the published shape against the core before any testing starts. dialMode is
# not, because the core accepts any string at parse time and only rejects one
# it has no code for when it actually dials -- so a dialMode the deployed core
# does not implement would ship as a list that fails at connect time. Keep it
# matched to what that build supports.
FM_ENCODED = (
    "%7B%22tcp%22%3A%20%5B%7B%22type%22%3A%20%22fragment%22%2C%20%22settings%22%3A%20%7B%22"
    "packets%22%3A%20%22tlshello%22%2C%20%22lengths%22%3A%20%5B%220%22%2C%20%22104%22%2C%20%22"
    "1%22%5D%2C%20%22delays%22%3A%20%5B%220%22%5D%2C%20%22maxSplit%22%3A%20%220%22%7D%7D%2C%7B"
    "%22type%22%3A%20%22fragment%22%2C%20%22settings%22%3A%20%7B%22packets%22%3A%20%221-1%22%2C"
    "%20%22lengths%22%3A%20%5B%22114%22%2C%20%221%22%5D%2C%20%22delays%22%3A%20%5B%221%22%5D%2C"
    "%20%22maxSplit%22%3A%20%2211%22%7D%7D%5D%7D"
)
DIAL_MODE_ENCODED = ""

FP = unquote(FP_ENCODED)
CS = unquote(CS_ENCODED)
FM = unquote(FM_ENCODED)
DIAL_MODE = unquote(DIAL_MODE_ENCODED)

# The two parameters :func:`finalise` owns, in every spelling. They are removed
# on the way in and set on the way out, so whatever a source supplied has no
# influence on either the health check or the published value.
DEFERRED_KEYS = ("fm", "dialmode")

# A vmess share link is base64'd JSON with a fixed key set, and that key set has
# nowhere to put fm or cs -- so a vmess node cannot satisfy rule 12 and would
# ship without the fragmentation every other node gets. They are dropped rather
# than published as silent exceptions. Set True to publish them unmasked anyway.
INCLUDE_VMESS = False

# Keep each source's own comment (everything after "#") in the published name.
# It cannot stand alone, though: one source labels all of its several thousand
# nodes "@DeltaKroneckerGithub", so on its own the comment would leave most
# entries indistinguishable in a client. A short content hash is appended to
# tell them apart. Set KEEP_SOURCE_COMMENT False for generated names only.
RENAME_NODES = True
KEEP_SOURCE_COMMENT = True
NAME_PREFIX = ""


def _self_check() -> None:
    """Fail loudly at import if a tunable above is unusable, rather than
    silently corrupting configs.txt."""
    for name, encoded, decoded in (
        ("FM", FM_ENCODED, FM),
        ("CS", CS_ENCODED, CS),
        ("FP", FP_ENCODED, FP),
        ("DIAL_MODE", DIAL_MODE_ENCODED, DIAL_MODE),
    ):
        if quote(decoded, safe="") != encoded:
            raise AssertionError(f"{name} does not round-trip through percent-encoding")
    for name, port in (
        ("HEALTHCHECK_PORT", HEALTHCHECK_PORT),
        ("OUTPUT_PORT", OUTPUT_PORT),
    ):
        if not (str(port).isdigit() and 1 <= int(port) <= 65535):
            raise AssertionError(f"{name} is not a port number: {port!r}")
    for name, address in (
        ("HEALTHCHECK_ADDRESS", HEALTHCHECK_ADDRESS),
        ("OUTPUT_ADDRESS", OUTPUT_ADDRESS),
    ):
        if not str(address).strip():
            raise AssertionError(f"{name} is empty")


_self_check()


# --- filters (rules 1-4) --------------------------------------------------


def rule_1_security_allowed(node: Node) -> bool:
    """Keep security=tls, security=none, or no security at all. Drops reality."""
    return node.security in ALLOWED_SECURITY


def rule_2_transport_allowed(node: Node) -> bool:
    return node.transport in ALLOWED_TRANSPORTS


def rule_3_has_host(node: Node) -> bool:
    return bool(node.host.strip())


def rule_4_port_allowed(node: Node) -> bool:
    return node.port in PORTS_MAPPED_TO_443 or node.port in PORTS_MAPPED_TO_8080


# --- port normalisation (rules 5-6) ---------------------------------------


def rule_5_normalise_to_443(node: Node) -> None:
    if node.port in PORTS_MAPPED_TO_443:
        node.port = "443"


def rule_6_normalise_to_8080(node: Node) -> None:
    if node.port in PORTS_MAPPED_TO_8080:
        node.port = "8080"


# --- post-normalisation filters (rules 7-8) -------------------------------


def rule_7_drop_plaintext_port_with_tls(node: Node) -> bool:
    """False (drop) when port 8080 carries security=tls."""
    return not (node.port == "8080" and node.security == "tls")


def rule_8_drop_tls_port_without_tls(node: Node) -> bool:
    """False (drop) when port 443 does not carry security=tls."""
    return not (node.port == "443" and node.security != "tls")


# --- rule 9: move plaintext nodes onto TLS --------------------------------


def rule_9_convert_to_tls(node: Node) -> None:
    """Move a plaintext node onto port 443 with TLS.

    This used to duplicate each node onto the other port and publish both. It
    does not any more: the ISP this list is built for blocks unencrypted
    connections to Cloudflare, so a port 8080 node cannot be reached, which
    makes it both untestable and useless. Converting instead of duplicating
    also halves the pool the health check has to work through.

    Must run before rule 10, which overwrites the port this reads.
    """
    if node.port != "8080":
        return
    node.port = "443"
    node.set("security", "tls")
    # NORMALISATION: the node is being moved onto TLS, and Cloudflare selects
    # the origin by SNI, so it has to name the fronted host.
    node.set("sni", node.host)


# --- rule 10: endpoints ---------------------------------------------------


def rule_10_point_at_healthcheck(node: Node) -> None:
    """Send the node through the endpoint the health check measures."""
    node.address = str(HEALTHCHECK_ADDRESS)
    node.port = str(HEALTHCHECK_PORT)


def rule_10_point_at_output(node: Node) -> None:
    """Send the node through the endpoint the subscription publishes.

    Separate from the health-check endpoint on purpose: the check proves the
    node answers behind Cloudflare, which stays true whichever Cloudflare
    address the published link happens to name.
    """
    node.address = str(OUTPUT_ADDRESS)
    node.port = str(OUTPUT_PORT)


# --- rule 11: strip certificate opt-outs and ECH --------------------------

# Everything rule 11 removes from every node, whatever its spelling or case.
STRIPPED_KEYS = INSECURE_KEYS + ECH_KEYS


def rule_11_strip_insecure(node: Node) -> None:
    for key in list(node.params):
        if key.lower() in STRIPPED_KEYS:
            del node.params[key]


# --- deferred parameters: fm and dialMode ---------------------------------


def strip_deferred_params(node: Node) -> None:
    """Remove whatever the source supplied for fm or dialMode.

    The health check has to run on nodes carrying neither, so that what it
    measures is the node rather than one source's idea of how to fragment.
    :func:`apply_deferred_params` puts this project's values on afterwards.
    """
    for key in list(node.params):
        if key.lower() in DEFERRED_KEYS:
            del node.params[key]


def apply_deferred_params(node: Node) -> None:
    """Add fm and dialMode to a node that has already passed the check.

    An empty constant means "publish without it": nothing is written. For
    dialMode that is not a compromise -- the core treats an absent dialMode and
    dialMode="" identically -- and :func:`strip_deferred_params` has already
    guaranteed the node is not carrying a stale value from its source, so an
    empty constant really does publish the default.
    """
    if FM:
        node.set("fm", FM)
    if DIAL_MODE:
        node.set("dialMode", DIAL_MODE)


# --- rule 12: masking parameters ------------------------------------------


def rule_12_apply_masking(node: Node) -> None:
    """The masking the health check exercises. Every node is TLS by now, so it
    applies to all of them. ``fm`` is deliberately not here -- see
    :func:`apply_deferred_params`."""
    node.set("fp", FP)
    node.set("cs", CS)
    # NORMALISATION: rule 10 puts a Cloudflare IP in the address field, and
    # Cloudflare selects the origin by SNI, so SNI has to be the fronted host.
    node.set("sni", node.host)


# --- naming ---------------------------------------------------------------

# Parameters the pipeline sets itself, alongside the address and port rule 10
# rewrites. Every published node carries the same values for these, so they
# cannot tell two nodes apart and are left out of the name hash below. That is
# what keeps a node's published name stable when an address, a mask or a
# dialMode is changed here: only a genuinely different node gets a new name.
INJECTED_KEYS = ("fp", "cs", "sni") + DEFERRED_KEYS


def naming_identity(node: Node) -> tuple:
    """What makes this node distinct upstream, ignoring everything the pipeline
    injects."""
    return (
        node.scheme,
        node.uid,
        tuple(
            sorted(
                (k.lower(), v)
                for k, v in node.params.items()
                if v != "" and k.lower() not in INJECTED_KEYS
            )
        ),
        tuple(sorted(node.extra.items())),
    )


# Every published name ends in " | <6 hex>". This project's own configs.txt is
# one of its sources -- that is what lets a node upstream has dropped stay in
# the list as long as it keeps passing -- so a node routinely arrives with that
# suffix already on it. Appending another would grow the name by six characters
# a day, and because the name is part of the link, configs.txt would be
# rewritten and committed daily even when nothing had changed.
_OWN_HASH_SUFFIX = re.compile(r"(?: \| [0-9a-f]{6})+$")


def source_comment(node: Node) -> str:
    """The node's display name with any hash :func:`make_tag` appended removed.

    Matches the lowercase 6-hex digest this file emits, so a source comment
    that merely contains a pipe is left alone. Strips a whole run of them, to
    clean up any name that grew before this existed.
    """
    return _OWN_HASH_SUFFIX.sub("", node.tag.strip()).strip()


def make_tag(node: Node) -> str:
    """The published name: the source's own comment, then a short content hash.

    The hash comes from :func:`naming_identity`, so the same upstream node
    always gets the same name and an unchanged upstream produces an unchanged
    configs.txt -- including across a change of exit address or masking, and
    across this project re-reading its own output.
    """
    digest = hashlib.sha256(repr(naming_identity(node)).encode("utf-8")).hexdigest()[:6]
    comment = source_comment(node)
    if KEEP_SOURCE_COMMENT and comment:
        head = comment
    else:
        transport = "ws" if node.transport == "websocket" else node.transport
        head = f"{node.host} | {node.scheme}-{transport}"
    # The port used to be part of the name, to separate a node from its twin
    # on the other port. There are no twins now, and every node is on 443.
    return f"{NAME_PREFIX}{head} | {digest}"


# --- drivers --------------------------------------------------------------


def transform(nodes: list[Node], stats: dict | None = None) -> list[Node]:
    """Apply rules 1-12 and return the deduplicated pool, ready to be tested.

    Every node that comes back is TLS, points at the health-check endpoint,
    carries fp and cs, and carries neither fm nor dialMode.
    """
    counts: dict = stats if stats is not None else {}

    def bump(key: str, amount: int = 1) -> None:
        counts[key] = counts.get(key, 0) + amount

    kept: list[Node] = []
    for node in nodes:
        if not INCLUDE_VMESS and node.scheme == "vmess":
            bump("dropped_vmess_cannot_carry_fm")
            continue
        if not rule_1_security_allowed(node):
            bump("dropped_rule_1_security")
            continue
        if not rule_2_transport_allowed(node):
            bump("dropped_rule_2_transport")
            continue
        if not rule_3_has_host(node):
            bump("dropped_rule_3_no_host")
            continue
        if not rule_4_port_allowed(node):
            bump("dropped_rule_4_port")
            continue

        rule_5_normalise_to_443(node)
        rule_6_normalise_to_8080(node)

        if not rule_7_drop_plaintext_port_with_tls(node):
            bump("dropped_rule_7_8080_with_tls")
            continue
        if not rule_8_drop_tls_port_without_tls(node):
            bump("dropped_rule_8_443_without_tls")
            continue

        kept.append(node)

    bump("kept_after_rules_1_to_8", len(kept))

    for node in kept:
        was_plaintext = node.port == "8080"
        rule_9_convert_to_tls(node)          # must run before rule 10
        if was_plaintext:
            bump("converted_to_tls_rule_9")
        rule_10_point_at_healthcheck(node)
        rule_11_strip_insecure(node)
        strip_deferred_params(node)
        rule_12_apply_masking(node)

    deduped: list[Node] = []
    seen: set[tuple] = set()
    for node in kept:
        key = node.identity()
        if key in seen:
            bump("dropped_duplicate")
            continue
        seen.add(key)
        if RENAME_NODES:
            node.tag = make_tag(node)
        deduped.append(node)

    bump("final_total", len(deduped))
    return deduped


def finalise(nodes: list[Node], stats: dict | None = None) -> list[Node]:
    """Turn health-check survivors into what actually gets published.

    Adds the deferred parameters and repoints the nodes at the output endpoint.
    Mutates in place and returns the same list, so the caller's ordering --
    fastest first, from the health check -- is preserved.
    """
    counts: dict = stats if stats is not None else {}
    for node in nodes:
        apply_deferred_params(node)
        rule_10_point_at_output(node)
    counts["published"] = len(nodes)
    counts["published_with_fm"] = len(nodes) if FM else 0
    counts["published_with_dial_mode"] = len(nodes) if DIAL_MODE else 0
    return nodes
