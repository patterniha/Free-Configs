"""Rules 1-12: turn the upstream lists into the Cloudflare-fronted node set.

Every numbered rule from the spec is its own function below, named after its
number, and :func:`transform` applies them in order. Tunables are grouped at
the top of the file.

Everything published is TLS on port 443. Nodes arriving on a plaintext
Cloudflare port are converted rather than kept alongside a TLS twin: the ISP
this list is built for blocks unencrypted connections to Cloudflare, so a
port 8080 node is untestable and unusable. That single invariant is what keeps
the rest of the file short -- there is one exit address, no rule 13, and no
plaintext-only parameters to strip.

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
from urllib.parse import quote, unquote

from nodes import ECH_KEYS, INSECURE_KEYS, Node

# --- rule 10: exit address ------------------------------------------------
# Every node exits here. There were two constants back when plaintext nodes
# were published alongside TLS ones; rule 9 converts them now, so one address
# covers everything.
EXIT_ADDRESS = "104.21.33.59"

# --- rules 4-6: port buckets ---------------------------------------------
PORTS_MAPPED_TO_443 = ("443", "2053", "2083", "2087", "2096", "8443")
PORTS_MAPPED_TO_8080 = ("80", "8080", "8880", "2052", "2082", "2086", "2095")

# --- rules 1-2: accepted values ------------------------------------------
ALLOWED_SECURITY = ("", "tls", "none")
ALLOWED_TRANSPORTS = ("ws", "xhttp", "websocket", "httpupgrade", "grpc")

# --- rule 12: client-side masking ----------------------------------------
# Stored exactly as supplied (percent-encoded), decoded once at import. The
# self-check below proves re-encoding reproduces these strings byte for byte,
# so what lands in configs.txt is what was asked for.
FP_443_ENCODED = "unsafe"
FM_443_ENCODED = (
    "%7B%22tcp%22%3A%20%5B%7B%22type%22%3A%20%22fragment%22%2C%20%22settings%22%3A%20%7B%22"
    "packets%22%3A%20%22tlshello%22%2C%20%22lengths%22%3A%20%5B%225%22%2C%20%2294%22%2C%20%22"
    "1%22%5D%2C%20%22delays%22%3A%20%5B%220%22%5D%2C%20%22maxSplit%22%3A%20%220%22%7D%7D%2C%7B"
    "%22type%22%3A%20%22fragment%22%2C%20%22settings%22%3A%20%7B%22packets%22%3A%20%221-1%22%2C"
    "%20%22lengths%22%3A%20%5B%22109%22%2C%20%221%22%5D%2C%20%22delays%22%3A%20%5B%221%22%5D%2C"
    "%20%22maxSplit%22%3A%20%22355%22%7D%7D%5D%7D"
)
CS_443_ENCODED = (
    "TLS_AES_256_GCM_SHA384%3ATLS_CHACHA20_POLY1305_SHA256%3ATLS_AES_128_GCM_SHA256%3A"
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384%3ATLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384%3A"
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256%3ATLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256%3A"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256%3ATLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    "%3ATLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA%3ATLS_ECDHE_RSA_WITH_AES_256_CBC_SHA%3A"
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256%3ATLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
)
FP_443 = unquote(FP_443_ENCODED)
FM_443 = unquote(FM_443_ENCODED)
CS_443 = unquote(CS_443_ENCODED)

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
    """Fail loudly at import if a masking constant would not survive a
    decode/encode round trip, which would silently corrupt configs.txt."""
    for name, encoded, decoded in (
        ("FM_443", FM_443_ENCODED, FM_443),
        ("CS_443", CS_443_ENCODED, CS_443),
    ):
        if quote(decoded, safe="") != encoded:
            raise AssertionError(f"{name} does not round-trip through percent-encoding")


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
    """
    if node.port != "8080":
        return
    node.port = "443"
    node.set("security", "tls")
    # NORMALISATION: the node is being moved onto TLS, and Cloudflare selects
    # the origin by SNI, so it has to name the fronted host.
    node.set("sni", node.host)


# --- rule 10: exit address ------------------------------------------------


def rule_10_set_address(node: Node) -> None:
    node.address = EXIT_ADDRESS


# --- rule 11: strip certificate opt-outs and ECH --------------------------

# Everything rule 11 removes from every node, whatever its spelling or case.
STRIPPED_KEYS = INSECURE_KEYS + ECH_KEYS


def rule_11_strip_insecure(node: Node) -> None:
    for key in list(node.params):
        if key.lower() in STRIPPED_KEYS:
            del node.params[key]


# --- rule 12: masking parameters ------------------------------------------


def rule_12_apply_masking(node: Node) -> None:
    """Every node is TLS on 443 by now, so this applies to all of them."""
    node.set("fp", FP_443)
    node.set("fm", FM_443)
    node.set("cs", CS_443)
    # NORMALISATION: rule 10 puts a Cloudflare IP in the address field, and
    # Cloudflare selects the origin by SNI, so SNI has to be the fronted host.
    node.set("sni", node.host)


# --- naming ---------------------------------------------------------------


def make_tag(node: Node) -> str:
    """The published name: the source's own comment, then the port and a short
    content hash. The hash is derived from the node itself, so the same node
    always gets the same name and an unchanged upstream produces an unchanged
    configs.txt."""
    digest = hashlib.sha256(repr(node.identity()).encode("utf-8")).hexdigest()[:6]
    comment = node.tag.strip()
    if KEEP_SOURCE_COMMENT and comment:
        head = comment
    else:
        transport = "ws" if node.transport == "websocket" else node.transport
        head = f"{node.host} | {node.scheme}-{transport}"
    # The port used to be part of the name, to separate a node from its twin
    # on the other port. There are no twins now, and every node is on 443.
    return f"{NAME_PREFIX}{head} | {digest}"


# --- driver ---------------------------------------------------------------


def transform(nodes: list[Node], stats: dict | None = None) -> list[Node]:
    """Apply rules 1-12 and return the deduplicated result."""
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
        rule_9_convert_to_tls(node)
        if was_plaintext:
            bump("converted_to_tls_rule_9")
        rule_10_set_address(node)
        rule_11_strip_insecure(node)
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
