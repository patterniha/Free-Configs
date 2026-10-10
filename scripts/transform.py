"""Rules 1-12: turn the upstream lists into the Cloudflare-fronted node set.

Every numbered rule from the spec is its own function below, named after its
number. The rules run in two phases, and which rule lands in which phase is the
shape of this whole file:

* :func:`transform` runs *before* the health check. It filters (rules 1-8),
  converts plaintext nodes to TLS (rule 9), points every node at the
  health-check endpoint (rule 10), strips what must not be tested (rule 11 and
  :func:`strip_deferred_params`) and sets the SNI Cloudflare routes on.

* :func:`finalise` runs on the survivors. It adds the six parameters that were
  deliberately withheld -- ``fm``, ``dialMode``, ``ech``, ``echOutbound``,
  ``fp`` and ``cs`` -- and repoints each node at the published endpoint, which
  need not be the one it was tested through. They are configured as a list of
  variants, and a survivor is published once per variant, so N survivors and
  I variants make N * I configs in one file.

The split exists because those six shape *how* the connection is made, not
*whether* the node carries traffic. Testing without them measures the node
itself, over the core's plain TLS, and adding them afterwards is a client-side
choice that can be retuned without re-testing anything. A node arriving from a
source carrying its own value for any of them has it removed before the check,
whatever it said, so no source can smuggle its own fragmentation, dialer, ECH
or fingerprint into the run.

Everything published is TLS on port 443. Nodes arriving on a plaintext
Cloudflare port are converted rather than kept alongside a TLS twin: the ISP
this list is built for blocks unencrypted connections to Cloudflare, so a
port 8080 node is untestable and unusable.

Three normalisations are applied on top of the numbered rules, each marked
NORMALISATION where it happens:

* rule 9 sets ``sni`` to ``host`` when converting, because the node is being
  moved onto TLS and Cloudflare selects the origin by SNI;
* every node gets ``sni`` set to its ``host`` (:func:`normalise_sni`), because
  rule 10 replaces the address with a Cloudflare IP -- an ``sni`` still naming
  the origin server would never connect;
* every ws and httpupgrade node gets ``alpn=http/1.1``
  (:func:`normalise_upgrade_alpn`), because both open with an HTTP/1.1 Upgrade
  that cannot run over h2.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from typing import NamedTuple
from urllib.parse import quote, unquote

from nodes import INSECURE_KEYS, WS_ALIASES, Node

# --- rule 10: where nodes point -------------------------------------------
# Every node is *tested* through this one fixed endpoint. Where it is
# *published* is a different decision, made per variant -- each entry of
# VARIANTS below names its own ip and port -- because the health check proves
# the node answers behind Cloudflare, and that stays true whichever Cloudflare
# address a published link names. So a node tested once can be published on as
# many addresses as there are variants, and they can change without re-testing.
HEALTHCHECK_ADDRESS = "188.114.97.6"
HEALTHCHECK_PORT = "443"

# --- rules 4-6: port buckets ---------------------------------------------
PORTS_MAPPED_TO_443 = ("443", "2053", "2083", "2087", "2096", "8443")
PORTS_MAPPED_TO_8080 = ("80", "8080", "8880", "2052", "2082", "2086", "2095")

# --- rules 1-2: accepted values ------------------------------------------
ALLOWED_SECURITY = ("", "tls", "none")
ALLOWED_TRANSPORTS = ("ws", "xhttp", "websocket", "httpupgrade", "grpc")

# --- fields applied AFTER the health check --------------------------------
# A variant is nine fields put on every survivor. Three say where and how the
# published link connects:
#
#   ip, port     the address and port of the link itself -- not query
#                parameters, so they are written plainly below, not
#                percent-encoded. ip may be IPv4, IPv6 (without brackets; the
#                link adds them) or a hostname.
#   security     "tls" or "none". Every node is tested over TLS whatever this
#                says; it only decides what is published. It fixes which
#                ports are usable, exactly as rules 7 and 8 do on the way in:
#                tls needs one of Cloudflare's HTTPS ports (PORTS_MAPPED_TO_443),
#                none one of its HTTP ports (PORTS_MAPPED_TO_8080). A none
#                variant cannot carry ech, echOutbound, fp or cs -- they only
#                exist inside TLS -- and its links drop the node's sni and alpn
#                for the same reason.
#
# The other six are share-link parameters that shape *how* a connection is
# made rather than *whether* a node carries traffic, so the health check runs
# without any of them -- over the core's plain TLS, to HEALTHCHECK_ADDRESS:
#
#   fm           finalmask -- splits the outgoing packets
#   dialMode     streamSettings.sockopt.dialMode, which dialing code the core
#                runs (fork-only, added in a3261029)
#   ech          tlsSettings.echConfigList -- a base64 ECHConfigList, or a DNS
#                query that fetches one, as "name+https://1.1.1.1/dns-query"
#                (h2c:// and udp:// work too; without "name+" the node's own
#                SNI is looked up)
#   echOutbound  a whole Xray outbound, as JSON, that PattN and PattNG add to
#                the config and send the ECH config query through
#                (tlsSettings.echSockopt.dialerProxy). It needs an ech beside
#                it, and a tag that is not empty, "direct" or "block" and does
#                not start with "proxy" -- both clients refuse anything else.
#   fp           tlsSettings.fingerprint -- the uTLS ClientHello to imitate
#   cs           tlsSettings.cipherSuites -- colon-separated Go suite names
#
# They travel together as one list of variants, so the nine can never drift
# out of step. Every healthy node is published once per variant, its variants
# adjacent, so N healthy nodes and I variants become N * I lines -- still one
# configs.txt and one configs_base64.txt. With a single variant, which is the
# default, that is one line per node exactly as before. To publish every node
# on several addresses, add variants that differ only in ip (and port).
#
# For the six parameters, "" publishes that parameter's default: nothing is
# written for it. ip, port and security always need a value.
# For dialMode that costs nothing, because an absent dialMode and dialMode=""
# are the same thing to the core -- both run the default dialer.
#
# Note what the split costs: a value here is never exercised by the health
# check -- including, for fp and cs, the TLS handshake itself: a node that
# passes over plain TLS is not proven to complete one with this fingerprint and
# these ciphers. _self_check below and the preflight catch what they can before
# any testing starts -- fm, echOutbound and fp are validated by the core
# itself, and ech and cs are checked against what the core accepts, because it
# silently tolerates both. dialMode is not: the
# core takes any string at parse time and only rejects one it has no code for
# when it dials, so a dialMode the deployed core does not implement would ship
# as a list that fails at connect time. Keep it matched to what that build
# supports.


class Variant(NamedTuple):
    """One published flavour of every healthy node."""

    ip: str
    port: str
    fm: str
    dial_mode: str
    security: str
    ech: str
    ech_outbound: str
    fp: str
    cs: str

    @property
    def params(self) -> dict[str, str]:
        """The six share-link parameters stripped before the check and put back
        after it, under the keys they are written as. Not ip and port, which
        are the link's address, nor security, which overrides a value the
        check itself needs rather than being withheld from it."""
        return {key: getattr(self, field) for field, key in zip(PARAM_FIELDS, VARIANT_KEYS)}


# Add a variant by adding an entry. Each is (ip, port, fm, dialMode, security,
# ech, echOutbound, fp, cs): ip and port written plainly, the rest
# percent-encoded exactly as they will be emitted, "" for any of the six
# parameters publishing that one's default. Write echOutbound as compact JSON
# on one line.
VARIANTS_ENCODED = [
    (
        # ip
        "188.114.97.6",
        # port
        "443",
        # fm
        "%7B%22tcp%22%3A%20%5B%7B%22type%22%3A%20%22fragment%22%2C%20%22settings%22%3A%20%7B%22"
        "packets%22%3A%20%22tlshello%22%2C%20%22lengths%22%3A%20%5B%220%22%2C%20%22104%22%2C%20%22"
        "1%22%5D%2C%20%22delays%22%3A%20%5B%220%22%5D%2C%20%22maxSplit%22%3A%20%220%22%7D%7D%2C%7B"
        "%22type%22%3A%20%22fragment%22%2C%20%22settings%22%3A%20%7B%22packets%22%3A%20%221-1%22%2C"
        "%20%22lengths%22%3A%20%5B%22114%22%2C%20%221%22%5D%2C%20%22delays%22%3A%20%5B%221%22%5D%2C"
        "%20%22maxSplit%22%3A%20%2211%22%7D%7D%5D%7D",
        # dialMode
        "",
        # security
        "tls",
        # ech
        "",
        # echOutbound
        "",
        # fp
        "unsafe",
        # cs
        "TLS_AES_256_GCM_SHA384%3ATLS_CHACHA20_POLY1305_SHA256%3ATLS_AES_128_GCM_SHA256%3A"
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384%3ATLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384%3A"
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256%3ATLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256%3A"
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256%3ATLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        "%3ATLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA%3ATLS_ECDHE_RSA_WITH_AES_256_CBC_SHA%3A"
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256%3ATLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    ),
    # As above, without a fragment or a cipher list, imitating Chrome's
    # ClientHello, with ECH fetched from Cloudflare's DNS over UDP.
    (
        # ip
        "188.114.97.6",
        # port
        "443",
        # fm
        "",
        # dialMode
        "",
        # security
        "tls",
        # ech
        "cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1",
        # echOutbound
        "",
        # fp
        "chrome",
        # cs
        "",
    ),
    # On a Cloudflare IPv6 address, without a fragment or a cipher list,
    # imitating Chrome's ClientHello.
    (
        # ip
        "2a06:98c1:3121::7",
        # port
        "443",
        # fm
        "",
        # dialMode
        "",
        # security
        "tls",
        # ech
        "",
        # echOutbound
        "",
        # fp
        "chrome",
        # cs
        "",
    ),
]

# The share-link keys of the six parameter fields -- every Variant field after
# ip and port -- in field order: the spelling :func:`apply_deferred_params`
# writes and both clients read. PattNG looks
# echOutbound up with an exact-case map key, so the casing here is load-bearing.
VARIANT_KEYS = ("fm", "dialMode", "ech", "echOutbound", "fp", "cs")

# The Variant field each of those keys is read from -- by name, so the order
# fields are written in never decides which value lands under which key.
PARAM_FIELDS = ("fm", "dial_mode", "ech", "ech_outbound", "fp", "cs")

# What a variant may publish, and the fields only TLS can carry.
SECURITY_VALUES = ("tls", "none")
TLS_ONLY_FIELDS = ("ech", "ech_outbound", "fp", "cs")
# Parameters the pipeline sets on every node that mean nothing without TLS, so
# a security=none link leaves them out.
TLS_ONLY_KEYS = ("sni", "alpn")

# The six parameters :func:`finalise` owns, in every spelling. They are removed
# on the way in and set on the way out, so whatever a source supplied has no
# influence on either the health check or the published value.
DEFERRED_KEYS = tuple(key.lower() for key in VARIANT_KEYS)

# The DNS servers the core can fetch an ECH config from (transport/internet/tls
# /ech.go). Anything else never yields a config, and every connection fails.
ECH_DNS_SCHEMES = ("https://", "h2c://", "udp://")

# Tags both clients refuse for an ECH outbound: direct and block are the
# config's own outbounds, and balancers pick their members by the "proxy"
# prefix, so an ECH outbound under it would end up carrying proxied traffic.
ECH_OUTBOUND_RESERVED_TAGS = ("direct", "block")
ECH_OUTBOUND_RESERVED_PREFIX = "proxy"

# Every name Go's crypto/tls knows, from tls.CipherSuites() and
# tls.InsecureCipherSuites() -- the two lists the core builds cipherSuites
# from (transport/internet/tls/config.go). It drops any name not in them
# without a word, so a typo silently loses a suite, and a cs that is all typos
# silently becomes Go's defaults. Nothing downstream would ever notice.
GO_CIPHER_SUITES = frozenset({
    # tls.CipherSuites()
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    # tls.InsecureCipherSuites()
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
})


def cs_problem(value: str) -> str | None:
    """Why the core would not use ``value`` as the cipher list given, or None."""
    names = [name.strip() for name in value.split(":")]
    unknown = [name for name in names if name not in GO_CIPHER_SUITES]
    if unknown:
        return (
            "names cipher suites the core does not know, which it would silently"
            f" drop: {', '.join(repr(name) for name in unknown)}"
        )
    if len(set(names)) != len(names):
        return "names a cipher suite twice"
    return None


def ech_problem(value: str) -> str | None:
    """Why the core would fail to use ``value`` as an echConfigList, or None.

    Mirrors ApplyECH in transform/internet/tls/ech.go, which only runs when a
    connection is dialled -- xray run -test stores the string without looking
    at it, so this is the only check it gets before the list is published.
    """
    if "://" in value:
        name, plus, server = value.partition("+")
        if plus and not name:
            return "a DNS query written as name+server needs the name before the '+'"
        if not plus:
            server = value
        if not server.startswith(ECH_DNS_SCHEMES):
            return (
                "the core only fetches an ECH config from "
                + ", ".join(ECH_DNS_SCHEMES)
                + " DNS servers"
            )
        return None
    try:
        base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return (
            "neither a base64 ECHConfigList nor a DNS query such as"
            " name+https://1.1.1.1/dns-query"
        )
    return None


def _reject_duplicate_keys(pairs: list) -> dict:
    """json object hook: PattN parses an echOutbound with duplicate keys
    disallowed, so a repeated key would make it refuse every config."""
    seen: set = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"repeated key {key!r}")
        seen.add(key)
    return dict(pairs)


def ech_outbound_problem(value: str, ech: str) -> str | None:
    """Why PattN or PattNG would refuse ``value`` as an echOutbound, or None.

    The same checks both clients make on import (NodeValidator in PattN,
    EchOutbound in PattNG). A value either of them refuses would make every
    published config carrying it fail to load there.
    """
    try:
        outbound = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as error:
        return f"not valid JSON: {error}"
    if not isinstance(outbound, dict):
        return "not a JSON object -- it has to be a whole Xray outbound"
    if not ech:
        return "needs an ech in the same variant; both clients refuse one without"
    tag = outbound.get("tag")
    if not isinstance(tag, str) or not tag:
        return "has no tag, so echSockopt would have nothing to point at"
    if tag in ECH_OUTBOUND_RESERVED_TAGS or tag.startswith(ECH_OUTBOUND_RESERVED_PREFIX):
        return (
            f"has the tag {tag!r}; it may not be direct or block,"
            f" or start with {ECH_OUTBOUND_RESERVED_PREFIX!r}"
        )
    return None


# A hostname, label by label: what a share link's address may be when it is
# not an IP.
_HOSTNAME = re.compile(
    r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
)


def endpoint_problem(ip: str, port: str, security: str = "tls") -> str | None:
    """Why a config with this ``security`` could not point at ``ip``:``port``,
    or None."""
    if not ip or ip != ip.strip():
        return "the address is empty or has spaces around it"
    if ip.startswith("["):
        return f"{ip!r}: write an IPv6 address without brackets -- the link adds them"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        # Not an IP. A hostname is fine -- a share link takes either -- but a
        # dotted run of digits that does not parse is a mistyped IPv4 address,
        # not a name anyone means.
        if re.fullmatch(r"[0-9.]+", ip):
            return f"{ip!r} is not a valid IPv4 address"
        if not _HOSTNAME.fullmatch(ip):
            return f"{ip!r} is neither an IP address nor a hostname"
    # Cloudflare serves TLS on its HTTPS ports only, and plain HTTP on its HTTP
    # ports only. A config on the other family cannot connect -- and when
    # configs.txt is read back in as a source, rule 4, 7 or 8 drops it.
    if security == "tls" and port not in PORTS_MAPPED_TO_443:
        return (
            f"port {port!r} is not one of Cloudflare's HTTPS ports"
            f" ({', '.join(PORTS_MAPPED_TO_443)}), which a TLS config needs"
        )
    if security == "none" and port not in PORTS_MAPPED_TO_8080:
        return (
            f"port {port!r} is not one of Cloudflare's HTTP ports"
            f" ({', '.join(PORTS_MAPPED_TO_8080)}), which a security=none config needs"
        )
    return None


def endpoint_text(ip: str, port: str) -> str:
    """ip:port as a link writes it, IPv6 bracketed, so it reads unambiguously."""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _decode_variants(entries: object) -> list[Variant]:
    """VARIANTS_ENCODED, decoded. An entry of the wrong shape is refused with a
    message about it, rather than as a TypeError out of the NamedTuple."""
    if not isinstance(entries, (list, tuple)):
        raise AssertionError(
            "VARIANTS_ENCODED must be a list of (ip, port, fm, dialMode, security,"
            f" ech, echOutbound, fp, cs) entries, not {type(entries).__name__}"
        )
    decoded: list[Variant] = []
    for index, entry in enumerate(entries):
        if (
            not isinstance(entry, (list, tuple))
            or len(entry) != len(Variant._fields)
            or not all(isinstance(value, str) for value in entry)
        ):
            raise AssertionError(
                f"VARIANTS_ENCODED[{index}] is not an (ip, port, fm, dialMode, security,"
                f" ech, echOutbound, fp, cs) entry of nine strings: {entry!r}"
            )
        # ip and port are the link's address, used as written; the rest are
        # query parameters, stored percent-encoded and decoded here.
        ip, port, *rest = entry
        decoded.append(Variant(ip, port, *(unquote(value) for value in rest)))
    return decoded


VARIANTS = _decode_variants(VARIANTS_ENCODED)

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
    # A variant is one entry of nine fields, so they can never drift out of
    # step -- but the list itself, and the shape of each entry, are still worth
    # checking here rather than as an IndexError deep inside finalise.
    _decode_variants(VARIANTS_ENCODED)
    if not VARIANTS:
        raise AssertionError("VARIANTS is empty: there would be nothing to publish")

    for index, (variant, encoded) in enumerate(zip(VARIANTS, VARIANTS_ENCODED)):
        if variant.security not in SECURITY_VALUES:
            raise AssertionError(
                f"VARIANTS[{index}].security is {variant.security!r}; it has to be"
                f" one of {', '.join(SECURITY_VALUES)}"
            )
        problem = endpoint_problem(variant.ip, variant.port, variant.security)
        if problem:
            raise AssertionError(f"VARIANTS[{index}]: {problem}")
        if variant.security == "none":
            carried = [field for field in TLS_ONLY_FIELDS if getattr(variant, field)]
            if carried:
                raise AssertionError(
                    f"VARIANTS[{index}] is security=none but sets {', '.join(carried)},"
                    " which only exist inside TLS"
                )
        for field, value, raw in zip(Variant._fields[2:], variant[2:], encoded[2:]):
            if quote(value, safe="") != raw:
                raise AssertionError(
                    f"VARIANTS[{index}].{field} does not round-trip through percent-encoding"
                )
        # fm is retyped by hand whenever a fragment is tuned, and it is never
        # exercised by the health check -- nodes are tested without it. Left
        # to the preflight, a JSON typo surfaces as a JSONDecodeError out of
        # Node.to_outbound rather than as a message about this line.
        if variant.fm:
            try:
                json.loads(variant.fm)
            except ValueError as error:
                raise AssertionError(
                    f"VARIANTS[{index}].fm is not valid JSON: {error}"
                ) from None
        # The health check never sees ech or echOutbound either, and the core
        # only parses ech when it dials, so a mistake in either would ship as a
        # list whose every config fails. Both are held to the rules the core
        # and the two clients apply.
        if variant.ech:
            problem = ech_problem(variant.ech)
            if problem:
                raise AssertionError(f"VARIANTS[{index}].ech: {problem}")
        if variant.ech_outbound:
            problem = ech_outbound_problem(variant.ech_outbound, variant.ech)
            if problem:
                raise AssertionError(f"VARIANTS[{index}].echOutbound {problem}")
        # An unknown fp fails the preflight -- the core refuses it at load, from
        # a list it keeps itself. An unknown cs does not, so it is checked here.
        if variant.cs:
            problem = cs_problem(variant.cs)
            if problem:
                raise AssertionError(f"VARIANTS[{index}].cs {problem}")

    # Two identical entries would publish the same link twice, which is the one
    # thing the rest of this pipeline works hardest to avoid.
    if len(set(VARIANTS)) != len(VARIANTS):
        raise AssertionError("VARIANTS repeats an entry, which would publish duplicate configs")

    # The tested endpoint is held to the same rules: the check is TLS too, and
    # a check that cannot connect fails every node.
    problem = endpoint_problem(str(HEALTHCHECK_ADDRESS), str(HEALTHCHECK_PORT), "tls")
    if problem:
        raise AssertionError(f"HEALTHCHECK_ADDRESS/HEALTHCHECK_PORT: {problem}")


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


def rule_10_point_at_output(node: Node, variant: int = 0) -> None:
    """Send the node through one variant's published endpoint.

    Separate from the health-check endpoint on purpose: the check proves the
    node answers behind Cloudflare, which stays true whichever Cloudflare
    address a published link names -- so a node tested once can be published
    on as many addresses as there are variants.
    """
    node.address = VARIANTS[variant].ip
    node.port = VARIANTS[variant].port


# --- rule 11: strip certificate opt-outs --------------------------------

# Everything rule 11 removes from every node, whatever its spelling or case.
# It used to take ech as well. ech is still removed before the health check --
# it is one of the DEFERRED_KEYS now -- but it is no longer thrown away: a
# variant can put this project's own ech back on the survivors.
STRIPPED_KEYS = INSECURE_KEYS


def rule_11_strip_insecure(node: Node) -> None:
    for key in list(node.params):
        if key.lower() in STRIPPED_KEYS:
            del node.params[key]


# --- deferred parameters ---------------------------------------------------


def strip_deferred_params(node: Node) -> None:
    """Remove whatever the source supplied for fm, dialMode, ech, echOutbound,
    fp or cs.

    The health check has to run on nodes carrying none of them, so that what it
    measures is the node rather than one source's idea of how to fragment,
    dial, hide the SNI, or shape the ClientHello. :func:`apply_deferred_params`
    puts this project's values on afterwards.
    """
    for key in list(node.params):
        if key.lower() in DEFERRED_KEYS:
            del node.params[key]


def apply_deferred_params(node: Node, variant: int = 0) -> None:
    """Put one variant's fm, dialMode, ech, echOutbound, fp and cs on a node
    that has already passed.

    ``variant`` indexes :data:`VARIANTS`, so the six always travel as the
    entry they were written as, each under the exact key in VARIANT_KEYS.
    The variant's ip and port are rule 10's -- see rule_10_point_at_output.

    An empty field means "publish without it": nothing is written. For dialMode
    that is not a compromise -- the core treats an absent dialMode and
    dialMode="" identically -- and :func:`strip_deferred_params` has already
    guaranteed the node is not carrying a stale value from its source, so an
    empty field really does publish the default.
    """
    for key, value in VARIANTS[variant].params.items():
        if value:
            node.set(key, value)


def set_published_security(node: Node, variant: int = 0) -> None:
    """Give a published copy its variant's security.

    Every node is tested over TLS; this only decides what is published. A
    security=none copy also loses its sni and alpn -- TLS extensions, set on
    every node before the check, that mean nothing on a plaintext link.
    """
    security = VARIANTS[variant].security
    node.set("security", security)
    if security == "none":
        for key in TLS_ONLY_KEYS:
            node.pop(key)


# --- SNI -------------------------------------------------------------------
# Rule 12's values -- fp, cs and fm -- are variant fields now, put on the
# survivors by apply_deferred_params. What stays before the check is the SNI
# normalisation that used to ride along with them.


def normalise_sni(node: Node) -> None:
    """NORMALISATION: rule 10 puts a Cloudflare IP in the address field, and
    Cloudflare selects the origin by SNI, so SNI has to be the fronted host --
    for the health check as much as for what is published."""
    node.set("sni", node.host)


# --- ALPN for the HTTP/1.1 Upgrade transports --------------------------------
# WebSocket and httpupgrade both open with an HTTP/1.1 Upgrade request, so a
# node on either that offers h2 lets Cloudflare pick a protocol the handshake
# cannot run over. The core does not prevent it: both dialers ask for http/1.1
# only when the config sets no ALPN at all (tls.WithNextProto in
# transport/internet/websocket and .../httpupgrade), so a source's "h2" or
# "h2,http/1.1" goes out exactly as written.
HTTP1_ALPN = "http/1.1"
HTTP1_UPGRADE_TRANSPORTS = WS_ALIASES + ("httpupgrade",)


def normalise_upgrade_alpn(node: Node) -> None:
    """NORMALISATION: every ws or httpupgrade node offers exactly http/1.1,
    whatever its source said -- or added when it said nothing.

    The old key is popped rather than overwritten so the link always carries it
    as "alpn": Node.set keeps an existing key's spelling, and a source's "ALPN"
    would otherwise reach the published link.
    """
    if node.transport in HTTP1_UPGRADE_TRANSPORTS:
        node.pop("alpn")
        node.set("alpn", HTTP1_ALPN)


# --- naming ---------------------------------------------------------------

# Parameters the pipeline sets itself, alongside the address and port rule 10
# rewrites. Every published node carries the same values for these, so they
# cannot tell two nodes apart and are left out of the name hash below. That is
# what keeps a node's published name stable when an address, a mask or a
# dialMode is changed here: only a genuinely different node gets a new name.
INJECTED_KEYS = ("sni",) + DEFERRED_KEYS


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


def make_tag(node: Node, variant: int = 0) -> str:
    """The published name: the source's own comment, then a short content hash.

    The hash comes from :func:`naming_identity`, so the same upstream node
    always gets the same name and an unchanged upstream produces an unchanged
    configs.txt -- including across a change of exit address or masking, and
    across this project re-reading its own output.

    ``variant`` is mixed in so that a node published under several variants
    does not appear in a client several times under one name, which would
    make the variants impossible to tell apart -- and choosing between them is
    the point of publishing more than one. The index is mixed in rather than
    the fm and dialMode values themselves, so that retuning a fragment still
    does not rename anything. Variant 0 is left unmixed, so a single-variant
    list produces exactly the names it always has.
    """
    seed = repr(naming_identity(node))
    if variant:
        seed += f"|variant-{variant}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:6]
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
    names its host as SNI, offers only http/1.1 if it is ws or httpupgrade, and
    carries none of the six variant fields.
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
        normalise_sni(node)
        normalise_upgrade_alpn(node)

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

    Each node is emitted once per entry in :data:`VARIANTS`, its variants
    adjacent, so N survivors and I variants produce N * I configs in the order

        node 1 variant 1, node 1 variant 2, node 2 variant 1, ...

    which keeps the caller's ordering -- fastest first, from the health check --
    and keeps a node's variants together for whoever reads the file.

    Returns new nodes and leaves the input untouched: one survivor can become
    several published configs, so there is nothing sensible to mutate in place.
    """
    counts: dict = stats if stats is not None else {}
    published: list[Node] = []
    for node in nodes:
        for variant in range(len(VARIANTS)):
            copy = node.copy()
            copy.latency_ms = node.latency_ms   # Node.copy does not carry this
            apply_deferred_params(copy, variant)
            set_published_security(copy, variant)
            rule_10_point_at_output(copy, variant)
            if RENAME_NODES and len(VARIANTS) > 1:
                # Named from the node as tested, not from the copy: then no
                # field of a variant -- its address, its security, anything it
                # adds -- can rename what is published. Only the index can.
                copy.tag = make_tag(node, variant)
            published.append(copy)
    counts["published"] = len(published)
    counts["published_variants"] = len(VARIANTS)
    counts["published_without_tls"] = sum(1 for node in published if node.security == "none")
    for key in VARIANT_KEYS:
        counts[f"published_with_{key}"] = sum(1 for node in published if node.has(key))
    return published
