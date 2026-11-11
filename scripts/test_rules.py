"""Tests for the transform rules and the share-link parser.

    python scripts/test_rules.py

No test framework needed. Every numbered rule from the spec has at least one
test named after it, plus parser edge cases and end-to-end properties.
"""

from __future__ import annotations

import base64
import collections
import contextlib
import http.client
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build  # noqa: E402
import transform  # noqa: E402
from nodes import Node, parse_line  # noqa: E402

# What transform.py ships is configuration, and any legal list is a valid one:
# adding, changing or removing a variant there must never need a change here.
# CI runs this suite before it builds, so a test that depended on the shipped
# values would stop the daily publish whenever they were edited.
#
# So the tests that check how the pipeline works run against a reference
# variant of their own, below, and never read the shipped list. The shipped
# list is checked only for what any list has to satisfy -- it is legal, every
# value round-trips, every variant is probed -- and the end-to-end build.py
# runs, which read the real transform.py, hold each published line to
# whichever shipped variant it came from.
SHIPPED_VARIANTS = transform.VARIANTS
SHIPPED_VARIANTS_ENCODED = transform.VARIANTS_ENCODED

# Without a prefix_name, so the names the tests below see are the ones earlier
# versions gave; prefixes are tested on their own.
REFERENCE_VARIANT = transform.Variant(
    prefix_name="",
    ip="188.114.98.0",
    port="443",
    fm=(
        '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0",'
        ' "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings":'
        ' {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}'
    ),
    dial_mode="",
    security="tls",
    ech="",
    ech_outbound="",
    fp="unsafe",
    cs=(
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    ),
    cp="",
    esr="",
)


def encode(variant: transform.Variant) -> tuple:
    """The VARIANTS_ENCODED entry of ``variant``: the plain fields as they are,
    the rest percent-encoded -- by field name, as transform.py writes them."""
    return tuple(
        value if field in transform.PLAIN_FIELDS else quote(value, safe="")
        for field, value in zip(transform.Variant._fields, variant)
    )


transform.VARIANTS = [REFERENCE_VARIANT]
transform.VARIANTS_ENCODED = [encode(REFERENCE_VARIANT)]
transform._self_check()      # the reference has to be a legal variant itself

FAILURES: list[str] = []
PASSED = 0


def check(condition: bool, label: str) -> None:
    global PASSED
    if condition:
        PASSED += 1
    else:
        FAILURES.append(label)


def link(**kwargs) -> str:
    """Build a vless link from keyword parts, for compact test cases."""
    uid = kwargs.pop("uid", "11111111-1111-1111-1111-111111111111")
    address = kwargs.pop("address", "1.2.3.4")
    port = kwargs.pop("port", "443")
    tag = kwargs.pop("tag", "name")
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in kwargs.items() if v is not None)
    return f"vless://{uid}@{address}:{port}?{query}#{tag}"


def one(**kwargs) -> list[Node]:
    """Run the full transform over a single synthetic link."""
    node = parse_line(link(**kwargs))
    assert node is not None, "test input did not parse"
    return transform.transform([node], {})


def survives(**kwargs) -> bool:
    return len(one(**kwargs)) > 0


def finalised(**kwargs) -> list[Node]:
    """Run the whole pipeline over one synthetic link: the pre-health-check
    transform, then the post-health-check finalise, exactly as build.py does
    for a node that passed."""
    return transform.finalise(one(**kwargs), {})


BASE = dict(security="tls", type="ws", host="a.example", path="/")


# --- rule 1: security ------------------------------------------------------

for value, expected in (("reality", False), ("tls", True), ("none", True), ("xtls", False)):
    got = survives(**{**BASE, "security": value, "port": "443" if value == "tls" else "8080"})
    check(got == expected, f"rule 1: security={value!r} should {'survive' if expected else 'drop'}")

check(survives(security=None, type="ws", host="a.example", port="8080"), "rule 1: absent security survives")

# --- rule 2: transport -----------------------------------------------------

# Spelled out rather than read from ALLOWED_TRANSPORTS: looping over the
# constant would shrink silently with it, so dropping a transport from the
# pipeline would pass unnoticed.
check(set(transform.ALLOWED_TRANSPORTS)
      == {"ws", "xhttp", "websocket", "httpupgrade", "grpc"},
      "rule 2: the accepted transports are the five in the spec")
for value in ("ws", "xhttp", "websocket", "httpupgrade", "grpc"):
    check(survives(**{**BASE, "type": value}), f"rule 2: type={value!r} should survive")
for value in ("tcp", "raw", "kcp", "h2", ""):
    check(not survives(**{**BASE, "type": value}), f"rule 2: type={value!r} should drop")

# --- rule 3: host ----------------------------------------------------------

check(not survives(security="tls", type="ws", path="/", host=None), "rule 3: missing host drops")
check(not survives(**{**BASE, "host": ""}), "rule 3: empty host drops")
check(not survives(**{**BASE, "host": "   "}), "rule 3: whitespace-only host drops")

# --- rules 4/5/6: ports ----------------------------------------------------

for port in transform.PORTS_MAPPED_TO_443:
    result = one(**{**BASE, "port": port})
    check(bool(result), f"rule 4: port {port} accepted")
    check(any(n.port == "443" for n in result), f"rule 5: port {port} maps to 443")

for port in transform.PORTS_MAPPED_TO_8080:
    result = one(**{**BASE, "security": "none", "port": port})
    check(bool(result), f"rule 4: port {port} accepted")
    # Rule 6 puts it on 8080, then rule 9 moves it to 443, so end to end it
    # lands on 443. Rule 6 itself is checked in isolation, since its result is
    # now an intermediate state no published node is ever left in.
    check(all(n.port == "443" for n in result), f"rules 6+9: port {port} ends up on 443")
    staged = parse_line(link(**{**BASE, "security": "none", "port": port}))
    transform.rule_6_normalise_to_8080(staged)
    check(staged.port == "8080", f"rule 6 isolated: port {port} normalises to 8080")

for port in ("22", "8444", "0", "65536", "443abc", "", "abc"):
    check(not survives(**{**BASE, "port": port}), f"rule 4: port {port!r} rejected")

check(parse_line("vless://uid@1.2.3.4?type=ws&host=a.example").port == "", "rule 4: no port parses as empty")
check(not survives(**{**BASE, "port": " 443"}), "rule 4: padded port rejected")

# --- rules 7/8: security must match the port -------------------------------

check(not survives(security="tls", type="ws", host="a.example", port="8080"),
      "rule 7: 8080 + tls drops")
check(not survives(security="none", type="ws", host="a.example", port="443"),
      "rule 8: 443 + non-tls drops")
check(not survives(type="ws", host="a.example", port="2053"),
      "rule 8: 443-bucket without security drops")

# --- rule 9: plaintext nodes are converted to TLS --------------------------

# A TLS node passes through untouched.
result = one(**BASE)
check(len(result) == 1, "rule 9: a node is no longer duplicated")
only = result[0]
check(only.port == "443" and only.security == "tls", "rule 9: a TLS node stays as it is")

# A plaintext node is moved onto 443 with TLS and an sni naming its host.
result = one(security="none", type="ws", host="b.example", path="/", port="8080")
check(len(result) == 1, "rule 9: a plaintext node yields one node, not two")
moved = result[0]
check(moved.port == "443", "rule 9: a plaintext node moves to port 443")
check(moved.security == "tls", "rule 9: the converted node carries security=tls")
check(moved.get("sni") == "b.example", "rule 9: the converted node gets sni=host")

# Nothing anywhere may still be on 8080 -- that is the whole point.
for spec in ({}, {"security": "none", "port": "8080"}, {"port": "2082", "security": "none"},
             {"port": "2053"}, {"port": "8880", "security": "none"}):
    for node in one(**{**BASE, **spec}):
        check(node.port == "443", f"rule 9: {spec or 'default'} ends up on 443")
        check(node.security == "tls", f"rule 9: {spec or 'default'} ends up on TLS")

# rule_9_convert_to_tls in isolation.
probe = parse_line(link(security="none", type="ws", host="c.example", path="/", port="8080"))
probe.port = "8080"
transform.rule_9_convert_to_tls(probe)
check(probe.port == "443" and probe.security == "tls" and probe.get("sni") == "c.example",
      "rule 9 isolated: a plaintext node is converted in place")
already = parse_line(link(**BASE))
already.set("sni", "orig.example")
transform.rule_9_convert_to_tls(already)
check(already.port == "443" and already.get("sni") == "orig.example",
      "rule 9 isolated: a node already on 443 is left alone")

# --- rule 10: endpoints ----------------------------------------------------
# One fixed endpoint for the health check; the published endpoint is each
# variant's own ip and port.

for node in one(**BASE):
    check(node.address == transform.HEALTHCHECK_ADDRESS,
          "rule 10: a node about to be tested uses the health-check address")
    check(node.port == transform.HEALTHCHECK_PORT,
          "rule 10: a node about to be tested uses the health-check port")

for node in finalised(**BASE):
    check(node.address == transform.VARIANTS[0].ip,
          "rule 10: a published node uses its variant's ip")
    check(node.port == transform.VARIANTS[0].port,
          "rule 10: a published node uses its variant's port")

probe = parse_line(link(**BASE))
probe.address, probe.port = "0.0.0.0", "1"
transform.rule_10_point_at_healthcheck(probe)
check(probe.address == transform.HEALTHCHECK_ADDRESS
      and probe.port == transform.HEALTHCHECK_PORT,
      "rule 10: the setter applies the health-check endpoint")
transform.rule_10_point_at_output(probe, 0)
check((probe.address, probe.port) == (transform.VARIANTS[0].ip, transform.VARIANTS[0].port),
      "rule 10: the setter applies a variant's endpoint")

# The tested and published endpoints are genuinely independent. Patched rather
# than assumed: they hold the same values today, so an equality test would
# still pass if one phase were wired to the other's.
real_endpoint = (transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT)
real_variants_rule10 = transform.VARIANTS
try:
    transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT = "10.0.0.1", "8443"
    transform.VARIANTS = [real_variants_rule10[0]._replace(ip="10.0.0.2", port="2053")]
    tested = one(**BASE)
    check([(n.address, n.port) for n in tested] == [("10.0.0.1", "8443")],
          "rule 10: the tested endpoint comes from the health-check constants")
    published = transform.finalise(tested, {})
    check([(n.address, n.port) for n in published] == [("10.0.0.2", "2053")],
          "rule 10: the published endpoint comes from the variant")
    check(published[0].to_link().startswith("vless://")
          and "@10.0.0.2:2053?" in published[0].to_link(),
          "rule 10: the variant's ip and port reach the emitted link")
finally:
    transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT = real_endpoint
    transform.VARIANTS = real_variants_rule10

# --- rule 11: strip certificate opt-outs -----------------------------------

for spelling in ("allowInsecure", "allow_insecure", "insecure", "ALLOWINSECURE",
                 "AllowInsecure"):
    result = one(**{**BASE, spelling: "1"})
    check(
        all(not n.has(spelling) for n in result),
        f"rule 11: {spelling} removed",
    )
    check(
        all(f"{spelling.lower()}=" not in n.to_link().lower() for n in result),
        f"rule 11: {spelling} absent from the emitted link",
    )

# ech used to be rule 11's as well. It is a deferred parameter now -- still
# gone before the health check, but no longer thrown away for good -- so rule
# 11 on its own must leave it for strip_deferred_params.
isolated = parse_line(link(**{**BASE, "ech": "x+https://1.1.1.1/dns-query", "insecure": "1"}))
transform.rule_11_strip_insecure(isolated)
check(not isolated.has("insecure") and isolated.has("ech"),
      "rule 11 isolated: strips certificate opt-outs and leaves ech to the deferred step")
transform.strip_deferred_params(isolated)
check(not isolated.has("ech"), "rule 11 isolated: the deferred step is what removes ech")

# ech is stripped even when it sits beside parameters that must survive.
survivor = one(**{**BASE, "ech": "ip.gs+udp://8.8.8.8"})
for node in survivor:
    check(not node.has("ech"), "deferred: a source ech is removed before the check")
    check(parse_line(node.to_link()).get("ech") == "",
          "deferred: a source ech is absent from the tested link")
    check(node.get("host") == "a.example" and node.get("type") == "ws",
          "deferred: stripping ech leaves the other parameters intact")
check(len(survivor) == 1, "deferred: stripping ech does not drop the node")

# --- deferred parameters: withheld from the check, added when publishing -----
# fm, dialMode, ech and echOutbound change how a connection is made, not
# whether a node carries traffic. None of them may reach the health check.

for spelling in ("fm", "FM", "Fm", "dialMode", "dialmode", "DIALMODE",
                 "ech", "ECH", "Ech", "echOutbound", "echoutbound", "ECHOUTBOUND",
                 "cp", "CP", "Cp", "esr", "ESR", "Esr"):
    tested = one(**{**BASE, spelling: "junk-from-a-source"})
    check(len(tested) == 1, f"deferred: a node carrying {spelling} is not dropped")
    for node in tested:
        check(not node.has(spelling),
              f"deferred: {spelling} is removed before the health check")
        check("junk-from-a-source" not in node.to_link(),
              f"deferred: a source value for {spelling} never reaches the tested link")

# What a source supplied is replaced by this project's value, never merged.
for node in transform.finalise(one(**{**BASE, "fm": "junk", "dialMode": "junk"}), {}):
    check(node.get("fm") == transform.VARIANTS[0].fm, "deferred: the published fm is this project's")
    check(node.get("dialMode") == transform.VARIANTS[0].dial_mode,
          "deferred: the published dialMode is this project's")

# The invariant the whole split exists for: nothing reaching the health check
# carries any of the four, whatever it arrived with, and everything reaching
# it still carries the masking the check is supposed to exercise.
SOURCE_DEFERRED = {"fm": "x", "dialMode": "x", "ech": "x", "echOutbound": "x", "cp": "x", "esr": "1"}
matrix = []
for security, port in (("tls", "443"), ("none", "8080"), ("tls", "2053"), ("none", "2082")):
    for extra in ({}, {"fm": "x"}, {"dialMode": "x"}, {"ech": "x"}, {"echOutbound": "x"},
                  {"cp": "X25519"}, {"esr": "1"}, SOURCE_DEFERRED):
        matrix.extend(one(**{**BASE, "security": security, "port": port, **extra}))
check(len(matrix) == 32, "deferred: every combination in the matrix survived the rules")
check(all(not n.has(key) for n in matrix for key in transform.VARIANT_KEYS),
      "deferred: no node reaches the health check carrying fm, dialMode, ech or echOutbound")
check(all(not parse_line(n.to_link()).has(key) for n in matrix for key in transform.VARIANT_KEYS),
      "deferred: no tested link carries fm, dialMode, ech or echOutbound")
tested_stream = [n.to_outbound("t")["streamSettings"] for n in matrix]
check(all("finalmask" not in st and "sockopt" not in st for st in tested_stream),
      "deferred: no tested outbound renders a finalmask or a sockopt")
check(all("echConfigList" not in st["tlsSettings"] and "echSockopt" not in st["tlsSettings"]
          for st in tested_stream),
      "deferred: no tested outbound renders an echConfigList or an echSockopt")
check(all(not n.has("fp") and not n.has("cs") for n in matrix),
      "deferred: no tested node carries fp or cs -- the check runs over plain TLS")
check(all("fingerprint" not in st["tlsSettings"] and "cipherSuites" not in st["tlsSettings"]
          for st in tested_stream),
      "deferred: no tested outbound renders a fingerprint or cipherSuites")
check(all("curvePreferences" not in st["tlsSettings"]
          and "enableSessionResumption" not in st["tlsSettings"] for st in tested_stream),
      "deferred: no tested outbound renders curvePreferences or enableSessionResumption")
check(all(n.port == transform.HEALTHCHECK_PORT and n.security == "tls" for n in matrix),
      "deferred: every tested node is TLS on the health-check port")

# --- rule 12: masking parameters -------------------------------------------
# fp, cs and fm are variant fields. None of them is on a node while it is
# tested, and the default variant puts all three on what is published.

DEFAULT = transform.VARIANTS[0]
# By field name, never by position: an index silently means a different field
# the moment one is added, and "fm" at index 0 would become the ip -- which is
# in every link, so a check on it would keep passing for the wrong reason.
DEFAULT_ENCODED = dict(zip(transform.Variant._fields, transform.VARIANTS_ENCODED[0]))

for node in one(**BASE):
    check(not node.has("fp") and not node.has("cs") and not node.has("fm"),
          "rule 12: no fp, cs or fm on a node about to be tested")
    check(node.get("sni") == node.host, "rule 12: the SNI is still set before the check")

for node in finalised(**BASE):
    check(node.get("fp") == "unsafe", "rule 12: fp=unsafe on a published node")
    check(node.get("cs") == DEFAULT.cs, "rule 12: cs value on a published node")
    check(node.get("fm") == DEFAULT.fm, "rule 12: fm value on a published node")
    emitted = node.to_link()
    check(DEFAULT_ENCODED["fm"] in emitted, "rule 12: fm is byte-exact in the published link")
    check(DEFAULT_ENCODED["cs"] in emitted, "rule 12: cs is byte-exact in the published link")
    check("fp=unsafe" in emitted, "rule 12: fp is byte-exact in the published link")

# A converted plaintext node gets the same masking as any other.
for node in finalised(security="none", type="ws", host="d.example", path="/", port="8080"):
    check((node.get("fp"), node.get("cs"), node.get("fm")) == (DEFAULT.fp, DEFAULT.cs, DEFAULT.fm),
          "rule 12: a converted node is masked like any other")

# A node arriving with its own fp and cs has them stripped before the check --
# stripped, not overwritten, because the check runs over plain TLS -- and gets
# the variant's values only when it is published.
inherited = one(
    security="none", type="ws", host="c.example", path="/", port="8080",
    alpn="h2,http/1.1", fp="chrome", cs="TLS_AES_128_GCM_SHA256", sni="stale.example",
)
check(len(inherited) == 1, "rule 12: a converted node is still a single node")
converted = inherited[0]
check(not converted.has("fp"), "rule 12: a source fp is stripped before the check")
check(not converted.has("cs"), "rule 12: a source cs is stripped before the check")
check(converted.get("sni") == "c.example", "rule 12: a stale sni is replaced by the host")
republished = transform.finalise([converted], {})[0]
check((republished.get("fp"), republished.get("cs")) == (DEFAULT.fp, DEFAULT.cs),
      "rule 12: the published fp and cs are the variant's, never the source's")

# The same for a node that was already TLS on 443 and so never went through
# rule 9 -- normalise_sni is the only thing that can correct its sni, and it must,
# because rule 10 has just replaced the address with a Cloudflare IP.
for node in one(**{**BASE, "sni": "stale.example"}):
    check(node.get("sni") == "a.example",
          "rule 12: a stale sni on an already-TLS node is replaced by the host")
for node in one(security="tls", type="ws", host="e.example", path="/", port="443"):
    check(node.get("sni") == "e.example",
          "rule 12: a node with no sni at all is given the host")

# Existing values must be overwritten, not kept ("set/change").
for node in finalised(**{**BASE, "fp": "chrome", "fm": "junk", "cs": "junk"}):
    check(node.get("fp") == "unsafe", "rule 12: existing fp is overwritten")
    check(node.get("fm") == transform.VARIANTS[0].fm, "rule 12: existing fm is overwritten")

# DIAL_MODE is "" today, so nothing should be emitted for it. Both states are
# patched in, because a test against the live constant asserts nothing about
# the set case while it is empty -- and the fork will grow more values.
real_variants = transform.VARIANTS
try:
    transform.VARIANTS = [real_variants[0]._replace(dial_mode="")]
    for node in finalised(**BASE):
        check(not node.has("dialMode"), "rule 12: an empty dialMode publishes nothing")
        check("dialMode" not in node.to_link(),
              "rule 12: an empty dialMode is absent from the published link")
        check("sockopt" not in node.to_outbound("t")["streamSettings"],
              "rule 12: an empty dialMode renders no sockopt")
    transform.VARIANTS = [real_variants[0]._replace(dial_mode="code-1")]
    for node in finalised(**BASE):
        check(node.get("dialMode") == "code-1", "rule 12: a set dialMode reaches the node")
        check("dialMode=code-1" in node.to_link(),
              "rule 12: a set dialMode reaches the published link")
        check(node.to_outbound("t")["streamSettings"]["sockopt"] == {"dialMode": "code-1"},
              "rule 12: a set dialMode reaches streamSettings.sockopt")
finally:
    transform.VARIANTS = real_variants

# --- ALPN for the HTTP/1.1 Upgrade transports --------------------------------
# Every ws and httpupgrade node offers exactly http/1.1 before the health check
# -- added when missing, replacing any other value -- because both open with an
# HTTP/1.1 Upgrade. Nothing else is touched.

for transport in ("ws", "websocket", "httpupgrade"):
    for source_alpn in (None, "h2", "h2,http/1.1", "http/1.1", "h3"):
        spec = {**BASE, "type": transport}
        if source_alpn is not None:
            spec["alpn"] = source_alpn
        label = f"{transport} with alpn={source_alpn!r}"
        tested = one(**spec)
        check(len(tested) == 1, f"upgrade alpn: {label} survives the rules")
        for node in tested:
            check(node.get("alpn") == "http/1.1", f"upgrade alpn: {label} offers exactly http/1.1 when tested")
            check("&alpn=http%2F1.1" in node.to_link(), f"upgrade alpn: {label} is emitted as alpn=http%2F1.1")
            check(node.to_outbound("t")["streamSettings"]["tlsSettings"]["alpn"] == ["http/1.1"],
                  f"upgrade alpn: {label} renders tlsSettings.alpn as [http/1.1]")

# A source spelling the key differently still ends up as the one "alpn" key.
for node in one(**{**BASE, "ALPN": "h2"}):
    check([k for k in node.params if k.lower() == "alpn"] == ["alpn"],
          "upgrade alpn: a source's ALPN key is replaced by a single lowercase alpn")

# A converted plaintext ws node gets it too, and it survives publishing.
for transport in ("ws", "httpupgrade"):
    for node in finalised(security="none", type=transport, host="p.example", path="/",
                          port="8080", alpn="h2"):
        check(node.get("alpn") == "http/1.1",
              f"upgrade alpn: a converted, published {transport} node offers http/1.1")

# grpc and xhttp are not Upgrade transports -- both can run over h2 -- so they
# keep whatever their source said, including nothing.
for transport in ("grpc", "xhttp"):
    for node in one(**{**BASE, "type": transport, "serviceName": "gs", "alpn": "h2"}):
        check(node.get("alpn") == "h2", f"upgrade alpn: a {transport} node's own alpn is left alone")
    for node in one(**{**BASE, "type": transport, "serviceName": "gs"}):
        check(not node.has("alpn"), f"upgrade alpn: a {transport} node without alpn is not given one")

# Two ws nodes that differed only in their source alpn are one node now.
twins = transform.transform(
    [parse_line(link(**{**BASE, "alpn": "h2"})), parse_line(link(**{**BASE, "alpn": "http/1.1"}))], {}
)
check(len(twins) == 1, "upgrade alpn: ws nodes differing only in source alpn deduplicate")

# --- published variants ----------------------------------------------------
# Every healthy node is published once per variant -- (prefix_name, ip, port,
# fm, dialMode, security, ech, echOutbound, fp, cs) -- its variants adjacent,
# so N survivors and I variants make N * I configs in one file.


def entry(**fields: str) -> tuple:
    """A variant entry by field name, in transform.Variant's order. Anything
    not given takes the default endpoint, security=tls and an empty value, so
    each case says only what it is about -- and none breaks when a field is
    added."""
    values = {field: "" for field in transform.Variant._fields}
    values.update(ip="188.114.98.0", port="443", security="tls")
    unknown = set(fields) - set(values)
    assert not unknown, f"not Variant fields: {unknown}"
    values.update(fields)
    return tuple(values[field] for field in transform.Variant._fields)


def set_variants(*entries: tuple) -> None:
    """Patch VARIANTS and VARIANTS_ENCODED together, so _self_check still has
    a consistent pair of lists to look at, written as transform.py writes
    them."""
    transform.VARIANTS = [transform.Variant(*entry) for entry in entries]
    transform.VARIANTS_ENCODED = [encode(variant) for variant in transform.VARIANTS]


def survivors(count: int) -> list[Node]:
    """`count` distinct transformed nodes, as the health check hands them over."""
    nodes: list[Node] = []
    for index in range(count):
        nodes.extend(one(**{**BASE, "host": f"h{index}.example"}))
    return nodes


ECH_DNS = "cloudflare-ech.com+https://1.1.1.1/dns-query"
ECH_OUT = '{"tag": "ech-out", "protocol": "freedom"}'

real_variants = transform.VARIANTS
real_variants_encoded = transform.VARIANTS_ENCODED
try:
    # Every field varies independently across the three, so a field wired to
    # the wrong place cannot line up with the right value by accident: three
    # endpoints (IPv4, an alternate Cloudflare port, IPv6), and the third
    # published without TLS.
    V1 = entry(fm='{"tcp": []}', fp="unsafe", cs="TLS_AES_256_GCM_SHA384",
               cp="X25519MLKEM768,X25519", esr="1")
    V2 = entry(ip="104.16.0.1", port="2053",
               fm='{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello"}}]}',
               dial_mode="code-1", ech=ECH_DNS, ech_outbound=ECH_OUT, fp="chrome",
               cs="TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")
    V3 = entry(ip="2606:4700::1", port="8080", dial_mode="code-2", security="none")
    VARIANTS3 = [transform.Variant(*v) for v in (V1, V2, V3)]
    set_variants(V1, V2, V3)

    pool = survivors(4)
    published = transform.finalise(pool, {})
    check(len(published) == 12, "variants: N survivors x I variants = N*I configs")
    check([n.host for n in published]
          == [f"h{i}.example" for i in range(4) for _ in range(3)],
          "variants: a node's variants are adjacent and the node order is kept")
    for field, key in zip(transform.PARAM_FIELDS, transform.VARIANT_KEYS):
        check([n.get(key) for n in published] == [getattr(v, field) for v in VARIANTS3] * 4,
              f"variants: {key} is taken from its own variant, in list order")
    check([n.security for n in published] == ["tls", "tls", "none"] * 4,
          "variants: security is taken from its own variant, in list order")
    check([(n.address, n.port) for n in published] == [(v.ip, v.port) for v in VARIANTS3] * 4,
          "variants: each variant of a node is published on its own ip and port")
    check(all(not n.has(key) for n in published[2::3]
              for key in ("fm", "ech", "echOutbound", "fp", "cs", "cp", "esr")),
          "variants: empty parameter fields publish nothing")
    check(all(not n.has(key) for n in published[0::3] for key in ("dialMode", "ech", "echOutbound")),
          "variants: empty dialMode, ech and echOutbound fields publish nothing")
    check(all(not n.has(key) for n in published[1::3] for key in ("cp", "esr")),
          "variants: empty cp and esr fields publish nothing")

    # A plaintext copy drops what only exists inside TLS; a TLS copy keeps it.
    check(all(not n.has("sni") and not n.has("alpn") for n in published[2::3]),
          "variants: a security=none copy publishes no sni and no alpn")
    check(all(n.get("sni") == n.host and n.get("alpn") == "http/1.1"
              for i, n in enumerate(published) if i % 3 != 2),
          "variants: a TLS copy keeps sni=host and the http/1.1 alpn")
    plain_stream = published[2].to_outbound("t")["streamSettings"]
    check(plain_stream["security"] == "none" and "tlsSettings" not in plain_stream,
          "variants: a security=none copy renders a plaintext outbound")
    check("security=none" in published[2].to_link(), "variants: and says so in its link")

    # cp and esr as both clients read them: cp's names joined by a comma that the
    # link percent-encodes, as it does alpn's, and esr=1; right after cs, as
    # PattN's own share links and QR-code JSON have them.
    curved = published[0].to_link()
    check("&cp=X25519MLKEM768%2CX25519&" in curved and "&esr=1&" in curved,
          "variants: cp and esr are byte-exact in the published link")
    check(curved.index("&cs=") < curved.index("&cp=") < curved.index("&esr=") < curved.index("&fm="),
          "variants: cp and esr follow cs in the published link")
    curved_tls = published[0].to_outbound("t")["streamSettings"]["tlsSettings"]
    check(curved_tls.get("curvePreferences") == ["X25519MLKEM768", "X25519"],
          "variants: cp renders tlsSettings.curvePreferences as a list of names")
    check(curved_tls.get("enableSessionResumption") is True,
          "variants: esr=1 renders tlsSettings.enableSessionResumption as true")
    plain_tls = published[1].to_outbound("t")["streamSettings"]["tlsSettings"]
    check("curvePreferences" not in plain_tls and "enableSessionResumption" not in plain_tls,
          "variants: without cp or esr, neither is rendered")
    spaced = Node("vless", "u", "a", "443", {"security": "tls", "cp": "x25519mlkem768, x25519 ,"})
    check(spaced.to_outbound("t")["streamSettings"]["tlsSettings"]["curvePreferences"]
          == ["x25519mlkem768", "x25519"],
          "variants: cp's names are trimmed and empty ones left out, as the clients do")
    check("enableSessionResumption" not in Node("vless", "u", "a", "443", {"security": "tls", "esr": "0"})
          .to_outbound("t")["streamSettings"]["tlsSettings"],
          "variants: an esr other than 1 renders no session resumption, as the clients read it")

    # Variants of one node are the same node: only what a variant sets differs.
    def not_set_by_variant(node: Node) -> dict:
        set_by_variant = set(transform.DEFERRED_KEYS) | {"security"} | set(transform.TLS_ONLY_KEYS)
        return {k.lower(): v for k, v in node.params.items() if k.lower() not in set_by_variant}

    trio = published[:3]
    check(not_set_by_variant(trio[0]) == not_set_by_variant(trio[1]) == not_set_by_variant(trio[2]),
          "variants: variants of one node differ in nothing but what the variant sets")
    check(len({(n.scheme, n.uid, n.host) for n in trio}) == 1,
          "variants: variants of one node share its identity")
    check(len({n.tag for n in published}) == 12,
          "variants: every published config gets a name of its own")

    # Both clients read these keys by their exact spelling -- PattNG with an
    # exact-case map lookup -- so a source's own casing must not survive into
    # the published link, even though it was stripped case-insensitively.
    shouting = one(**{**BASE, "host": "hs.example", "ECH": "x", "ECHOUTBOUND": "y",
                      "DIALMODE": "z", "FM": "w", "FP": "v", "CS": "u", "CP": "t", "ESR": "s"})
    # Every copy at once: each key is set by at least one of the variants.
    emitted = " ".join(n.to_link() for n in transform.finalise(shouting, {}))
    # Pinned literally: every other check reads VARIANT_KEYS itself, so a
    # misspelling there would be checked against the misspelling.
    CLIENT_KEYS = ("fm", "dialMode", "ech", "echOutbound", "fp", "cs", "cp", "esr")
    check(transform.VARIANT_KEYS == CLIENT_KEYS,
          "variants: the eight keys are spelled exactly as PattN and PattNG read them")
    for key in CLIENT_KEYS:
        check(f"&{key}=" in emitted, f"variants: {key} is emitted under its exact spelling")
    check(not any(f"&{key.upper()}=" in emitted for key in transform.VARIANT_KEYS),
          "variants: a source's casing of a deferred key never reaches the link")

    # finalise builds new nodes; one survivor becomes several, so there is
    # nothing sensible to mutate in place.
    check(all(not n.has(key) for n in pool for key in transform.VARIANT_KEYS),
          "variants: finalise leaves the nodes it was handed untouched")
    check(all(n.address == transform.HEALTHCHECK_ADDRESS and n.security == "tls" for n in pool),
          "variants: finalise neither repoints nor un-TLSes the nodes it was handed")

    measured = survivors(1)
    measured[0].latency_ms = 42
    check([n.latency_ms for n in transform.finalise(measured, {})] == [42, 42, 42],
          "variants: the measured latency is carried onto every variant")

    stats: dict = {}
    transform.finalise(survivors(2), stats)
    check(stats["published"] == 6 and stats["published_variants"] == 3,
          "variants: the counts describe the expansion")
    check([stats[f"published_with_{key}"] for key in transform.VARIANT_KEYS] == [4, 4, 2, 2, 4, 4, 2, 2],
          "variants: the counts only count configs that really carry each field")
    check(stats["published_without_tls"] == 2, "variants: plaintext copies are counted")

    # A single variant has to behave exactly as the pipeline did before.
    transform.VARIANTS, transform.VARIANTS_ENCODED = real_variants, real_variants_encoded
    solo = transform.finalise(survivors(3), {})
    check(len(solo) == 3, "variants: one variant publishes one config per node")
    check([n.tag for n in solo]
          == [one(**{**BASE, "host": f"h{i}.example"})[0].tag for i in range(3)],
          "variants: one variant leaves the published names exactly as they were")

    # The self-source round trip has to survive the expansion: re-reading a
    # published file collapses the variants back to one node each -- the
    # plaintext copy too, which rule 9 turns back into TLS -- and re-expands to
    # the identical file.
    set_variants(V1, V2, V3)
    links = [n.to_link() for n in transform.finalise(survivors(2), {})]
    check(len(links) == 6, "variants: three variants of two nodes make six links")
    stats = {}
    collapsed = transform.transform([parse_line(line) for line in links], stats)
    check(len(collapsed) == 2,
          "variants: re-reading the published file collapses back to the nodes")
    check(stats.get("converted_to_tls_rule_9") == 2,
          "variants: the plaintext copies come back through rule 9")
    check(all(not n.has(key) for n in collapsed for key in transform.VARIANT_KEYS),
          "variants: a re-read variant carries none of the six into the next check")
    check([n.to_link() for n in transform.finalise(collapsed, {})] == links,
          "variants: and re-expands to exactly the same file")

    # Retuning a variant must not rename what is published: finalise names each
    # copy from the node as tested and the variant's index, never from what
    # the variant adds, or a fragment tweak would rewrite every name.
    names_before = [n.tag for n in transform.finalise(survivors(2), {})]
    set_variants(
        transform.Variant(*V1)._replace(cs="TLS_AES_128_GCM_SHA256", ip="104.16.0.9",
                                        port="2052", security="none", fp="", fm=""),
        transform.Variant(*V2)._replace(fm='{"tcp": [{"type": "fragment"}]}', fp="firefox",
                                        cs="TLS_AES_256_GCM_SHA384", port="2096"),
        transform.Variant(*V3)._replace(security="tls", port="443", fp="unsafe"),
    )
    check([n.tag for n in transform.finalise(survivors(2), {})] == names_before,
          "variants: retuning any field of any variant, security included, renames nothing")
    set_variants(V1, V2, V3)

    # _self_check is where a badly written variant list has to stop -- before
    # anything is fetched, and long before a list whose every config fails at
    # connect time could be published.
    for label, entries, expected in (
        ("an empty list", (), "nothing to publish"),
        ("a repeated entry", (V1, V1), "duplicate"),
        ("an fm that is not JSON", (entry(fm="{not json"),), "not valid JSON"),
        # security, and the port family that has to go with it
        ("an empty security", (entry(security=""),), "has to be one of"),
        ("security spelled in capitals", (entry(security="TLS"),), "has to be one of"),
        ("a security the pipeline cannot publish", (entry(security="reality"),), "has to be one of"),
        ("tls on a Cloudflare HTTP port", (entry(port="8080"),), "HTTPS ports"),
        ("none on a Cloudflare HTTPS port", (entry(security="none", port="443"),), "HTTP ports"),
        ("none on a port Cloudflare does not serve", (entry(security="none", port="81"),), "HTTP ports"),
        ("none with an fp", (entry(security="none", port="8080", fp="chrome"),), "inside TLS"),
        ("none with a cs", (entry(security="none", port="8080", cs="TLS_AES_128_GCM_SHA256"),),
         "inside TLS"),
        ("none with an ech", (entry(security="none", port="8080", ech=ECH_DNS),), "inside TLS"),
        ("none with an echOutbound",
         (entry(security="none", port="8080", ech=ECH_DNS, ech_outbound=ECH_OUT),), "inside TLS"),
        # ech, mirroring what the core accepts when it dials
        ("an ech that is neither base64 nor a query", (entry(ech="not base64!"),), "neither a base64"),
        ("an ech query with an empty name", (entry(ech="+https://1.1.1.1/dns-query"),), "needs the name"),
        ("an ech query to a server the core cannot use", (entry(ech="x+tls://1.1.1.1"),), "only fetches"),
        # echOutbound, mirroring what PattN and PattNG accept
        ("an echOutbound without an ech", (entry(ech_outbound=ECH_OUT),), "needs an ech"),
        ("an echOutbound that is not JSON", (entry(ech=ECH_DNS, ech_outbound="{bad"),), "not valid JSON"),
        ("an echOutbound that is not an object", (entry(ech=ECH_DNS, ech_outbound="[1]"),),
         "not a JSON object"),
        ("an echOutbound with no tag", (entry(ech=ECH_DNS, ech_outbound='{"protocol": "freedom"}'),),
         "no tag"),
        ("an echOutbound tagged direct", (entry(ech=ECH_DNS, ech_outbound='{"tag": "direct"}'),),
         "may not be"),
        ("an echOutbound tagged block", (entry(ech=ECH_DNS, ech_outbound='{"tag": "block"}'),),
         "may not be"),
        ("an echOutbound tagged proxy", (entry(ech=ECH_DNS, ech_outbound='{"tag": "proxy"}'),),
         "may not be"),
        ("an echOutbound tagged proxy-2", (entry(ech=ECH_DNS, ech_outbound='{"tag": "proxy-2"}'),),
         "may not be"),
        ("an echOutbound repeating a key",
         (entry(ech=ECH_DNS, ech_outbound='{"tag": "a", "tag": "b"}'),), "repeated key"),
        # cs, which the core would otherwise trim without a word
        ("a cs naming a suite Go does not know",
         (entry(cs="TLS_AES_128_GCM_SHA256:TLS_NOT_A_SUITE"),), "does not know"),
        ("a cs that is all typos", (entry(cs="TLS_AES_128_GCM"),), "does not know"),
        ("a cs naming a suite twice",
         (entry(cs="TLS_AES_128_GCM_SHA256:TLS_AES_128_GCM_SHA256"),), "twice"),
        # prefix_name, which starts every name its variant publishes
        ("a prefix_name with a space after it", (entry(prefix_name="F&F "),), "spaces around it"),
        ("a prefix_name with a space before it", (entry(prefix_name=" F&F"),), "spaces around it"),
        ("a prefix_name with a line break", (entry(prefix_name="F&F\nX"),), "control character"),
        ("a prefix_name with a tab", (entry(prefix_name="F\tF"),), "control character"),
        ("two entries differing only in prefix_name",
         (entry(prefix_name="F&F"), entry(prefix_name="ECH")), "duplicate"),
        # cp, which the core trims as quietly as cs, and applies under Go's own TLS alone
        ("a cp naming a curve the core does not know", (entry(fp="unsafe", cp="X25519,X448"),),
         "does not know"),
        ("a cp written with cs's colons", (entry(fp="unsafe", cp="X25519MLKEM768:X25519"),),
         "does not know"),
        ("a cp with an empty name", (entry(fp="unsafe", cp="X25519,"),), "does not know"),
        ("a cp naming a curve twice", (entry(fp="unsafe", cp="X25519,x25519"),), "twice"),
        ("a cp under the chrome fingerprint", (entry(fp="chrome", cp="X25519"),), "needs fp=unsafe"),
        ("a cp under an empty fingerprint, which is Chrome's", (entry(cp="X25519"),),
         "needs fp=unsafe"),
        ("none with a cp", (entry(security="none", port="8080", cp="X25519"),), "inside TLS"),
        # esr, of which both clients read "1" alone as on
        ("an esr of true", (entry(esr="true"),), "has to be"),
        ("an esr of 0", (entry(esr="0"),), "has to be"),
        ("none with an esr", (entry(security="none", port="8080", esr="1"),), "inside TLS"),
    ):
        set_variants(*entries)
        try:
            transform._self_check()
            check(False, f"variants: _self_check rejects {label}")
        except AssertionError as error:
            check(expected in str(error), f"variants: _self_check rejects {label}")

    # And accepts what both clients and the core accept, including the forms
    # that look wrong at a glance: base64 carries '+', and the clients' prefix
    # check is case-sensitive.
    accepted_cases = [
        ("an ech query naming its server", (entry(ech=ECH_DNS),)),
        ("an ech query of the node's own SNI", (entry(ech="https://1.1.1.1/dns-query"),)),
        ("an ech query over udp", (entry(ech="ip.gs+udp://8.8.8.8"),)),
        ("a base64 ech containing +", (entry(ech="AEX+DQBBAA=="),)),
        ("an echOutbound with its ech", (entry(ech=ECH_DNS, ech_outbound=ECH_OUT),)),
        ("an echOutbound tagged Proxy", (entry(ech=ECH_DNS, ech_outbound='{"tag": "Proxy"}'),)),
        ("a cs from Go's insecure list", (entry(cs="TLS_RSA_WITH_AES_128_CBC_SHA"),)),
        # real_variants, not transform.VARIANTS: inside this block the latter is
        # whatever the previous case patched in.
        ("the default cs", (entry(cs=real_variants[0].cs),)),
        ("none with an fm and a dialMode",
         (entry(security="none", port="8080", fm='{"tcp": []}', dial_mode="code-1"),)),
        ("the same node with and without TLS",
         (entry(), entry(security="none", port="8080"))),
        ("no prefix_name", (entry(prefix_name=""),)),
        ("a prefix_name of several words", (entry(prefix_name="Fast ECH"),)),
        ("a prefix_name of symbols and emoji", (entry(prefix_name="F&F 🇩🇪 #1 | x"),)),
        ("an emoji joined by a zero-width joiner", (entry(prefix_name="🏳️‍🌈"),)),
        ("two variants sharing a prefix_name",
         (entry(prefix_name="IPv6"), entry(prefix_name="IPv6", ip="104.16.0.1"))),
        ("a cp of the curves both clients offer", (entry(fp="unsafe", cp="X25519MLKEM768,X25519"),)),
        ("a cp of every curve the core knows",
         (entry(fp="unsafe", cp="CurveP256,CurveP384,CurveP521,X25519,X25519MLKEM768,"
                                "SecP256r1MLKEM768,SecP384r1MLKEM1024"),)),
        ("a cp in lower case, spaced after its commas", (entry(fp="unsafe", cp="x25519mlkem768, x25519"),)),
        ("a cp under fp=UNSAFE in capitals", (entry(fp="UNSAFE", cp="X25519"),)),
        ("an esr of 1", (entry(esr="1"),)),
        ("an esr under a uTLS fingerprint", (entry(fp="chrome", esr="1"),)),
    ]
    for port in transform.PORTS_MAPPED_TO_8080:
        accepted_cases.append((f"none on Cloudflare HTTP port {port}",
                               (entry(security="none", port=port),)))
    for label, entries in accepted_cases:
        set_variants(*entries)
        try:
            transform._self_check()
            check(True, f"variants: _self_check accepts {label}")
        except AssertionError as error:
            check(False, f"variants: _self_check accepts {label} ({error})")

    # Entries that are not twelve strings at all -- including every shape the
    # list has had before, so an old entry pasted back in is refused clearly.
    for label, bad in (
        ("an entry of the old two-field shape", ("{}", "")),
        ("an entry of the old four-field shape", ("{}", "", "", "")),
        ("an entry of the old six-field shape", ("{}", "", "", "", "unsafe", "")),
        ("an entry of the old eight-field shape",
         ("188.114.98.0", "443", "{}", "", "", "", "unsafe", "")),
        ("an entry of the old nine-field shape, without a prefix_name", entry()[1:-2]),
        ("an entry of the old ten-field shape, without cp and esr", entry()[:-2]),
        ("an entry with a field that is not a string", entry()[:5] + (None,) + entry()[6:]),
        ("an entry with a port that is not a string",
         tuple(443 if field == "port" else value
               for field, value in zip(transform.Variant._fields, entry()))),
    ):
        transform.VARIANTS_ENCODED = [bad]
        try:
            transform._self_check()
            check(False, f"variants: _self_check rejects {label}")
        except AssertionError as error:
            check("not a (prefix_name, ip, port, fm, dialMode, security, ech, echOutbound, fp, cs,"
                  " cp, esr) entry" in str(error), f"variants: _self_check rejects {label}")
finally:
    transform.VARIANTS, transform.VARIANTS_ENCODED = real_variants, real_variants_encoded

# --- one node on several addresses ------------------------------------------
# Variants that differ only in ip and port publish every healthy node once per
# address -- the reason ip and port are variant fields at all.

real_variants_mip = transform.VARIANTS
real_variants_encoded_mip = transform.VARIANTS_ENCODED
real_healthcheck_mip = (transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT)
try:
    def at(ip: str, port: str) -> tuple:
        """The default variant, published on ip:port."""
        return tuple(DEFAULT._replace(ip=ip, port=port))

    ENDPOINTS = [
        ("188.114.98.0", "443"),
        ("104.16.0.1", "2053"),
        ("2606:4700::1", "8443"),
        ("cf.example.net", "2096"),
    ]
    set_variants(*[at(*endpoint) for endpoint in ENDPOINTS])

    pool = survivors(3)
    tested_endpoints = {(n.address, n.port) for n in pool}
    check(tested_endpoints == {(transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT)},
          "endpoints: however many addresses are published, every node is tested on the one")

    published = transform.finalise(pool, {})
    check(len(published) == 3 * len(ENDPOINTS),
          "endpoints: N healthy nodes x I addresses = N*I published configs")
    check([(n.address, n.port) for n in published] == ENDPOINTS * 3,
          "endpoints: each node is published on every address, in the order listed")
    check(len({n.to_link() for n in published}) == len(published),
          "endpoints: no two published configs are the same link")
    check(len({n.tag for n in published}) == len(published),
          "endpoints: every address of a node gets a name of its own")

    # Within one node, the address is the only thing that differs.
    first = published[:len(ENDPOINTS)]
    check(len({tuple(sorted(n.params.items())) for n in first}) == 1,
          "endpoints: one node's copies carry identical parameters")
    check(all(n.get(key) == value for n in first for key, value in DEFAULT.params.items() if value),
          "endpoints: and those are the variant's own parameters")

    # IPv6 is bracketed in the link, bare everywhere else; a hostname is as written.
    v6 = published[2]
    check("@[2606:4700::1]:8443?" in v6.to_link(),
          "endpoints: an IPv6 address is bracketed in the published link")
    check(parse_line(v6.to_link()).address == "2606:4700::1",
          "endpoints: and parses back to the bare address")
    check(v6.to_outbound("t")["settings"]["vnext"][0]["address"] == "2606:4700::1",
          "endpoints: the outbound gets the bare IPv6 address")
    check("@cf.example.net:2096?" in published[3].to_link(),
          "endpoints: a hostname is published as written")
    check([transform.endpoint_text(ip, port) for ip, port in ENDPOINTS]
          == ["188.114.98.0:443", "104.16.0.1:2053", "[2606:4700::1]:8443", "cf.example.net:2096"],
          "endpoints: logs and labels write an IPv6 endpoint bracketed, as links do")

    # configs.txt is a source. Copies of one node on four addresses must come
    # back as one node -- tested once, on the health-check endpoint -- and go
    # out again as exactly the same four links.
    links = [n.to_link() for n in published]
    collapsed = transform.transform([parse_line(line) for line in links], {})
    check(len(collapsed) == 3,
          "endpoints: re-reading the published file collapses each node's addresses into one")
    check({(n.address, n.port) for n in collapsed}
          == {(transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT)},
          "endpoints: and re-tests them on the health-check endpoint, not a published one")
    check([n.to_link() for n in transform.finalise(collapsed, {})] == links,
          "endpoints: and re-expands to exactly the same links")

    # What _self_check refuses, and what it lets through.
    for label, endpoint, expected in (
        ("an empty ip", ("", "443"), "empty"),
        ("an ip with a space around it", (" 188.114.98.0", "443"), "spaces"),
        ("a mistyped IPv4 address", ("188.114.976", "443"), "not a valid IPv4 address"),
        ("a bracketed IPv6 address", ("[2606:4700::1]", "443"), "without brackets"),
        ("an ip that is no address at all", ("bad_host!", "443"), "neither an IP address"),
        ("a Cloudflare plaintext port", ("188.114.98.0", "8080"), "HTTPS ports"),
        ("an arbitrary port", ("188.114.98.0", "444"), "HTTPS ports"),
        ("a port that is not a number", ("188.114.98.0", "https"), "HTTPS ports"),
        ("an empty port", ("188.114.98.0", ""), "HTTPS ports"),
    ):
        set_variants(at(*endpoint))
        try:
            transform._self_check()
            check(False, f"endpoints: _self_check rejects {label}")
        except AssertionError as error:
            check(expected in str(error), f"endpoints: _self_check rejects {label}")

    for port in transform.PORTS_MAPPED_TO_443:
        set_variants(at("188.114.98.0", port))
        try:
            transform._self_check()
            check(True, f"endpoints: _self_check accepts Cloudflare HTTPS port {port}")
        except AssertionError as error:
            check(False, f"endpoints: _self_check accepts Cloudflare HTTPS port {port} ({error})")

    # A loopback address is a relay on the user's own device -- an SNI-spoofing
    # tool, say -- so any port is the relay's own, with TLS or without. Every
    # other address still needs one of Cloudflare's ports.
    def relay(ip: str, port: str, security: str = "tls") -> tuple:
        """The default variant, published through a relay at ip:port."""
        variant = DEFAULT._replace(ip=ip, port=port, security=security)
        if security == "none":
            variant = variant._replace(fp="", cs="", ech="", ech_outbound="")
        return tuple(variant)

    for ip, port, security in (
        ("127.0.0.1", "40443", "tls"),
        ("127.0.0.1", "40443", "none"),
        ("127.0.0.1", "1", "tls"),
        ("127.0.0.1", "65535", "tls"),
        ("127.0.0.2", "443", "tls"),
        ("::1", "1080", "tls"),
    ):
        label = f"a loopback relay on {transform.endpoint_text(ip, port)} with security={security}"
        set_variants(relay(ip, port, security))
        try:
            transform._self_check()
            check(True, f"endpoints: _self_check accepts {label}")
        except AssertionError as error:
            check(False, f"endpoints: _self_check accepts {label} ({error})")
    for label, ip, port, expected in (
        ("port 0 on a loopback relay", "127.0.0.1", "0", "port number"),
        ("port 65536 on a loopback relay", "127.0.0.1", "65536", "port number"),
        ("a loopback port with a letter in it", "127.0.0.1", "4o443", "port number"),
        ("a loopback port with a leading zero", "127.0.0.1", "040443", "port number"),
        ("an empty loopback port", "::1", "", "port number"),
        ("a relay's port on a Cloudflare address", "188.114.98.0", "40443", "HTTPS ports"),
        ("a relay's port on a private address", "192.168.1.1", "40443", "HTTPS ports"),
        ("localhost written as a name", "localhost", "40443", "HTTPS ports"),
    ):
        set_variants(relay(ip, port))
        try:
            transform._self_check()
            check(False, f"endpoints: _self_check rejects {label}")
        except AssertionError as error:
            check(expected in str(error), f"endpoints: _self_check rejects {label}")

    # Published through the relay, and read back from configs.txt: the relay's
    # copy is dropped by rule 4 -- its port is none of Cloudflare's -- and its
    # node comes back through the other variant, published again unchanged,
    # wherever the relay stands in the list.
    for order in ("second", "first"):
        variants = [at("188.114.98.0", "443"), relay("127.0.0.1", "40443")]
        if order == "first":
            variants.reverse()
        set_variants(*variants)
        relayed = [n.to_link() for n in transform.finalise(survivors(2), {})]
        through_relay = [parse_line(line) for line in relayed if "@127.0.0.1:40443?" in line]
        check(len(through_relay) == 2, f"endpoints: with the relay {order}, each node goes through it once")
        check(all(n.get("sni") == n.host and n.security == "tls" for n in through_relay),
              f"endpoints: with the relay {order}, its copies keep TLS and the node's SNI")
        stats = {}
        collapsed = transform.transform([parse_line(line) for line in relayed], stats)
        check(len(collapsed) == 2 and stats.get("dropped_rule_4_port") == 2,
              f"endpoints: with the relay {order}, read back, its copies are dropped and the nodes stay")
        check([n.to_link() for n in transform.finalise(collapsed, {})] == relayed,
              f"endpoints: with the relay {order}, the nodes are published again unchanged")
    set_variants(relay("127.0.0.1", "40443"))
    alone = [n.to_link() for n in transform.finalise(survivors(2), {})]
    check(transform.transform([parse_line(line) for line in alone], {}) == [],
          "endpoints: a list of relays alone gets nothing back from configs.txt")

    # The same address twice publishes the same link twice; two addresses with
    # the same parameters are exactly what this feature is for.
    set_variants(at(*ENDPOINTS[0]), at(*ENDPOINTS[0]))
    try:
        transform._self_check()
        check(False, "endpoints: _self_check rejects the same address listed twice")
    except AssertionError as error:
        check("duplicate" in str(error), "endpoints: _self_check rejects the same address listed twice")
    set_variants(*[at(*endpoint) for endpoint in ENDPOINTS])
    try:
        transform._self_check()
        check(True, "endpoints: _self_check accepts one parameter set on four addresses")
    except AssertionError as error:
        check(False, f"endpoints: _self_check accepts one parameter set on four addresses ({error})")

    # The health-check endpoint is held to the same rules.
    set_variants(at(*ENDPOINTS[0]))
    transform.HEALTHCHECK_PORT = "8080"
    try:
        transform._self_check()
        check(False, "endpoints: _self_check rejects a health-check port TLS cannot use")
    except AssertionError as error:
        check("HEALTHCHECK" in str(error),
              "endpoints: _self_check rejects a health-check port TLS cannot use")
finally:
    transform.VARIANTS, transform.VARIANTS_ENCODED = real_variants_mip, real_variants_encoded_mip
    transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT = real_healthcheck_mip

# --- names are pinned across versions --------------------------------------
# Every check above compares names computed by the same code, so a change to
# how names are made -- what the hash covers, its format -- would pass them all
# while renaming every config in configs.txt on the next run. These pin today's
# names. If one fails on purpose, the next published list is a full rename.
GOLDEN_LINK = ("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
               "?security=tls&type=ws&host=a.example&path=%2F#name")
golden = transform.transform([parse_line(GOLDEN_LINK)], {})[0]
check(golden.tag == "name | 122798",
      "naming: a node's published name is the one earlier versions gave it")
real_variants_golden = transform.VARIANTS
try:
    transform.VARIANTS = real_variants_golden + [real_variants_golden[0]._replace(ip="104.16.0.1")]
    check(transform.finalise([golden], {})[1].tag == "name | 917341",
          "naming: a second variant's name is the one earlier versions gave it")
    # A prefix_name is covered by the hash, so it gives a name a hash of its own.
    transform.VARIANTS = [real_variants_golden[0]._replace(prefix_name="F&F"),
                          real_variants_golden[0]._replace(prefix_name="ECH", ip="104.16.0.1")]
    check([n.tag for n in transform.finalise([golden], {})]
          == ["F&F name | 0649ee", "ECH name | df2db7"],
          "naming: a prefixed name is the one it was first published under")
finally:
    transform.VARIANTS = real_variants_golden

# --- the published header -------------------------------------------------
# Plaintext configs are a claim the health check never tested -- every node is
# checked over TLS -- so the file has to say so, and say nothing when there
# are none.
header_with = build.render(["vless://x"], {"final_total": 1, "published_without_tls": 3}, ["s"])
header_without = build.render(["vless://x"], {"final_total": 1, "published_without_tls": 0}, ["s"])
check("# 3 configs published without TLS; every node was tested over TLS only" in header_with,
      "header: plaintext configs are declared in the published file")
check("without TLS" not in header_without,
      "header: and nothing is said when every config is TLS")

# --- naming ----------------------------------------------------------------
# A published name carries a short content hash so a client can tell two nodes
# apart. It is taken from what the node IS upstream, not from what the pipeline
# injects, so repointing an endpoint or retuning a mask must not rename
# everything -- that would turn a run that found nothing new into a full-file
# diff and a pointless daily commit.


def _name_under(**overrides) -> str:
    """The published name of the BASE node with some tunables patched."""
    keys = list(overrides)
    saved = [getattr(transform, key) for key in keys]
    try:
        for key, value in overrides.items():
            setattr(transform, key, value)
        return one(**BASE)[0].tag
    finally:
        for key, value in zip(keys, saved):
            setattr(transform, key, value)


baseline_name = _name_under()
check(baseline_name.startswith("name | "),
      "naming: the source comment leads the published name")
for label, overrides in (
    ("a variant's ip", dict(VARIANTS=[transform.VARIANTS[0]._replace(ip="10.9.8.7")])),
    ("the health-check address", dict(HEALTHCHECK_ADDRESS="10.9.8.7")),
    ("a variant's port", dict(VARIANTS=[transform.VARIANTS[0]._replace(port="8443")])),
    ("fm and dialMode", dict(VARIANTS=[transform.VARIANTS[0]._replace(fm="{}", dial_mode="code-1")])),
    ("fp and cs", dict(VARIANTS=[transform.VARIANTS[0]._replace(
        fp="chrome", cs="TLS_AES_128_GCM_SHA256")])),
    ("ech and echOutbound", dict(VARIANTS=[transform.VARIANTS[0]._replace(
        ech="x+https://1.1.1.1/dns-query", ech_outbound='{"tag": "ech-out", "protocol": "freedom"}')])),
    ("cp and esr", dict(VARIANTS=[transform.VARIANTS[0]._replace(cp="X25519MLKEM768,X25519", esr="1")])),
):
    check(_name_under(**overrides) == baseline_name,
          f"naming: changing {label} does not rename nodes")

check(one(**{**BASE, "host": "b.example"})[0].tag != baseline_name,
      "naming: a genuinely different node still gets a different name")
check(transform.naming_identity(one(**BASE)[0])
      == transform.naming_identity(one(**{**BASE, "fm": "x", "dialMode": "y"})[0]),
      "naming: what a source supplied for fm or dialMode cannot affect a name")

# This project's own configs.txt is the first entry in sources.txt, so a node
# routinely arrives with a name this file already built. Re-appending the hash
# would grow the name by six characters every day, and since the name is part
# of the link, configs.txt would be rewritten and committed daily for nothing.
for raw, expected in (
    ("NAME | d152c7", "NAME"),
    ("NAME | d152c7 | d152c7 | aaa111", "NAME"),      # cleans up accumulated ones
    ("NAME | notahex", "NAME | notahex"),             # not a digest, left alone
    ("NAME | ABC123", "NAME | ABC123"),               # digests are lowercase
    ("NAME | abc12", "NAME | abc12"),                 # five characters, not six
    # Only a suffix is a suffix: a hash-shaped run in the middle of someone's
    # comment is part of their comment.
    ("a | abc123 | tail", "a | abc123 | tail"),
    ("abc123 tail", "abc123 tail"),
    ("a | b | c", "a | b | c"),
    ("", ""),
):
    got = transform.source_comment(Node("vless", "u", "a", "443", {}, raw))
    check(got == expected, f"naming: source_comment({raw!r}) -> {expected!r}")

# The property that matters: a published link fed back through the pipeline
# emits itself, byte for byte, however many times it goes round.
published_link = transform.finalise(one(**BASE), {})[0].to_link()
current = published_link
for cycle in range(1, 6):
    node = parse_line(current)
    current = transform.finalise(transform.transform([node], {}), {})[0].to_link()
    check(current == published_link,
          f"naming: cycle {cycle} of re-ingestion emits the identical link")
final_tag = parse_line(current).tag
check(final_tag.count("|") == 1,
      "naming: exactly one hash remains on the name after five cycles")

# --- name prefixes ---------------------------------------------------------
# Each variant's prefix_name starts the name of every config it publishes.
# configs.txt is a source, so a name comes back with that prefix on it, and it
# has to come off again -- under whatever prefix_name the run that published it
# had -- or a name would grow a prefix a day, and renaming a prefix would leave
# the old one behind.


def named(tag: str, head: str) -> bool:
    """Whether ``tag`` is ``head`` followed by the hash a published name ends in."""
    stem, separator, digest = tag.rpartition(" | ")
    return (stem == head and bool(separator) and len(digest) == 6
            and set(digest) <= set("0123456789abcdef"))


def read_back(links: list[str]) -> list[str]:
    """``links`` read as a source and published again, as the next run does."""
    nodes = transform.transform([parse_line(line) for line in links], {})
    return [node.to_link() for node in transform.finalise(nodes, {})]


def heads_of(links: list[str]) -> list[str]:
    """The names of ``links`` without their hash."""
    return [parse_line(line).tag.rpartition(" | ")[0] for line in links]


real_variants_prefix = transform.VARIANTS
real_variants_encoded_prefix = transform.VARIANTS_ENCODED
try:
    P1 = transform.Variant(*entry(prefix_name="F&F", fm='{"tcp": []}', fp="unsafe",
                                  cs="TLS_AES_256_GCM_SHA384"))
    P2 = transform.Variant(*entry(prefix_name="ECH", ech=ECH_DNS, fp="chrome"))
    P3 = transform.Variant(*entry(prefix_name="IPv6", ip="2606:4700::1", fp="chrome"))
    set_variants(P1, P2, P3)
    pair = [n for i in range(2) for n in one(**{**BASE, "host": f"p{i}.example"})]
    published = transform.finalise(pair, {})
    check(all(named(n.tag, head)
              for n, head in zip(published, ["F&F name", "ECH name", "IPv6 name"] * 2)),
          "prefix: each variant's prefix_name starts the names it publishes")
    check(len({n.tag for n in published}) == 6,
          "prefix: and every published config still has a name of its own")
    links = [n.to_link() for n in published]
    check("#F%26F%20name%20%7C%20" in links[0], "prefix: the name reaches the link percent-encoded")
    check(transform._decode_variants([encode(P1._replace(prefix_name="A%20B"))])[0].prefix_name
          == "A%20B", "prefix: a prefix_name is used as written, never percent-decoded")

    # Read back and published again, as every run does: the same file, however
    # many times round.
    current = links
    for cycle in range(1, 4):
        current = read_back(current)
        check(current == links, f"prefix: cycle {cycle} of reading configs.txt back emits it unchanged")

    # Whatever the list becomes, the next run names every config after it
    # alone: no trace of a prefix it no longer has, and none of them twice.
    for label, variants, heads in (
        ("renaming a prefix", (P1._replace(prefix_name="Frag"), P2, P3),
         ["Frag name", "ECH name", "IPv6 name"]),
        ("reordering the variants", (P3, P1, P2), ["IPv6 name", "F&F name", "ECH name"]),
        ("emptying a prefix", (P1._replace(prefix_name=""), P2, P3),
         ["name", "ECH name", "IPv6 name"]),
        ("a prefix of several words", (P1._replace(prefix_name="Fast F&F"), P2, P3),
         ["Fast F&F name", "ECH name", "IPv6 name"]),
        ("removing the first variant", (P2, P3), ["ECH name", "IPv6 name"]),
        ("adding a variant in front",
         (transform.Variant(*entry(prefix_name="New", ip="104.16.0.1")), P1, P2, P3),
         ["New name", "F&F name", "ECH name", "IPv6 name"]),
    ):
        set_variants(*variants)
        after = read_back(links)
        check(heads_of(after) == heads * 2, f"prefix: {label} takes over in the next run's names")
        check(read_back(after) == after, f"prefix: after {label}, the run after that changes nothing")
    set_variants(P1, P2, P3)

    # A list published before prefixes existed takes them on, comment intact.
    set_variants(*(v._replace(prefix_name="") for v in (P1, P2, P3)))
    legacy = [n.to_link() for n in transform.finalise(pair, {})]
    check(heads_of(legacy) == ["name"] * 6, "prefix: (an unprefixed list to start from)")
    set_variants(P1, P2, P3)
    check(read_back(legacy) == links, "prefix: an unprefixed list read back is published with its prefixes")

    # A config that comes back without its node's first variant -- copied
    # alone into some other list, say -- is recognised all the same, even
    # under a prefix renamed since.
    set_variants(P1, P2._replace(prefix_name="Encrypted"), P3)
    check(heads_of(read_back([links[1]])) == ["F&F name", "Encrypted name", "IPv6 name"],
          "prefix: a later variant's config read back alone sheds its prefix too")
    set_variants(P1, P2, P3)

    # A comment that starts with a prefix's own word keeps it: only what the
    # pipeline added comes off.
    set_variants(P2, P1)
    echo = [n.to_link() for n in transform.finalise(one(**{**BASE, "tag": "ECH node"}), {})]
    check(heads_of(echo) == ["ECH ECH node", "F&F ECH node"],
          "prefix: a comment starting with a prefix's word is published whole")
    check(read_back(echo) == echo, "prefix: and read back, keeps that word")
    set_variants(P1, P2, P3)

    # A node that has changed since it was published has a new hash, which no
    # longer covers the prefix on its old name. The prefix still comes off.
    def moved(line: str) -> str:
        node = parse_line(line)
        node.set("path", "/moved")
        return node.to_link()

    changed = read_back([moved(line) for line in links])
    check(heads_of(changed) == ["F&F name", "ECH name", "IPv6 name"] * 2,
          "prefix: a node changed since it was published sheds its old prefix too")
    check(not set(parse_line(line).tag for line in changed) & set(parse_line(line).tag for line in links),
          "prefix: (the change did reach the hash, so that is the case tested)")
    check(read_back(changed) == changed, "prefix: and once renamed, it stays as it is")

    # A list of one variant prefixes its names as well.
    set_variants(P1)
    check(named(transform.finalise(one(**BASE), {})[0].tag, "F&F name"),
          "prefix: a list of one variant prefixes its names too")

    # Two variants sharing a prefix still name their configs apart.
    set_variants(P3, P3._replace(ip="2606:4700::2"))
    shared = [n.to_link() for n in transform.finalise(one(**BASE), {})]
    check(heads_of(shared) == ["IPv6 name"] * 2 and len({parse_line(line).tag for line in shared}) == 2,
          "prefix: two variants sharing a prefix still name each config apart")
    check(read_back(shared) == shared, "prefix: and read back, both keep their names")

    # Generated names are prefixed too.
    set_variants(P1, P2, P3)
    real_keep = transform.KEEP_SOURCE_COMMENT
    try:
        transform.KEEP_SOURCE_COMMENT = False
        generated = [n.to_link() for n in transform.finalise(one(**BASE), {})]
        check(heads_of(generated) == [f"{p} a.example | vless-ws" for p in ("F&F", "ECH", "IPv6")],
              "prefix: a generated name is prefixed like a source's comment")
        check(read_back(generated) == generated, "prefix: and read back, stays as it is")
    finally:
        transform.KEEP_SOURCE_COMMENT = real_keep

    # With renaming off, a source's name is published as it is: no prefix, no hash.
    real_rename = transform.RENAME_NODES
    try:
        transform.RENAME_NODES = False
        check([n.tag for n in transform.finalise(one(**BASE), {})] == ["name"] * 3,
              "prefix: with RENAME_NODES off, a source's name is published untouched")
    finally:
        transform.RENAME_NODES = real_rename
finally:
    transform.VARIANTS, transform.VARIANTS_ENCODED = real_variants_prefix, real_variants_encoded_prefix
check(final_tag == baseline_name,
      "naming: five cycles of re-ingestion leave the name the first build gave it")

# --- parser edge cases -----------------------------------------------------

node = parse_line("vless://uid@[2001:db8::1]:443?type=ws&host=a.example&security=tls#n")
check(node is not None and node.address == "2001:db8::1", "parser: bracketed IPv6 address")
check(node is not None and node.port == "443", "parser: port after IPv6 brackets")
check("[2001:db8::1]:443" in node.to_link(), "parser: IPv6 is re-bracketed on output")

node = parse_line("trojan://pa:ss@word@host.example:443?type=ws&host=a.example")
check(node is not None and node.address == "host.example", "parser: userinfo containing @ and :")
check(node is not None and node.uid == "pa:ss@word", "parser: password preserved verbatim")

node = parse_line("vless://uid@h.example:443?path=/a%3Db&type=ws&host=a.example")
check(node is not None and node.get("path") == "/a=b", "parser: '=' inside an encoded value")

node = parse_line("vless://uid@h.example:443?type=ws&host=a.example")
check(node is not None and node.tag == "", "parser: missing fragment is empty, not an error")

node = parse_line("vless://uid@h.example:443#n")
check(node is not None and node.params == {}, "parser: empty query")

check(parse_line("") is None, "parser: blank line")
check(parse_line("#comment") is None, "parser: comment line")
check(parse_line("ss://whatever@h:443") is None, "parser: unsupported scheme")
check(parse_line("vmess://not-base64!!!") is None, "parser: malformed vmess")
check(parse_line("garbage") is None, "parser: no scheme separator")

node = parse_line("vless://uid@h.example:443?Host=Cap.example&type=ws&security=tls#n")
check(node is not None and node.host == "Cap.example", "parser: capitalised Host is found")

# Round trip: emitting and re-parsing must be stable.
for node in one(**BASE):
    emitted = node.to_link()
    reparsed = parse_line(emitted)
    check(reparsed is not None and reparsed.to_link() == emitted, "parser: emit/parse round trip")

# --- dedup -----------------------------------------------------------------

pair = [parse_line(link(**BASE)), parse_line(link(**BASE))]
check(len(transform.transform(pair, {})) == 1, "dedup: identical inputs collapse to one node")

differing = [parse_line(link(**BASE)), parse_line(link(**{**BASE, "host": "other.example"}))]
check(len(transform.transform(differing, {})) == 2, "dedup: different hosts stay distinct")

# --- vmess -----------------------------------------------------------------

VMESS = (
    "vmess://eyJ2IjoiMiIsInBzIjoibiIsImFkZCI6IjEuMi4zLjQiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1aWQiLCJhaWQi"
    "OiIwIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJhLmV4YW1wbGUiLCJwYXRoIjoiLyIsInRscyI6InRs"
    "cyJ9"
)
node = parse_line(VMESS)
check(node is not None and node.scheme == "vmess", "vmess: parses")
check(node is not None and node.transport == "ws", "vmess: net maps to transport")
check(node is not None and node.security == "tls", "vmess: tls maps to security")
check(node is not None and node.host == "a.example", "vmess: host")
check(transform.INCLUDE_VMESS is False, "vmess: excluded by default (cannot carry fm/cs)")
check(len(transform.transform([parse_line(VMESS)], {})) == 0, "vmess: dropped by the transform")

# vmess serialisation is only reachable when INCLUDE_VMESS is turned on, but a
# toggle nobody exercises is a toggle that breaks silently. These also verify
# the reason it is off: a vmess link genuinely cannot carry fm or cs.

VMESS_FULL = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "ps": "original name", "add": "9.9.9.9", "port": "2053",
    "id": "33333333-3333-3333-3333-333333333333", "aid": "0", "scy": "aes-128-gcm",
    "net": "ws", "type": "none", "host": "vm.example", "path": "/vm",
    "tls": "tls", "sni": "vm.example", "alpn": "", "fp": "chrome",
}).encode()).decode()

vm = parse_line(VMESS_FULL)
check(vm is not None, "vmess: a full link parses")
again = parse_line(vm.to_link())
check(again is not None, "vmess: re-parses after serialisation")
for field in ("scheme", "uid", "address", "port", "tag"):
    check(getattr(again, field) == getattr(vm, field), f"vmess: {field} survives a round trip")
for key in ("type", "security", "host", "path", "sni", "headerType"):
    check(again.get(key) == vm.get(key), f"vmess: {key} survives a round trip")
check(again.extra.get("scy") == "aes-128-gcm", "vmess: the cipher survives a round trip")

outbound = vm.to_outbound("t")
user = outbound["settings"]["vnext"][0]["users"][0]
check(outbound["protocol"] == "vmess", "vmess: outbound protocol")
check(user["alterId"] == 0 and user["security"] == "aes-128-gcm",
      "vmess: alterId and cipher reach the outbound")
check(outbound["streamSettings"]["network"] == "ws", "vmess: net maps to the stream network")

real_include = transform.INCLUDE_VMESS
try:
    transform.INCLUDE_VMESS = True
    vm_out = transform.transform([parse_line(VMESS_FULL)], {})
    check(len(vm_out) == 1, "vmess: with the toggle on it survives as a single node")
    check(vm_out[0].address == transform.HEALTHCHECK_ADDRESS,
          "vmess: rule 10 points a vmess node at the health-check address too")
    vm443 = transform.finalise(vm_out, {})[0]
    check(vm443.address == transform.VARIANTS[0].ip and vm443.security == "tls",
          "vmess: rules 8 and 10 apply to a vmess node")
    check(vm443.port == transform.VARIANTS[0].port,
          "vmess: a vmess node ends up on the output port like any other")
    check(vm443.get("fm") == transform.VARIANTS[0].fm and vm443.get("cs") == transform.VARIANTS[0].cs,
          "vmess: the pipeline sets fm and cs on the node")

    # The documented limitation, verified rather than assumed: the vmess wire
    # format has a fixed key set with nowhere to put fm or cs, so they are
    # silently lost on serialisation. That is why the toggle defaults to off.
    payload = json.loads(base64.b64decode(
        vm443.to_link().split("://", 1)[1] + "=="
    ).decode("utf-8", "replace"))
    check("fm" not in payload and "cs" not in payload,
          "vmess: the wire format has nowhere to carry fm or cs")
    check(DEFAULT_ENCODED["fm"] not in vm443.to_link(),
          "vmess: fm really is absent from the emitted link")
    check(payload["tls"] == "tls" and payload["sni"] == "vm.example",
          "vmess: what the format can carry is still carried")
    check(payload["add"] == transform.VARIANTS[0].ip
          and payload["port"] == transform.VARIANTS[0].port,
          "vmess: the rewritten address and port reach the wire format")
finally:
    transform.INCLUDE_VMESS = real_include

# --- masking constants round trip ------------------------------------------

# Every percent-encoded field of every variant, by name: prefix_name, ip and
# port are written plainly and so are not part of this; security is.
constant_pairs = []
for _i, (_v, _e) in enumerate(zip(SHIPPED_VARIANTS, SHIPPED_VARIANTS_ENCODED)):
    _encoded = dict(zip(transform.Variant._fields, _e))
    for _field in transform.Variant._fields:
        if _field not in transform.PLAIN_FIELDS:
            constant_pairs.append((f"VARIANTS[{_i}].{_field}", _encoded[_field], getattr(_v, _field)))
    check(all(getattr(_v, field) == _encoded[field] for field in transform.PLAIN_FIELDS),
          f"constants: VARIANTS[{_i}]'s prefix_name, ip and port are used exactly as written")
check(len(constant_pairs)
      == (len(transform.Variant._fields) - len(transform.PLAIN_FIELDS)) * len(SHIPPED_VARIANTS),
      "constants: every encoded field of every shipped variant is round-tripped")
for name, encoded, decoded in constant_pairs:
    check(quote(decoded, safe="") == encoded, f"constants: {name} survives a decode/encode cycle")

# --- Xray outbound rendering ----------------------------------------------


for node in finalised(**BASE):
    outbound = json.loads(json.dumps(node.to_outbound("t")))
    stream = outbound["streamSettings"]
    check(outbound["protocol"] == "vless", "outbound: protocol")
    check(stream["network"] == "ws", "outbound: network")
    check(isinstance(stream.get("finalmask"), dict), "outbound: fm becomes a finalmask object")
    check(stream["wsSettings"]["host"] == "a.example", "outbound: ws host header")
    check(stream["security"] == "tls", "outbound: every published node uses tls")
    check(stream["tlsSettings"]["fingerprint"] == "unsafe", "outbound: fingerprint")
    check(stream["tlsSettings"]["cipherSuites"] == transform.VARIANTS[0].cs, "outbound: cipherSuites")
    check(stream["tlsSettings"]["allowInsecure"] is False, "outbound: never skips verification")

# A node in the state the health check sees it: plain TLS to the right SNI,
# and nothing that would make the measurement about the masking rather than
# the node.
for node in one(**BASE):
    stream = node.to_outbound("t")["streamSettings"]
    tls_settings = stream["tlsSettings"]
    check("finalmask" not in stream, "outbound: a node being tested renders no finalmask")
    check("sockopt" not in stream, "outbound: a node being tested renders no sockopt")
    check("cipherSuites" not in tls_settings,
          "outbound: a node being tested renders no cipherSuites -- the core's defaults")
    check("fingerprint" not in tls_settings,
          "outbound: a node being tested renders no fingerprint -- the core's own TLS")
    check(tls_settings["serverName"] == "a.example",
          "outbound: a node being tested still presents the fronted host as SNI")

grpc = one(**{**BASE, "type": "grpc", "serviceName": "gs"})
check(len(grpc) == 1, "outbound: a grpc node reaches the outbound tests at all")
for node in grpc:
    outbound = node.to_outbound("t")
    check(outbound["streamSettings"]["network"] == "grpc", "outbound: grpc network")
    check(
        outbound["streamSettings"]["grpcSettings"]["authority"] == "a.example",
        "outbound: grpc authority comes from host",
    )

# --- health check: routing safety and bisection ------------------------------
# These do not need a network or an Xray binary, but they guard the property
# everything else rests on: a node must only be able to pass by carrying real
# traffic through its own outbound.

import healthcheck  # noqa: E402

batch = [n for spec in ({}, {"host": "b.example"}, {"host": "c.example"}) for n in one(**{**BASE, **spec})]
batch_ports = healthcheck._placeholder_ports(len(batch))
config = healthcheck._build_config(batch, batch_ports)

# If the default outbound were freedom rather than blackhole, traffic that
# missed its rule would go out directly and EVERY node would look healthy.
check(config["outbounds"][0]["protocol"] == "blackhole",
      "healthcheck: the default outbound is a blackhole, so nothing leaks direct")
check(not any(o.get("protocol") == "freedom" for o in config["outbounds"]),
      "healthcheck: no freedom outbound exists to fall through to")
check(config["routing"]["rules"][-1]["outboundTag"] == "block",
      "healthcheck: a catch-all rule blocks anything unmatched")

rules = config["routing"]["rules"][:-1]
check(len(rules) == len(batch), "healthcheck: every node gets exactly one routing rule")
check(
    all(r["inboundTag"] == [f"in-{i}"] and r["outboundTag"] == f"out-{i}"
        for i, r in enumerate(rules)),
    "healthcheck: inbound N routes to outbound N, never to a neighbour",
)
ports = [i["port"] for i in config["inbounds"]]
check(ports == batch_ports, "healthcheck: each inbound binds the port it was given")
check(len(set(ports)) == len(ports), "healthcheck: no two inbounds share a port")
check(all(i["listen"] == "127.0.0.1" for i in config["inbounds"]),
      "healthcheck: inbounds bind loopback only")
check(
    [o["tag"] for o in config["outbounds"][1:]] == [f"out-{i}" for i in range(len(batch))],
    "healthcheck: outbound order matches node order",
)

# Bisection must isolate exactly the offending node, keeping the rest.
POISON = "deadbeef-dead-beef-dead-beefdeadbeef"
poisoned = batch[0].copy()
poisoned.uid = POISON
mixed = batch[:2] + [poisoned] + batch[2:]


def _stub_accepted(xray, cfg, directory):
    """Stand in for Xray: reject any config containing the poisoned node."""
    for outbound in cfg["outbounds"]:
        for target in outbound.get("settings", {}).get("vnext", []):
            for user in target.get("users", []):
                if user.get("id") == POISON:
                    return False
    return True


real_accepted = healthcheck._config_accepted
try:
    healthcheck._config_accepted = _stub_accepted
    ok, bad = healthcheck.validate_nodes("xray", mixed, tempfile.gettempdir())
    check(len(bad) == 1 and bad[0].uid == POISON,
          "healthcheck: bisection isolates exactly the rejected node")
    check(len(ok) == len(mixed) - 1 and all(n.uid != POISON for n in ok),
          "healthcheck: the other nodes survive one bad node")

    # A node whose outbound cannot even be rendered must be rejected, not fatal.
    broken = batch[0].copy()
    broken.uid = "broken-node"
    broken.set("fm", "{not valid json")
    ok, bad = healthcheck.validate_nodes("xray", batch[:2] + [broken], tempfile.gettempdir())
    check(len(bad) == 1 and bad[0].uid == "broken-node",
          "healthcheck: an unrenderable outbound is rejected rather than crashing")
    check(len(ok) == 2, "healthcheck: an unrenderable node does not take the batch with it")
finally:
    healthcheck._config_accepted = real_accepted

# _run_batch maps each node to its own loopback port and each result back to
# that node. An off-by-one here would not fail loudly -- it would quietly
# credit one node with another's result and publish the wrong ones.
class _FakeProcess:
    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


probed_ports: list[int] = []
probed_endpoints: list[str] = []
FIXED_PORTS = [50101, 50102, 50103, 50104, 50105, 50106]
real_reserve = healthcheck.reserve_ports
real_popen = healthcheck.subprocess.Popen
real_wait = healthcheck._wait_until_listening
real_probe = healthcheck._probe
try:
    healthcheck.reserve_ports = lambda count: FIXED_PORTS[:count]
    healthcheck.subprocess.Popen = lambda *a, **k: _FakeProcess()
    healthcheck._wait_until_listening = lambda ports, deadline, process=None: True
    # Latency encodes the port, so a mis-mapped result is visible in the output.
    def _record(port, endpoint):
        probed_ports.append(port)
        probed_endpoints.append(endpoint.host)
        return (port % 2 == 0, float(port))

    healthcheck._probe = _record
    mapped = healthcheck._run_batch("xray", scored_batch := [n for n in one(**BASE)] * 3,
                                    tempfile.gettempdir(), "unit",
                                    healthcheck.TEST_ENDPOINTS[0])
finally:
    healthcheck.reserve_ports = real_reserve
    healthcheck.subprocess.Popen = real_popen
    healthcheck._wait_until_listening = real_wait
    healthcheck._probe = real_probe

check(sorted(probed_ports) == FIXED_PORTS[:len(scored_batch)],
      "healthcheck: each node in a batch is probed on its own reserved port, once")
check(
    all(latency == float(FIXED_PORTS[index]) for index, latency in mapped.items()),
    "healthcheck: a probe result is credited to the node it came from",
)
check(
    set(mapped) == {i for i in range(len(scored_batch)) if FIXED_PORTS[i] % 2 == 0},
    "healthcheck: only the nodes that passed appear in the result",
)
check(set(probed_endpoints) == {healthcheck.TEST_ENDPOINTS[0].host},
      "healthcheck: every node in a batch is measured against the same endpoint")


# Ports come from the OS, not a fixed range: a hardcoded range fails wholesale
# if anything else on the machine already listens in it.
reserved = healthcheck.reserve_ports(8)
check(len(reserved) == 8, "ports: the requested number of ports is reserved")
check(len(set(reserved)) == 8, "ports: reserved ports are distinct")
check(all(1024 < p < 65536 for p in reserved), "ports: reserved ports are usable numbers")
bound = []
try:
    for p_ in reserved:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", p_))
        bound.append(srv)
    check(True, "ports: every reserved port can actually be bound afterwards")
except OSError:
    check(False, "ports: every reserved port can actually be bound afterwards")
finally:
    for srv in bound:
        srv.close()
check(healthcheck.reserve_ports(0) == [], "ports: reserving none is not an error")

# A batch that cannot get ports must not take the whole run down with it: the
# rounds already completed would be lost.
_real_reserve = healthcheck.reserve_ports
try:
    def _refuse(count):
        raise OSError("no ports today")

    healthcheck.reserve_ports = _refuse
    with contextlib.redirect_stdout(io.StringIO()) as captured:
        result = healthcheck._run_batch(
            "xray", [n for n in one(**BASE)], tempfile.gettempdir(), "unit",
            healthcheck.TEST_ENDPOINTS[0],
        )
    check(result == {}, "ports: a batch that cannot reserve ports is simply untested")
    check("could not reserve" in captured.getvalue(),
          "ports: the reservation failure is reported, not swallowed")
finally:
    healthcheck.reserve_ports = _real_reserve
check(healthcheck._run_batch("xray", [], tempfile.gettempdir(), "unit",
                             healthcheck.TEST_ENDPOINTS[0]) == {},
      "ports: an empty batch is handled without indexing past the end")

# _wait_until_listening only probes the first and last port of a batch. That is
# only safe because Xray refuses to start at all when any one inbound cannot
# bind -- verified against the real core, which exits with "failed to listen
# TCP on <port>" and binds nothing. What makes the shortcut safe is polling the
# process, so a dead process must end the wait immediately rather than at the
# deadline.
class _DeadProcess:
    def poll(self):
        return 1


started = time.monotonic()
check(
    healthcheck._wait_until_listening([1], time.monotonic() + 30, _DeadProcess()) is False,
    "ports: a process that has already exited ends the wait",
)
check(time.monotonic() - started < 5,
      "ports: it notices immediately rather than waiting out the deadline")


class _LingeringProcess:
    def poll(self):
        return None


check(
    healthcheck._wait_until_listening([1], time.monotonic() + 0.5, _LingeringProcess())
    is False,
    "ports: a port that never opens times out rather than hanging",
)

# check() decides what is published. A node must pass EVERY round: passing
# some rounds is what "flaky" means, and publishing those is the mistake the
# three-round design exists to avoid.
scored = [n for i in range(5) for n in one(**{**BASE, "host": f"n{i}.example"})][:5]
for index, node in enumerate(scored):
    node.tag = f"node-{index}"

# node-0 and node-4 pass all three rounds; node-1 passes two; node-2 passes
# one; node-3 never passes.
# node-0's latencies are chosen so the median and the final round disagree on
# the ordering: by median it is slower than node-4, by last round it is faster.
ROUND_RESULTS = [
    {0: 300.0, 1: 10.0, 4: 50.0},
    {0: 100.0, 1: 10.0, 4: 50.0},
    {0: 20.0, 2: 10.0, 4: 50.0},
]
rounds_seen: list[str] = []

real_validate = healthcheck.validate_nodes
real_run_batch = healthcheck._run_batch
real_pause = healthcheck.PAUSE_BETWEEN_ROUNDS
real_usable_endpoints = healthcheck.usable_endpoints
try:
    healthcheck.validate_nodes = lambda xray, nodes, directory: (list(nodes), [])
    healthcheck.PAUSE_BETWEEN_ROUNDS = 0
    healthcheck.usable_endpoints = lambda: list(healthcheck.TEST_ENDPOINTS)

    def _stub_run_batch(xray, batch, directory, label, endpoint):
        rounds_seen.append(endpoint.host)
        return ROUND_RESULTS[len(rounds_seen) - 1]

    healthcheck._run_batch = _stub_run_batch
    stats: dict = {}
    # check() narrates its rounds; that belongs in a build log, not here.
    with contextlib.redirect_stdout(io.StringIO()):
        healthy = healthcheck.check("xray", scored, stats, rounds=3)

    survivors = [n.tag for n in healthy]
    check(survivors == ["node-4", "node-0"],
          "healthcheck: only nodes passing every round survive, fastest median first")
    check("node-1" not in survivors and "node-2" not in survivors,
          "healthcheck: a node passing some rounds is not published")
    check("node-3" not in survivors, "healthcheck: a node passing no round is not published")
    check(stats["healthy"] == 2, "healthcheck: the healthy count is recorded")
    check([stats[f"round_{i}_passed"] for i in (1, 2, 3)] == [3, 3, 3],
          "healthcheck: per-round pass counts are recorded")
    # 4 nodes worked at least once, 2 worked every time.
    check(stats["flaky_percent"] == 50.0, "healthcheck: flakiness is measured, not guessed")
    check(healthy[0].latency_ms == 50 and healthy[1].latency_ms == 100,
          "healthcheck: the published latency is the median across rounds")
    check(len(rounds_seen) == 3, "healthcheck: it really runs the requested number of rounds")
    check(rounds_seen == [e.host for e in healthcheck.TEST_ENDPOINTS[:3]],
          "healthcheck: each round uses a different endpoint, in order")
    check(len({e.host for e in healthcheck.TEST_ENDPOINTS}) == len(healthcheck.TEST_ENDPOINTS),
          "healthcheck: the endpoints are distinct hosts")

    # No nodes at all must not explode.
    empty_stats: dict = {}
    with contextlib.redirect_stdout(io.StringIO()):
        empty_result = healthcheck.check("xray", [], empty_stats)
    check(empty_result == [] and empty_stats["healthy"] == 0,
          "healthcheck: an empty node list is handled")
finally:
    healthcheck.validate_nodes = real_validate
    healthcheck._run_batch = real_run_batch
    healthcheck.PAUSE_BETWEEN_ROUNDS = real_pause
    # Leaving this stubbed would silently feed the endpoint tests below.
    healthcheck.usable_endpoints = real_usable_endpoints

# --- the variants this repository ships ---------------------------------------
# Everything else runs against the first shipped variant alone; this is where
# the list as configured in transform.py is held to account. _self_check has
# already accepted it on import, so what is left is what that cannot know.
check(len(SHIPPED_VARIANTS) >= 1, "shipped: at least one variant is configured")
check(len({v._replace(prefix_name="") for v in SHIPPED_VARIANTS}) == len(SHIPPED_VARIANTS),
      "shipped: no variant is listed twice, whatever its prefix_name")
real_variants_shipped = transform.VARIANTS
try:
    transform.VARIANTS = SHIPPED_VARIANTS
    shipped_probes = healthcheck.preflight_probes()
    check(len(shipped_probes) == 1 + len(SHIPPED_VARIANTS),
          "shipped: the preflight probes the tested shape and every shipped variant")
    check([(node.address, node.port, node.get("security")) for _, node in shipped_probes[1:]]
          == [(v.ip, v.port, v.security) for v in SHIPPED_VARIANTS],
          "shipped: each shipped variant is probed on its own endpoint and security")
    # Built here rather than with survivors(): the health-check tests above
    # reuse that name for a list.
    two_nodes = [n for i in range(2) for n in one(**{**BASE, "host": f"s{i}.example"})]
    shipped_names = [n.tag for n in transform.finalise(two_nodes, {})]
    check(len(shipped_names) == 2 * len(SHIPPED_VARIANTS) == len(set(shipped_names)),
          "shipped: every shipped variant of every node gets a name of its own")
    check(all(name.startswith(f"{variant.prefix_name} name | " if variant.prefix_name else "name | ")
              for name, variant in zip(shipped_names, SHIPPED_VARIANTS * 2)),
          "shipped: each shipped variant's names start with its prefix_name")
finally:
    transform.VARIANTS = real_variants_shipped

# The preflight has to exercise both shapes the pipeline emits -- the one the
# health check runs and the one the subscription publishes -- or it proves
# nothing about the core it is about to trust. The published shape matters most
# here: fm is added after the check, so the preflight is the only place in the
# pipeline that ever hands one to the core.
probes = healthcheck.preflight_probes()
check(len(probes) == 2, "healthcheck: the preflight checks both shapes")
tested_probe, published_probe = probes[0][1], probes[1][1]

check(
    not tested_probe.has("fp") and not tested_probe.has("cs"),
    "healthcheck: the tested probe carries the real fp and cs values",
)
check(not tested_probe.has("fm") and not tested_probe.has("dialMode"),
      "healthcheck: the tested probe carries no fm or dialMode, like the pool it stands for")
check((tested_probe.address, tested_probe.port)
      == (transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT),
      "healthcheck: the tested probe uses the real health-check endpoint")

check(published_probe.get("fm") == transform.VARIANTS[0].fm,
      "healthcheck: the published probe carries the real fm value")
check(published_probe.get("fp") == transform.VARIANTS[0].fp
      and published_probe.get("cs") == transform.VARIANTS[0].cs,
      "healthcheck: the published probe keeps fp and cs as well")
check((published_probe.address, published_probe.port)
      == (transform.VARIANTS[0].ip, transform.VARIANTS[0].port),
      "healthcheck: the published probe uses the real output endpoint")

check(tested_probe.security == "tls" and published_probe.security == "tls",
      "healthcheck: both probes are TLS outbounds")

rendered = json.dumps(
    healthcheck._build_config([published_probe], healthcheck._placeholder_ports(1))
)
check("finalmask" in rendered, "healthcheck: the published probe renders a finalmask")
rendered = json.dumps(
    healthcheck._build_config([tested_probe], healthcheck._placeholder_ports(1))
)
check("finalmask" not in rendered, "healthcheck: the tested probe renders no finalmask")

# A dialMode has to be validated too once one is set, and only on the shape
# that carries it.
real_variants = transform.VARIANTS
try:
    transform.VARIANTS = [real_variants[0]._replace(dial_mode="code-1")]
    dial_probes = healthcheck.preflight_probes()
    check("dialMode" in dial_probes[1][0],
          "healthcheck: a set dialMode is named in the published probe's description")
    check(dial_probes[1][1].get("dialMode") == "code-1",
          "healthcheck: a set dialMode reaches the published probe")
    check(not dial_probes[0][1].has("dialMode"),
          "healthcheck: a set dialMode never reaches the tested probe")
    rendered = json.dumps(
        healthcheck._build_config([dial_probes[1][1]], healthcheck._placeholder_ports(1))
    )
    check('"dialMode": "code-1"' in rendered,
          "healthcheck: the published probe renders the dialMode sockopt")
finally:
    transform.VARIANTS = real_variants

# Every variant needs a probe of its own. fm is the one value the health check
# never exercises, so this is the only place the core ever sees one -- probing
# just the first would let a bad second variant reach configs.txt unchallenged.
real_variants = transform.VARIANTS
try:
    transform.VARIANTS = [
        transform.Variant(*entry(fm='{"tcp": []}', fp="unsafe", cs="TLS_AES_256_GCM_SHA384",
                                 cp="X25519MLKEM768,X25519", esr="1")),
        transform.Variant(*entry(ip="104.16.0.1", port="2053",
                                 fm='{"tcp": [{"type": "fragment", "settings": {}}]}',
                                 dial_mode="code-1", ech="x+https://1.1.1.1/dns-query",
                                 ech_outbound='{"tag": "ech-out", "protocol": "freedom"}',
                                 fp="chrome", cs="TLS_AES_128_GCM_SHA256")),
        transform.Variant(*entry(ip="2606:4700::1", port="8080", dial_mode="code-2",
                                 security="none")),
    ]
    many = healthcheck.preflight_probes()
    check(len(many) == 4,
          "healthcheck: the preflight probes the tested shape plus every variant")
    check([node.get("fm") for _, node in many[1:]]
          == [variant.fm for variant in transform.VARIANTS],
          "healthcheck: each published probe carries its own variant's fm")
    check([node.get("dialMode") for _, node in many[1:]]
          == [variant.dial_mode for variant in transform.VARIANTS],
          "healthcheck: each published probe carries its own variant's dialMode")
    check("1/3" in many[1][0] and "3/3" in many[3][0],
          "healthcheck: the probe descriptions number the variants")
    # And name the masks each fm holds, so a refused one points at the right
    # kind -- a merge mask is not a fragment.
    for fm, label in (
        ("", "no fm"),
        ('{"tcp": [{"type": "fragment", "settings": {}}, {"type": "fragment", "settings": {}}]}',
         "fm fragment"),
        ('{"tcp": [{"type": "merge", "settings": {"times": 100}}]}', "fm merge"),
        ('{"tcp": [{"type": "fragment"}, {"type": "merge"}], "udp": [{"type": "noise"}]}',
         "fm fragment+merge+noise"),
        ('{"tcp": []}', "fm"),
        ("[1]", "fm"),
    ):
        check(healthcheck._fm_label(fm) == label,
              f"healthcheck: an fm of {fm[:44]!r} is described as {label!r}")
    check(f"({transform.VARIANTS[1].security} + fm fragment + " in many[2][0],
          "healthcheck: a published probe's description names its fm's masks")
    listed = transform.VARIANTS
    transform.VARIANTS = [transform.Variant(*entry(fm='{"tcp": [{"type": "merge", "settings": {}}]}'))]
    merge_probe = healthcheck.preflight_probes()[1][0]
    transform.VARIANTS = listed
    check("(tls + fm merge)" in merge_probe,
          "healthcheck: a probe whose fm is a merge mask is described as one, not as a fragment")
    check(not any(many[0][1].has(key) for key in transform.VARIANT_KEYS),
          "healthcheck: the tested probe is unaffected by how many variants there are")
    check([node.get("ech") for _, node in many[1:]]
          == [variant.ech for variant in transform.VARIANTS],
          "healthcheck: each published probe carries its own variant's ech")
    check([node.get("echOutbound") for _, node in many[1:]]
          == [variant.ech_outbound for variant in transform.VARIANTS],
          "healthcheck: each published probe carries its own variant's echOutbound")
    check([(node.get("fp"), node.get("cs")) for _, node in many[1:]]
          == [(variant.fp, variant.cs) for variant in transform.VARIANTS],
          "healthcheck: each published probe carries its own variant's fp and cs")
    check([(node.get("cp"), node.get("esr")) for _, node in many[1:]]
          == [(variant.cp, variant.esr) for variant in transform.VARIANTS],
          "healthcheck: each published probe carries its own variant's cp and esr")
    check("cp X25519MLKEM768,X25519 + esr" in many[1][0]
          and "cp " not in many[2][0] and "esr" not in many[2][0],
          "healthcheck: a probe's description names its curves and session resumption")
    check([(node.address, node.port) for _, node in many[1:]]
          == [(variant.ip, variant.port) for variant in transform.VARIANTS],
          "healthcheck: each published probe points at its own variant's endpoint")
    check((many[0][1].address, many[0][1].port)
          == (transform.HEALTHCHECK_ADDRESS, transform.HEALTHCHECK_PORT),
          "healthcheck: the tested probe stays on the one health-check endpoint")
    check("104.16.0.1:2053" in many[2][0],
          "healthcheck: a probe's description names its endpoint")
    check("ech" in many[2][0] and "echOutbound" in many[2][0] and "echOutbound" not in many[3][0],
          "healthcheck: a probe's description says which of the eight it carries")
    check("fp chrome" in many[2][0] and "fp" not in many[3][0],
          "healthcheck: a probe's description names its fingerprint")
    check(many[3][1].get("security") == "none"
          and not any(many[3][1].has(key) for key in transform.TLS_ONLY_KEYS),
          "healthcheck: a security=none variant is probed as plaintext, without sni or alpn")
    check(many[1][1].get("security") == "tls" and many[1][1].get("sni") == "example.com",
          "healthcheck: a tls variant is probed over TLS, with its sni")
    plain_config = healthcheck._preflight_config(many[3][1])
    check(plain_config["outbounds"][1]["streamSettings"]["security"] == "none",
          "healthcheck: and the config the core validates for it is plaintext")
finally:
    transform.VARIANTS = real_variants

# ech renders as tlsSettings.echConfigList, and echOutbound as an echSockopt
# dialling through the ECH outbound's tag -- which the preflight adds to the
# config beside the node, exactly as PattN and PattNG do. Without that the
# core never looks at the outbound: dialerProxy is only a tag at load time.
ech_node = Node("vless", "00000000-0000-0000-0000-000000000000", "1.2.3.4", "443", {
    "encryption": "none", "security": "tls", "type": "ws", "host": "e.example",
    "sni": "e.example", "ech": "x+https://1.1.1.1/dns-query",
    "echOutbound": '{"tag": "ech-out", "protocol": "freedom"}',
})
tls_settings = ech_node.to_outbound("t")["streamSettings"]["tlsSettings"]
check(tls_settings.get("echConfigList") == "x+https://1.1.1.1/dns-query",
      "outbound: ech becomes tlsSettings.echConfigList, as written")
check(tls_settings.get("echSockopt") == {"dialerProxy": "ech-out"},
      "outbound: echOutbound becomes an echSockopt dialling through its tag")
check(ech_node.ech_outbound() == {"tag": "ech-out", "protocol": "freedom"},
      "outbound: ech_outbound parses the outbound the ECH query is sent through")
check(parse_line(link(**BASE)).ech_outbound() is None,
      "outbound: a node without an echOutbound has no ECH outbound")

preflight_config = healthcheck._preflight_config(ech_node)
check([o.get("tag") for o in preflight_config["outbounds"]] == ["block", "out-0", "ech-out"],
      "healthcheck: the preflight adds the ECH outbound beside the node, as the clients do")
check(preflight_config["outbounds"][-1] == {"tag": "ech-out", "protocol": "freedom"},
      "healthcheck: the ECH outbound is added exactly as written")
check([o.get("tag") for o in healthcheck._preflight_config(parse_line(link(**BASE)))["outbounds"]]
      == ["block", "out-0"],
      "healthcheck: a probe without an echOutbound gets no extra outbound")
check([o.get("tag") for o in healthcheck._build_config(
          [ech_node], healthcheck._placeholder_ports(1))["outbounds"]] == ["block", "out-0"],
      "healthcheck: the health check's own config builder never adds an ECH outbound")


# Endpoint selection and the pass/fail decision inside _probe. Both are stubbed
# at the connection layer so the suite stays offline.
class _FakeResponse:
    def __init__(self, status):
        self.status = status

    def read(self):
        return b""


class _FakeHTTPS:
    scripted: dict = {}

    def __init__(self, host, port=None, timeout=None):
        self._target = host

    def set_tunnel(self, host, port):
        self._target = host

    def request(self, method, path, headers=None):
        pass

    def getresponse(self):
        value = _FakeHTTPS.scripted.get(self._target, 599)
        if isinstance(value, Exception):
            raise value
        return _FakeResponse(value)

    def close(self):
        pass


CF, GS, AP = healthcheck.TEST_ENDPOINTS
real_https = healthcheck.http.client.HTTPSConnection
try:
    healthcheck.http.client.HTTPSConnection = _FakeHTTPS
    _FakeHTTPS.scripted = {
        CF.host: 204,                        # healthy
        GS.host: 500,                        # answers, but wrongly
        AP.host: OSError("refused"),         # unreachable
    }
    with contextlib.redirect_stdout(io.StringIO()):
        usable = healthcheck.usable_endpoints()
    check([e.host for e in usable] == [CF.host],
          "endpoints: only endpoints that actually answer correctly are used")

    # A node's verdict follows the endpoint's own expected status, not a
    # hardcoded 204 -- captive.apple.com answers 200 and that must count.
    _FakeHTTPS.scripted = {CF.host: 204}
    check(healthcheck._probe(1, CF)[0], "probe: the expected status passes")
    _FakeHTTPS.scripted = {CF.host: 200}
    check(not healthcheck._probe(1, CF)[0], "probe: a 200 does not pass a 204 endpoint")
    _FakeHTTPS.scripted = {AP.host: 200}
    check(healthcheck._probe(1, AP)[0], "probe: a 200 passes the endpoint that expects 200")
    _FakeHTTPS.scripted = {AP.host: 204}
    check(not healthcheck._probe(1, AP)[0], "probe: a 204 does not pass a 200 endpoint")
    _FakeHTTPS.scripted = {CF.host: OSError("boom")}
    ok, elapsed = healthcheck._probe(1, CF)
    check(not ok and elapsed >= 0, "probe: a connection failure is a clean failure, not a crash")
finally:
    healthcheck.http.client.HTTPSConnection = real_https
    _FakeHTTPS.scripted = {}

# With every endpoint unusable there is nothing to measure, and the run must
# say so rather than reporting that every node is dead.
real_usable = healthcheck.usable_endpoints
try:
    healthcheck.usable_endpoints = lambda: []
    raised = False
    try:
        healthcheck.check("xray", [n for n in one(**BASE)], {}, rounds=1)
    except healthcheck.HealthCheckError:
        raised = True
    check(raised, "endpoints: no reachable endpoint aborts rather than failing every node")
finally:
    healthcheck.usable_endpoints = real_usable

# The cap on how many nodes reach the health check. Rule 9 converts rather than
# duplicates now, so there are no mirrors to rank below originals and no second
# port to balance against -- the cap is a plain trim that keeps input order.
pool = []
for i in range(60):
    pool += one(**{**BASE, "host": f"t{i}.example"})
check(len(pool) == 60, "cap: test pool built")
check(all(n.port == "443" for n in pool), "cap: every node in the pool is on 443")

check(build.cap_nodes(pool, 500) is pool, "cap: a pool under the limit is returned untouched")
check(len(build.cap_nodes(pool, 60)) == 60, "cap: a pool exactly at the limit is kept whole")

trimmed = build.cap_nodes(pool, 40)
check(len(trimmed) == 40, "cap: an oversized pool is trimmed to exactly the limit")
check(trimmed == pool[:40], "cap: the trim keeps input order, so it is deterministic")
check(len({n.identity() for n in trimmed}) == 40, "cap: trimming introduces no duplicates")

for limit in (1, 7, 39, 59):
    check(len(build.cap_nodes(pool, limit)) == limit,
          f"cap: limit {limit} yields exactly {limit} nodes")
check(build.cap_nodes([], 10) == [], "cap: an empty pool is handled")

# --- fetch retry coverage --------------------------------------------------
# A truncated response raises IncompleteRead, which is an HTTPException and NOT
# an OSError, so a handler catching only OSError silently skips the retry and
# lets the error escape as a traceback.



for exc in (
    http.client.IncompleteRead,
    http.client.BadStatusLine,
    http.client.RemoteDisconnected,
    urllib.error.URLError,
    urllib.error.HTTPError,
    TimeoutError,
    ConnectionResetError,
):
    check(
        issubclass(exc, build.RETRYABLE_FETCH_ERRORS),
        f"fetch: {exc.__name__} is retried rather than fatal",
    )


def _http_error(code: int):
    return urllib.error.HTTPError("http://x", code, "msg", {}, None)


# A wrong URL answers the same way every time; retrying it only delays the
# other sources. 408 and 429 explicitly mean "try again", and 5xx is transient.
for code in (400, 401, 403, 404, 410):
    check(build.is_permanent_http_error(_http_error(code)), f"fetch: HTTP {code} is not retried")
for code in (408, 429, 500, 502, 503):
    check(not build.is_permanent_http_error(_http_error(code)), f"fetch: HTTP {code} is retried")
check(not build.is_permanent_http_error(TimeoutError()), "fetch: a timeout is retried")


# --- sources ----------------------------------------------------------------

check(build.decode_if_base64("vless://x\ntrojan://y") == "vless://x\ntrojan://y",
      "sources: plain text passes through untouched")
encoded = base64.b64encode(b"vless://a\nvless://b").decode()
check(build.decode_if_base64(encoded) == "vless://a\nvless://b",
      "sources: a base64 list is decoded")
check(build.decode_if_base64(encoded.rstrip("=")) == "vless://a\nvless://b",
      "sources: base64 missing its padding still decodes")
check(build.decode_if_base64("not base64 and no scheme") == "not base64 and no scheme",
      "sources: undecodable text is left alone rather than mangled")
check(build.decode_if_base64("") == "", "sources: empty body is handled")
# A list may open with a long comment header, so the plain-text check has to
# scan the whole body rather than a prefix.
long_header = "# " + ("x" * 8000) + "\nvless://uid@1.2.3.4:443?type=ws&host=a.example\n"
check(build.decode_if_base64(long_header) == long_header,
      "sources: plain text is recognised even behind a long header")

saved = {k: os.environ.get(k) for k in ("SOURCE_URLS", "SOURCE_URL")}
try:
    os.environ.pop("SOURCE_URL", None)
    os.environ["SOURCE_URLS"] = "http://a/1.txt, http://b/2.txt"
    check(build.load_sources() == ["http://a/1.txt", "http://b/2.txt"],
          "sources: SOURCE_URLS accepts a comma-separated list")
    os.environ["SOURCE_URLS"] = "http://a/1.txt\nhttp://b/2.txt"
    check(build.load_sources() == ["http://a/1.txt", "http://b/2.txt"],
          "sources: SOURCE_URLS accepts newline separation")
    os.environ["SOURCE_URLS"] = "http://a/1.txt,http://a/1.txt,http://b/2.txt"
    check(build.load_sources() == ["http://a/1.txt", "http://b/2.txt"],
          "sources: a URL listed twice is fetched once, order preserved")
    # Isolates the per-line BOM strip: this path never goes through the
    # utf-8-sig file read, so only _clean can be cleaning it up.
    os.environ["SOURCE_URLS"] = "﻿http://a/1.txt"
    check(build.load_sources() == ["http://a/1.txt"],
          "sources: a stray BOM is stripped even outside the sources file")
    os.environ.pop("SOURCE_URLS")
    os.environ["SOURCE_URL"] = "http://only/1.txt"
    check(build.load_sources() == ["http://only/1.txt"],
          "sources: the older SOURCE_URL still works")
    os.environ.pop("SOURCE_URL")
    # Point at a throwaway file with distinctive URLs. Reading the real
    # sources.txt could not prove anything: it currently holds the same URL as
    # DEFAULT_SOURCES, so ignoring the file entirely would look identical.
    scratch = tempfile.mkdtemp(prefix="free-configs-sources-")
    fake = os.path.join(scratch, "sources.txt")
    with open(fake, "w", encoding="utf-8") as handle:
        handle.write(
            "# a comment\n"
            "\n"
            "https://example.invalid/one.txt\n"
            "   https://example.invalid/two.txt   \n"
            "   # an indented comment\n"
        )
    # Notepad writes UTF-8 with a BOM by default, and an unstripped BOM ends up
    # glued to the first URL, making it unusable.
    bom_file = os.path.join(scratch, "sources-bom.txt")
    with open(bom_file, "w", encoding="utf-8-sig") as handle:
        handle.write("# comment\nhttps://example.invalid/bom.txt\n")

    real_sources_file = build.SOURCES_FILE
    try:
        build.SOURCES_FILE = fake
        check(
            build.load_sources()
            == ["https://example.invalid/one.txt", "https://example.invalid/two.txt"],
            "sources: sources.txt is read, with comments and blank lines skipped",
        )
        build.SOURCES_FILE = bom_file
        check(
            build.load_sources() == ["https://example.invalid/bom.txt"],
            "sources: a byte-order mark does not corrupt the first URL",
        )
    finally:
        build.SOURCES_FILE = real_sources_file
        shutil.rmtree(scratch, ignore_errors=True)

    shipped = build.load_sources()
    check(
        bool(shipped) and all(u.startswith("http") for u in shipped),
        "sources: the repository's own sources.txt yields usable URLs",
    )
finally:
    for key, value in saved.items():
        os.environ.pop(key, None)
        if value is not None:
            os.environ[key] = value

# --- refusing to publish rubbish -------------------------------------------
# A source can return HTTP 200 and still be useless (an error page, or a
# changed format). build.py must fail and leave the previous configs.txt alone
# rather than publishing an empty subscription. Served from loopback so the
# test stays offline.



SERVERS: list[socket.socket] = []


def serve(body: bytes, status: str = "200 OK") -> str:
    """Serve one canned response on a loopback port; return its URL."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    sock.settimeout(30)
    SERVERS.append(sock)
    head = (
        f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()

    def loop() -> None:
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(4096)
                    conn.sendall(head + body)
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    return f"http://127.0.0.1:{sock.getsockname()[1]}/list.txt"


def run_build(source_urls: str, **extra_env) -> tuple[subprocess.CompletedProcess, bool, str]:
    """Run build.py against the given sources; report whether a pre-existing
    configs.txt survived, and its final contents."""
    staging = tempfile.mkdtemp(prefix="free-configs-test-")
    sentinel = "#header\nvless://PREEXISTING\n"
    with open(os.path.join(staging, "configs.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(sentinel)
    environment = dict(os.environ)
    environment.pop("SOURCE_URL", None)
    environment.update(
        SOURCE_URLS=source_urls,
        OUTPUT_DIR=staging,
        SKIP_HEALTHCHECK="1",
        PYTHONIOENCODING="utf-8",
        **extra_env,
    )
    completed = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "build.py")],
        capture_output=True,
        text=True,
        env=environment,
        timeout=180,
    )
    with open(os.path.join(staging, "configs.txt"), encoding="utf-8") as fh:
        produced = fh.read()
    shutil.rmtree(staging, ignore_errors=True)
    return completed, produced == sentinel, produced


GOOD_BODY = (
    b"vless://22222222-2222-2222-2222-222222222222@9.9.9.9:2053"
    b"?security=tls&type=ws&host=live.example&path=/#ok\n"
)

# A source can return HTTP 200 and still be useless.
completed, untouched, _ = run_build(serve(b"<html><body>404 Not Found</body></html>"))
check(completed.returncode != 0, "build: an unusable source fails the run")
check(untouched, "build: an unusable source leaves the previous configs.txt intact")
check("Traceback" not in completed.stderr, "build: an unusable source reports, not crashes")
# The message has to name the source as the problem. Reaching the generic
# "not enough healthy nodes" path instead would send someone hunting for dead
# proxies when the real fault is upstream returning something unusable.
check(
    "no usable configs parsed" in completed.stderr,
    "build: an unusable source is diagnosed as a source problem",
)

# One dead source must not sink the others.
completed, _, produced = run_build(
    serve(GOOD_BODY) + "," + serve(b"gone", status="404 Not Found")
)
check(completed.returncode == 0, "sources: a dead source does not fail the build")
check("live.example" in produced, "sources: the surviving source still publishes")
check("unreachable source" in completed.stdout, "sources: the dead source is reported")

# finalise has to be wired into build.py, not merely implemented: the deferred
# parameters and the output endpoint reach configs.txt only if the build runs
# it after the health check.
completed, _, produced = run_build(serve(GOOD_BODY))
emitted = [l for l in produced.splitlines() if l and not l.startswith("#")]
check(completed.returncode == 0 and len(emitted) == len(SHIPPED_VARIANTS),
      "finalise: the build publishes the one node it was given, once per shipped variant")
check(all(
    (node.address, node.port, node.security) == (variant.ip, variant.port, variant.security)
    and all(node.get(key) == value for key, value in variant.params.items())
    for node, variant in zip((parse_line(line) for line in emitted), SHIPPED_VARIANTS)
), "finalise: each published line carries its own shipped variant, in order")
check(all(
    named(parse_line(line).tag, f"{variant.prefix_name} ok" if variant.prefix_name else "ok")
    for line, variant in zip(emitted, SHIPPED_VARIANTS)
), "finalise: each published line is named with its own shipped variant's prefix_name")
published = parse_line(emitted[0])
# Byte-exact: each shipped parameter appears in its line exactly as written in
# VARIANTS_ENCODED -- whatever it is, empty or not.
shipped_encoded = [dict(zip(transform.Variant._fields, e)) for e in SHIPPED_VARIANTS_ENCODED]
check(all(
    f"&{key}={encoded[field]}" in line
    for line, encoded in zip(emitted, shipped_encoded)
    for field, key in zip(transform.PARAM_FIELDS, transform.VARIANT_KEYS)
    if encoded[field]
), "finalise: every shipped parameter is byte-exact in configs.txt")

# A URL with no scheme is the likeliest typo in a hand-edited sources.txt.
# urllib raises ValueError for it, which is not a URLError, so left unhandled
# it would abort the whole build -- healthy sources included -- with a
# traceback rather than naming the bad line.
completed, _, produced = run_build("raw.example.com/no-scheme.txt," + serve(GOOD_BODY))
check(completed.returncode == 0, "sources: a URL with no scheme does not sink the build")
check("live.example" in produced, "sources: the valid source still publishes alongside a typo")
check("Traceback" not in completed.stderr, "sources: a malformed URL reports, not crashes")

# Duplicate detection compares what a node IS, not how it is written: the
# #comment is a display name and query-parameter order carries no meaning, so
# neither may make two copies of one node look distinct. The comment on the
# surviving copy still has to reach configs.txt.
UID = "44444444-4444-4444-4444-444444444444"
SAME = (
    f"vless://{UID}@9.9.9.9:2053?security=tls&type=ws&host=live.example&path=/#FIRST NAME\n"
    # identical node, different display name
    f"vless://{UID}@9.9.9.9:2053?security=tls&type=ws&host=live.example&path=/#second name\n"
    # identical node, query parameters in a different order
    f"vless://{UID}@9.9.9.9:2053?path=/&host=live.example&type=ws&security=tls#third name\n"
    # identical node again, both differences at once
    f"vless://{UID}@9.9.9.9:2053?type=ws&security=tls&path=/&host=live.example#fourth\n"
).encode()

completed, _, produced = run_build(serve(SAME))
emitted = [l for l in produced.splitlines() if l and not l.startswith("#")]
check(completed.returncode == 0, "dedup: the four-copy list builds")
check("1 distinct configs parsed" in completed.stdout,
      "dedup: four spellings of one node collapse to one")
check("3 duplicates dropped" in completed.stdout, "dedup: the other three are counted as repeats")
check(len(emitted) == len(SHIPPED_VARIANTS),
      "dedup: four spellings of one node yield one published node per variant")
# Names are percent-encoded on the wire, so decode before comparing.
names = [parse_line(l).tag for l in emitted]
check(all(named(n, f"{v.prefix_name} FIRST NAME" if v.prefix_name else "FIRST NAME")
          for n, v in zip(names, SHIPPED_VARIANTS)),
      "dedup: the surviving copy keeps its source comment in the published name")

# Order-insensitivity at the identity level, independent of the build.
a = parse_line(f"vless://{UID}@9.9.9.9:443?security=tls&type=ws&host=x.example#one")
b = parse_line(f"vless://{UID}@9.9.9.9:443?host=x.example&type=ws&security=tls#two")
check(a.identity() == b.identity(),
      "dedup: field order does not change a node's identity")
c = parse_line(f"vless://{UID}@9.9.9.9:443?security=tls&type=ws&host=OTHER.example#one")
check(a.identity() != c.identity(),
      "dedup: a genuinely different node keeps a different identity")

# The cap has to be wired into the build, not just implemented. Six distinct
# nodes become twelve after rule 9; a cap of 4 must leave exactly 4.
SIX = "".join(
    f"vless://55555555-5555-5555-5555-55555555555{i}@9.9.9.9:2053"
    f"?security=tls&type=ws&host=c{i}.example&path=/#n{i}\n"
    for i in range(6)
).encode()

completed, _, produced = run_build(serve(SIX), MAX_NODES_TO_TEST="4")
capped = [l for l in produced.splitlines() if l and not l.startswith("#")]
check(completed.returncode == 0, "cap: a capped build succeeds")
check(len(capped) == 4 * len(SHIPPED_VARIANTS),
      "cap: the build tests only the capped number of nodes")
check("capped to 4 nodes" in completed.stdout, "cap: the build reports that it capped")
check("2 dropped" in completed.stdout, "cap: the build reports how many it dropped")
check([parse_line(l).port for l in capped] == [v.port for v in SHIPPED_VARIANTS] * 4,
      "cap: everything published is on its variant's port")

# Under the cap, nothing is dropped and nothing is reported.
completed, _, produced = run_build(serve(SIX), MAX_NODES_TO_TEST="500")
check(len([l for l in produced.splitlines() if l and not l.startswith("#")])
      == 6 * len(SHIPPED_VARIANTS),
      "cap: a pool under the limit is published whole")
check("capped to" not in completed.stdout, "cap: no cap message when the limit is not reached")

# Every source dead is a different matter.
completed, untouched, _ = run_build(
    serve(b"gone", status="404 Not Found") + "," + serve(b"gone", status="410 Gone")
)
check(completed.returncode != 0, "sources: all sources dead fails the build")
check(untouched, "sources: all sources dead leaves the previous configs.txt intact")

# A base64 source is decoded, and duplicate lines across sources collapse.
completed, _, produced = run_build(
    serve(GOOD_BODY) + "," + serve(base64.b64encode(GOOD_BODY))
)
check(completed.returncode == 0, "sources: a base64 source is accepted")
# One input node listed by both sources is one node, published once per
# shipped variant -- not twice per variant.
emitted = [l for l in produced.splitlines() if l and not l.startswith("#")]
check(len(emitted) == len(SHIPPED_VARIANTS), "sources: the same node from two sources is deduped")
# Node-level dedup would collapse these anyway, so assert the line-level pass
# actually ran -- it is what keeps a large overlapping source from being
# parsed twice.
check(
    "1 distinct configs parsed" in completed.stdout
    and "1 duplicates dropped" in completed.stdout,
    "sources: a repeated node is dropped once, not parsed twice",
)
check(parse_line(emitted[0]).port == SHIPPED_VARIANTS[0].port,
      "sources: the surviving node is published on its variant's port")

for sock in SERVERS:
    sock.close()

# Locating the core, reading the previous file, and tailing a log. Small, but
# each has a failure path a user actually meets: a wrong XRAY_BIN, a missing
# configs.txt on the very first run, and a batch that died before logging.

_saved_xray_bin = os.environ.get("XRAY_BIN")
_scratch = tempfile.mkdtemp(prefix="free-configs-misc-")
try:
    real_binary = os.path.join(_scratch, "xray-stub")
    with open(real_binary, "w", encoding="utf-8") as handle:
        handle.write("stub")

    os.environ["XRAY_BIN"] = real_binary
    check(build.locate_xray() == real_binary, "locate: XRAY_BIN is used when it exists")

    os.environ["XRAY_BIN"] = os.path.join(_scratch, "not-here")
    try:
        build.locate_xray()
        check(False, "locate: a missing XRAY_BIN is rejected")
    except SystemExit as error:
        check("not-here" in str(error),
              "locate: a missing XRAY_BIN is rejected, naming the path")

    # Nothing on PATH and nothing in bin/: the message has to say what is
    # needed, since this is what a broken install step looks like in CI.
    os.environ.pop("XRAY_BIN", None)
    _real_which, _real_root = shutil.which, build.REPO_ROOT
    try:
        build.shutil.which = lambda name: None
        build.REPO_ROOT = _scratch
        try:
            build.locate_xray()
            check(False, "locate: absent core is reported")
        except SystemExit as error:
            check(build.MIN_XRAY_VERSION in str(error) and "XRAY_BIN" in str(error),
                  "locate: absent core names both the fix and the version floor")
    finally:
        build.shutil.which = _real_which
        build.REPO_ROOT = _real_root

    # existing_links: what the publish step compares against.
    missing = os.path.join(_scratch, "nope.txt")
    check(build.existing_links(missing) == [],
          "publish: a missing previous file reads as no links, not an error")
    header_only = os.path.join(_scratch, "header.txt")
    with open(header_only, "w", encoding="utf-8") as handle:
        handle.write("#profile-title: x\n# a comment\n\n")
    check(build.existing_links(header_only) == [],
          "publish: a file of only comments reads as no links")
    with_links = os.path.join(_scratch, "some.txt")
    with open(with_links, "w", encoding="utf-8") as handle:
        handle.write("#header\nvless://a\n\nvless://b\n")
    check(build.existing_links(with_links) == ["vless://a", "vless://b"],
          "publish: links are read and comments and blanks skipped")

    # _log_tail: only ever used when something already went wrong.
    check("(no log)" in healthcheck._log_tail(os.path.join(_scratch, "absent.log")),
          "log tail: a missing log does not raise while reporting a failure")
    log_file = os.path.join(_scratch, "x.log")
    with open(log_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(f"line {i}" for i in range(20)) + "\n")
    tail = healthcheck._log_tail(log_file, lines=3)
    check(tail.count("\n") == 2 and "line 19" in tail and "line 16" not in tail,
          "log tail: the last lines are returned, not the first")
finally:
    shutil.rmtree(_scratch, ignore_errors=True)
    os.environ.pop("XRAY_BIN", None)
    if _saved_xray_bin is not None:
        os.environ["XRAY_BIN"] = _saved_xray_bin

# --- report ----------------------------------------------------------------

print(f"{PASSED} checks passed, {len(FAILURES)} failed")
for failure in FAILURES:
    print(f"  FAIL: {failure}")
raise SystemExit(1 if FAILURES else 0)
