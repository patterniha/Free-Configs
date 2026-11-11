"""Share-link model shared by the transform and health-check stages.

Parses ``vless://``, ``trojan://`` and ``vmess://`` share links into a common
:class:`Node`, re-serialises them, and renders the equivalent Xray-core
outbound JSON that the health check runs.

Parameter values live *decoded* on the node; percent-encoding happens only in
:meth:`Node.to_link` via ``quote(value, safe="")``.  That is what makes the
``fm``/``cs`` values round-trip byte-for-byte.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

SUPPORTED_SCHEMES = ("vless", "trojan", "vmess")

# Transport names that mean the same thing. The pipeline keeps whatever the
# source wrote (rule 2 accepts both "ws" and "websocket"); only the Xray
# outbound builder canonicalises.
WS_ALIASES = ("ws", "websocket")

# Query keys carrying "don't verify the certificate", in every spelling seen in
# the wild. Rule 11 strips all of them.
INSECURE_KEYS = ("allowinsecure", "allow_insecure", "insecure")


# Stable emit order, so an unchanged upstream produces a byte-identical
# configs.txt and the daily commit is a real diff rather than noise.
PARAM_ORDER = (
    "encryption",
    "security",
    "type",
    "host",
    "path",
    "serviceName",
    "mode",
    "sni",
    "alpn",
    "fp",
    "cs",
    "cp",
    "esr",
    "fm",
    "dialMode",
    "ech",
    "echOutbound",
    "flow",
    "headerType",
    "packetEncoding",
)

# vmess share links are base64'd JSON with their own key names. These map onto
# the query-parameter vocabulary used everywhere else in the pipeline.
_VMESS_PARAM_KEYS = {
    "net": "type",       # transport (vmess "type" is the *header* type)
    "tls": "security",
    "host": "host",
    "path": "path",
    "sni": "sni",
    "alpn": "alpn",
    "fp": "fp",
    "type": "headerType",
}
# Keys handled explicitly rather than through the table above.
_VMESS_RESERVED = {"add", "port", "id", "ps"} | set(_VMESS_PARAM_KEYS)


def _b64decode(payload: str) -> str:
    """Decode base64 that may be url-safe and/or missing its padding."""
    payload = payload.strip()
    payload += "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(payload.encode()).decode("utf-8", "replace")


def _split_host_port(hostport: str) -> tuple[str, str]:
    """Split ``host:port``, tolerating bracketed IPv6 and a missing port."""
    if hostport.startswith("["):
        host, _, rest = hostport.partition("]")
        return host[1:], rest.lstrip(":")
    host, sep, port = hostport.rpartition(":")
    if not sep:
        return port, ""  # no colon at all -> the whole thing was the host
    return host, port


@dataclass
class Node:
    """One proxy node, independent of which share-link dialect it came from."""

    scheme: str                                   # vless | trojan | vmess
    uid: str                                      # uuid (vless/vmess) or password (trojan)
    address: str
    port: str                                     # kept as text; "" means "no visible port"
    params: dict[str, str] = field(default_factory=dict)
    tag: str = ""                                 # display name (the #fragment)
    extra: dict = field(default_factory=dict)     # vmess-only fields to round-trip
    source: str = ""                              # original line, for diagnostics
    latency_ms: int | None = None                 # filled in by the health check

    # -- parameter access -------------------------------------------------
    # Share links are inconsistent about case ("allowInsecure" vs
    # "allowinsecure"), so every lookup is case-insensitive.

    def _find_key(self, key: str) -> str | None:
        lowered = key.lower()
        for existing in self.params:
            if existing.lower() == lowered:
                return existing
        return None

    def get(self, key: str, default: str = "") -> str:
        actual = self._find_key(key)
        return self.params[actual] if actual is not None else default

    def set(self, key: str, value: str) -> None:
        actual = self._find_key(key)
        self.params[actual if actual is not None else key] = value

    def pop(self, key: str) -> str:
        actual = self._find_key(key)
        return self.params.pop(actual) if actual is not None else ""

    def has(self, key: str) -> bool:
        return self._find_key(key) is not None

    # -- convenience views ------------------------------------------------

    @property
    def transport(self) -> str:
        return self.get("type").lower()

    @property
    def security(self) -> str:
        return self.get("security").lower()

    @property
    def host(self) -> str:
        return self.get("host")

    def copy(self) -> "Node":
        return Node(
            scheme=self.scheme,
            uid=self.uid,
            address=self.address,
            port=self.port,
            params=dict(self.params),
            tag=self.tag,
            extra=dict(self.extra),
            source=self.source,
        )

    def identity(self) -> tuple:
        """Everything that makes a node functionally distinct, ignoring its name."""
        return (
            self.scheme,
            self.uid,
            self.address,
            self.port,
            tuple(sorted((k.lower(), v) for k, v in self.params.items() if v != "")),
            tuple(sorted(self.extra.items())),
        )

    # -- serialisation ----------------------------------------------------

    def _ordered_params(self) -> list[tuple[str, str]]:
        rank = {name.lower(): i for i, name in enumerate(PARAM_ORDER)}
        items = [(k, v) for k, v in self.params.items() if v != ""]
        items.sort(key=lambda kv: (rank.get(kv[0].lower(), len(rank)), kv[0].lower()))
        return items

    def to_link(self) -> str:
        if self.scheme == "vmess":
            return self._to_vmess_link()
        query = "&".join(
            f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in self._ordered_params()
        )
        host = f"[{self.address}]" if ":" in self.address else self.address
        link = f"{self.scheme}://{quote(self.uid, safe='')}@{host}:{self.port}"
        if query:
            link += "?" + query
        if self.tag:
            link += "#" + quote(self.tag, safe="")
        return link

    def _to_vmess_link(self) -> str:
        payload = {
            "v": str(self.extra.get("v", "2")),
            "ps": self.tag,
            "add": self.address,
            "port": str(self.port),
            "id": self.uid,
            "aid": str(self.extra.get("aid", "0")),
            "scy": self.extra.get("scy", "auto") or "auto",
            "net": self.get("type"),
            "type": self.get("headerType", "none") or "none",
            "host": self.get("host"),
            "path": self.get("path"),
            "tls": self.get("security"),
            "sni": self.get("sni"),
            "alpn": self.get("alpn"),
            "fp": self.get("fp"),
        }
        blob = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return "vmess://" + base64.b64encode(blob).decode("ascii")

    # -- Xray outbound ----------------------------------------------------

    def ech_outbound(self) -> dict | None:
        """The ``echOutbound`` share-link parameter, parsed: a whole Xray
        outbound, written as JSON, that the ECH config query is sent through.

        None when the node carries none. Invalid JSON raises rather than being
        skipped -- transform._self_check validates every value this project
        publishes, so reaching here with a broken one is a bug worth seeing.
        """
        raw = self.get("echOutbound")
        return json.loads(raw) if raw else None

    def to_outbound(self, tag: str) -> dict:
        """Render this node as an Xray-core outbound object.

        Mirrors whatever the node carries, including the share-link extensions
        ``fp`` (fingerprint), ``cs`` (cipherSuites), ``cp`` (curvePreferences),
        ``esr`` (enableSessionResumption), ``fm`` (finalmask), ``dialMode`` (a
        sockopt), ``ech`` (echConfigList) and ``echOutbound`` (the echSockopt
        dialer). Which are present depends on the stage: the health check runs
        on nodes carrying none of the eight, over the core's plain TLS, and
        transform.finalise adds them to the survivors. See scripts/transform.py
        for why the pipeline is split that way.
        """
        net = self.transport
        stream: dict = {"network": "ws" if net in WS_ALIASES else net}

        if self.security == "tls":
            stream["security"] = "tls"
            tls: dict = {
                "serverName": self.get("sni") or self.host or self.address,
                "allowInsecure": False,
            }
            if self.get("fp"):
                tls["fingerprint"] = self.get("fp")
            if self.get("cs"):
                tls["cipherSuites"] = self.get("cs")
            if self.get("cp"):
                # As both clients pass it: the names split on "," and trimmed.
                tls["curvePreferences"] = [
                    name.strip() for name in self.get("cp").split(",") if name.strip()
                ]
            if self.get("esr") == "1":
                # "1" is the only value either client reads as on.
                tls["enableSessionResumption"] = True
            if self.get("alpn"):
                tls["alpn"] = [a for a in self.get("alpn").split(",") if a]
            if self.get("ech"):
                # Stored as-is by the core, which only parses it when it dials.
                tls["echConfigList"] = self.get("ech")
            ech_outbound = self.ech_outbound()
            if ech_outbound is not None:
                # What PattN and PattNG do with echOutbound: the ECH config
                # query is dialled through that outbound, found by its tag. The
                # outbound itself has to be added to the config beside this one
                # -- see healthcheck.preflight, the only place that renders it.
                tls["echSockopt"] = {"dialerProxy": ech_outbound["tag"]}
            stream["tlsSettings"] = tls
        else:
            stream["security"] = "none"

        path = self.get("path") or "/"
        if net in WS_ALIASES:
            stream["wsSettings"] = {"path": path, "host": self.host}
        elif net == "httpupgrade":
            stream["httpupgradeSettings"] = {"path": path, "host": self.host}
        elif net == "xhttp":
            xhttp = {"path": path, "host": self.host}
            if self.get("mode"):
                xhttp["mode"] = self.get("mode")
            stream["xhttpSettings"] = xhttp
        elif net == "grpc":
            stream["grpcSettings"] = {
                "serviceName": self.get("serviceName"),
                "authority": self.host,
            }

        if self.get("fm"):
            # Raises if the value is not valid JSON; build.py surfaces that as
            # a hard failure rather than emitting configs Xray would reject.
            stream["finalmask"] = json.loads(self.get("fm"))

        if self.get("dialMode"):
            # A fork-only sockopt (streamSettings.sockopt.dialMode) selecting
            # which dialing code the core runs. Passed through as-is: the core
            # accepts any string here at parse time and only rejects one it has
            # no implementation for when it dials.
            stream["sockopt"] = {"dialMode": self.get("dialMode")}

        port = int(self.port)
        if self.scheme == "vless":
            user = {"id": self.uid, "encryption": self.get("encryption") or "none"}
            if self.get("flow"):
                user["flow"] = self.get("flow")
            settings = {"vnext": [{"address": self.address, "port": port, "users": [user]}]}
        elif self.scheme == "trojan":
            settings = {
                "servers": [{"address": self.address, "port": port, "password": self.uid}]
            }
        else:  # vmess
            try:
                alter_id = int(self.extra.get("aid", 0) or 0)
            except (TypeError, ValueError):
                alter_id = 0
            user = {
                "id": self.uid,
                "alterId": alter_id,
                "security": self.extra.get("scy") or "auto",
            }
            settings = {"vnext": [{"address": self.address, "port": port, "users": [user]}]}

        return {
            "tag": tag,
            "protocol": self.scheme,
            "settings": settings,
            "streamSettings": stream,
        }


# -- parsing --------------------------------------------------------------


def parse_line(line: str) -> Node | None:
    """Parse one share link. Returns None for blanks, comments and anything
    that is not a supported scheme or does not parse."""
    line = line.strip()
    if not line or line.startswith("#") or "://" not in line:
        return None
    scheme = line.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            return _parse_vmess(line)
        if scheme in ("vless", "trojan"):
            return _parse_url_style(line, scheme)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, binascii.Error):
        return None
    return None


def _parse_url_style(line: str, scheme: str) -> Node | None:
    rest = line.split("://", 1)[1]

    tag = ""
    if "#" in rest:
        rest, tag = rest.split("#", 1)
        tag = unquote(tag)

    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)

    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
    else:
        userinfo, hostport = "", rest

    address, port = _split_host_port(hostport)
    if not address:
        return None

    params: dict[str, str] = {}
    for chunk in query.split("&"):
        if not chunk:
            continue
        key, _, value = chunk.partition("=")
        key = unquote(key)
        if key:
            params[key] = unquote(value)

    return Node(
        scheme=scheme,
        uid=unquote(userinfo),
        address=address,
        port=port,
        params=params,
        tag=tag,
        source=line,
    )


def _parse_vmess(line: str) -> Node | None:
    payload = line.split("://", 1)[1].split("#", 1)[0]
    data = json.loads(_b64decode(payload))
    if not isinstance(data, dict):
        return None

    params: dict[str, str] = {}
    for vmess_key, param_key in _VMESS_PARAM_KEYS.items():
        value = data.get(vmess_key, "")
        params[param_key] = "" if value is None else str(value)

    extra = {"v": str(data.get("v", "2")), "aid": str(data.get("aid", "0"))}
    if data.get("scy"):
        extra["scy"] = str(data["scy"])
    for key, value in data.items():
        if key not in _VMESS_RESERVED and key not in ("v", "aid", "scy") and value not in (None, ""):
            extra[key] = str(value)

    return Node(
        scheme="vmess",
        uid=str(data.get("id", "")),
        address=str(data.get("add", "")),
        port=str(data.get("port", "")),
        params=params,
        tag=str(data.get("ps", "")),
        extra=extra,
        source=line,
    )
