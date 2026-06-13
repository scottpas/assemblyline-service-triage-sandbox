from typing import Any, Optional

_PROTO_PRIORITY: dict[str, int] = {"dns": 0, "http": 1, "http2": 1, "tls": 2}


def _split_addr(addr: str) -> tuple[str, int]:
    """Parse 'ip:port' or '[ipv6]:port' into (ip_str, port_int)."""
    if addr.startswith("["):
        ip = addr[1 : addr.index("]")]
        port = int(addr[addr.index("]") + 2 :])
    else:
        ip, port_str = addr.rsplit(":", 1)
        port = int(port_str)
    return ip, port


def _parse_http_headers(headers: Any) -> dict[str, str]:
    """Parse Triage HTTP headers (list of 'name: value' strings or dicts) into a dict."""
    result: dict[str, str] = {}
    for h in headers or []:
        if isinstance(h, dict):
            result[h.get("name", "")] = h.get("value", "")
        elif isinstance(h, str):
            name, _, value = h.partition(": ")
            if name:
                result[name] = value
    return result


def _get_connection_type(protocols: list[str]) -> Optional[str]:
    """Return AL connection_type for a Triage flow. Priority: dns > http/http2 > tls."""
    best_rank: Optional[int] = None
    best: Optional[str] = None
    for p in protocols:
        rank = _PROTO_PRIORITY.get(p)
        if rank is not None and (best_rank is None or rank < best_rank):
            best_rank = rank
            best = "http" if p in ("http", "http2") else p
    return best
