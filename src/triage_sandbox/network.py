from dataclasses import dataclass
from itertools import zip_longest
from typing import Any

from assemblyline.odm.models.ontology.results.network import LOOKUP_TYPES


@dataclass
class NetworkTransaction:
    flow: Any
    index: Any
    protocol: str
    occurrence: int
    request: dict[str, Any] | None
    response: dict[str, Any] | None


def _network_transactions(records: list[dict[str, Any]]) -> list[NetworkTransaction]:
    """Pair halves within a task by flow/index/protocol, retaining every occurrence.

    An omitted index represents zero in Triage's Go schema. Combined records
    are already paired; standalone halves are paired in recorded order. Extra
    halves remain separate occurrences, since identical content cannot tell a
    duplicate record from a repeated transaction. Never pair records lacking a
    flow, since there is no connection identity to establish an association.
    """
    groups: dict[tuple[Any, Any, str, Any], list[tuple[int, dict[str, Any]]]] = {}
    for position, record in enumerate(records):
        for protocol in ("dns", "http"):
            if f"{protocol}_request" not in record and f"{protocol}_response" not in record:
                continue
            flow = record.get("flow")
            key = (flow, record.get("index", 0), protocol, position if flow is None else None)
            groups.setdefault(key, []).append((position, record))

    transactions: list[tuple[int, NetworkTransaction]] = []
    for (flow, index, protocol, _), entries in groups.items():
        requests = []
        responses = []
        paired = []
        for position, record in entries:
            request = record.get(f"{protocol}_request")
            response = record.get(f"{protocol}_response")
            if request is not None and response is not None:
                paired.append((position, request, response))
            elif request is not None:
                requests.append((position, request))
            elif response is not None:
                responses.append((position, response))
        for request_half, response_half in zip_longest(requests, responses):
            positions = [half[0] for half in (request_half, response_half) if half is not None]
            paired.append(
                (min(positions), request_half[1] if request_half else None, response_half[1] if response_half else None)
            )
        for occurrence, (position, request, response) in enumerate(sorted(paired, key=lambda item: item[0])):
            transactions.append((position, NetworkTransaction(flow, index, protocol, occurrence, request, response)))
    return [transaction for _, transaction in sorted(transactions, key=lambda item: item[0])]


def _normalize_dns_lookup_type(raw: Any) -> str | None:
    """Accept a record type, optionally preceded by a recognized DNS class."""
    if not isinstance(raw, str):
        return None
    parts = raw.upper().split()
    if len(parts) == 2 and parts[0] in {"IN", "CS", "CH", "HS", "NONE", "ANY"}:
        parts = parts[1:]
    if len(parts) == 1 and parts[0] in LOOKUP_TYPES:
        return parts[0]
    return None


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
