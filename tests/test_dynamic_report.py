"""
Unit tests for triage_sandbox.report.DynamicReport and its private mapping methods.

Each DynamicReport is exercised via construction: __post_init__ runs all
the private __add_* methods automatically.

OntologyResults accessors used:
  - ontology.get_sandboxes()          -> list[Sandbox]
  - ontology.get_processes()          -> list[Process]
  - ontology.get_network_connections() -> list[NetworkConnection]
  - ontology.get_signatures()         -> list[Signature]
"""

from datetime import datetime
from typing import Any

from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults

from triage_sandbox.network import _get_connection_type
from triage_sandbox.report import DynamicReport

# ---------------------------------------------------------------------------
# Construction helper
# ---------------------------------------------------------------------------


def make_report(**over):
    base: dict[str, Any] = dict(
        ontology=OntologyResults(service_name="Triage"),
        task_id="behavioral1",
        version="1.0",
        sample={"id": "sample123"},
        task={},
        analysis={
            "submitted": "2024-02-02T23:56:27Z",
            "reported": "2024-02-02T23:59:09Z",
            "resource": "win7",
        },
        signatures=[],
        network={},
        processes=None,
        extracted=None,
    )
    base.update(over)
    return DynamicReport(**base)


# ---------------------------------------------------------------------------
# 1. __post_init__ — session, times, malware_config
# ---------------------------------------------------------------------------


def test_post_init_sets_times_and_session():
    dr = make_report()

    assert dr.session == "sample123/behavioral1"

    assert isinstance(dr.start_time, datetime)
    assert isinstance(dr.end_time, datetime)
    assert dr.start_time == datetime(2024, 2, 2, 23, 56, 27)
    assert dr.end_time == datetime(2024, 2, 2, 23, 59, 9)

    assert dr.malware_config == []


# ---------------------------------------------------------------------------
# 2. __add_sandbox
# ---------------------------------------------------------------------------


def test_add_sandbox_recorded():
    dr = make_report()
    sandboxes = dr.ontology.get_sandboxes()

    assert len(sandboxes) == 1
    sb = sandboxes[0]
    prim = sb.as_primitives()
    assert prim["sandbox_name"] == "Triage"
    assert prim["sandbox_version"] == "1.0"


# ---------------------------------------------------------------------------
# 3. __add_processes
# ---------------------------------------------------------------------------


def test_add_processes_builds_id_pid_map():
    procs_input = [
        {"procid": 1, "pid": 100, "ppid": 4, "image": "a.exe", "cmd": "a", "started": 1},
        {"procid": 2, "pid": 200, "ppid": 100, "image": "b.exe", "cmd": "b", "started": 2, "terminated": 5},
    ]
    dr = make_report(processes=procs_input)

    assert dr._id_pid_map == {1: 100, 2: 200}

    procs = dr.ontology.get_processes()
    assert len(procs) == 2

    # procid 1 has no 'terminated' -> end_time should be the sentinel value
    proc_a = next(p for p in procs if p.pid == 100)
    assert proc_a.end_time == "9999-12-31 23:59:59.999999"


# ---------------------------------------------------------------------------
# 4. __add_network — IPv4 flow
# ---------------------------------------------------------------------------


def test_add_network_ipv4_flow():
    network = {"flows": [{"id": 1, "dst": "8.8.8.8:53", "src": "10.0.0.5:1234", "proto": "udp", "first_seen": 1}]}
    dr = make_report(network=network)

    assert 1 in dr.flow_dict
    flow = dr.flow_dict[1]
    assert flow["destination_ip"] == "8.8.8.8"
    assert flow["destination_port"] == 53
    assert flow["source_ip"] == "10.0.0.5"
    assert flow["source_port"] == 1234
    assert flow["direction"] == "outbound"

    conns = dr.ontology.get_network_connections()
    assert len(conns) == 1


# ---------------------------------------------------------------------------
# 5. __add_network — IPv6 flow
# ---------------------------------------------------------------------------


def test_add_network_ipv6_flow():
    """Test that __add_network correctly parses IPv6 addresses in flow 'dst' and 'src' fields."""
    network = {"flows": [{"id": 1, "dst": "[2001:db8::1]:443", "src": "10.0.0.5:1234", "proto": "tcp"}]}
    dr = make_report(network=network)
    assert dr.flow_dict[1]["destination_ip"] == "2001:db8::1"
    assert dr.flow_dict[1]["destination_port"] == 443


# ---------------------------------------------------------------------------
# 6. __add_signatures — label used as name
# ---------------------------------------------------------------------------


def test_add_signatures_label_used_as_name():
    dr = make_report(signatures=[{"label": "my_label", "score": 3}])
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert sigs[0].name == "my_label"


# ---------------------------------------------------------------------------
# 7. __add_signatures — name derived from sig["name"]
# ---------------------------------------------------------------------------


def test_add_signatures_name_derived():
    dr = make_report(signatures=[{"name": "Suspicious behavior: use of WriteProcessMemory", "score": 3}])
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert sigs[0].name == "writeprocessmemory"


# ---------------------------------------------------------------------------
# 8. __add_signatures — score multiplied by SCORE_MULTIPLY_FACTOR
# ---------------------------------------------------------------------------


def test_add_signatures_score_multiplied():
    dr = make_report(signatures=[{"label": "s", "score": 7}])
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert sigs[0].score == 700


def test_add_signatures_zero_score_when_missing():
    dr = make_report(signatures=[{"label": "s"}])
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert sigs[0].score == 0


# ---------------------------------------------------------------------------
# 9. __add_signatures — family extracted from tags
# ---------------------------------------------------------------------------


def test_add_signatures_family_from_tags():
    dr = make_report(signatures=[{"label": "s", "score": 3, "tags": ["family:emotet"]}])
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    prim = sigs[0].as_primitives()
    assert prim["malware_families"] == ["EMOTET"]


# ---------------------------------------------------------------------------
# 10. __add_signatures — deduplication by tag
# ---------------------------------------------------------------------------


def test_add_signatures_dedup():
    dr = make_report(signatures=[{"label": "dup", "score": 3}, {"label": "dup", "score": 6}])
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1


# ---------------------------------------------------------------------------
# 11. __add_extracted — config adds malware_config entry + rule signature
# ---------------------------------------------------------------------------


def test_add_extracted_config_and_rule_signature():
    extracted = [{"config": {"family": "emotet", "c2": ["http://x.io"], "rule": "EmotetRule"}}]
    dr = make_report(extracted=extracted)

    assert len(dr.malware_config) == 1

    sigs = dr.ontology.get_signatures()
    rule_sigs = [s for s in sigs if s.name == "EmotetRule"]
    assert len(rule_sigs) == 1


# ---------------------------------------------------------------------------
# 12. __add_extracted — ransom config
# ---------------------------------------------------------------------------


def test_add_extracted_ransom_note():
    extracted = [{"ransom_note": {"note": "n", "family": "conti", "wallets": ["w"]}}]
    dr = make_report(extracted=extracted)
    assert len(dr.malware_config) == 1
    prim = dr.malware_config[0].as_primitives(strip_null=True)
    assert prim["family"] == ["CONTI"]


def test_add_extracted_ransom_note_no_family():
    """Real Triage ransom_note objects often omit 'family'; should default to UNKNOWN."""
    extracted = [{"ransom_note": {"note": "pay up", "wallets": ["w1"], "emails": ["x@evil.com"]}}]
    dr = make_report(extracted=extracted)
    assert len(dr.malware_config) == 1
    prim = dr.malware_config[0].as_primitives(strip_null=True)
    assert prim["family"] == ["UNKNOWN"]
    assert prim.get("category") == ["ransomware"]


# ---------------------------------------------------------------------------
# 13. __add_extracted — credentials config
# ---------------------------------------------------------------------------


def test_add_extracted_credentials():
    extracted = [{"credentials": {"protocol": "ftp", "username": "u", "password": "p", "host": "h", "port": 21}}]
    dr = make_report(extracted=extracted)

    assert len(dr.malware_config) == 1
    prim = dr.malware_config[0].as_primitives(strip_null=True)
    assert prim["family"] == ["UNKNOWN"]


# ---------------------------------------------------------------------------
# _get_connection_type
# ---------------------------------------------------------------------------


def test_connection_type_dns():
    assert _get_connection_type(["dns"]) == "dns"


def test_connection_type_http_wins_over_tls():
    assert _get_connection_type(["tls", "http"]) == "http"


def test_connection_type_http2_normalizes_to_http():
    assert _get_connection_type(["tls", "http2"]) == "http"


def test_connection_type_tls_only():
    assert _get_connection_type(["tls"]) == "tls"


def test_connection_type_empty_returns_none():
    assert _get_connection_type([]) is None


def test_network_flow_no_connection_type_without_details():
    """AL ODM only allows connection_type with matching details; flows without request details have none."""
    network = {"flows": [{"id": 1, "dst": "8.8.8.8:53", "src": "10.0.0.1:5000", "proto": "udp", "protocols": ["dns"]}]}
    dr = make_report(network=network)
    conns = dr.ontology.get_network_connections()
    assert conns[0].as_primitives().get("connection_type") is None


# ---------------------------------------------------------------------------
# flow.domain + TLS fingerprints → network_tags
# ---------------------------------------------------------------------------


def test_flow_domain_added_to_network_tags():
    network = {
        "flows": [{"id": 1, "dst": "1.2.3.4:443", "src": "10.0.0.1:5000", "proto": "tcp", "domain": "evil.example.com"}]
    }
    dr = make_report(network=network)
    assert ("network.dynamic.domain", "evil.example.com") in dr.network_tags


def test_flow_domain_ip_tagged_as_network_dynamic_ip():
    # Triage sets flow.domain to the raw destination IP when no hostname is
    # resolved. AL rejects IP values in network.dynamic.domain, so they must
    # be routed to network.dynamic.ip instead.
    network = {
        "flows": [
            {"id": 1, "dst": "5.180.253.105:80", "src": "10.0.0.1:5000", "proto": "tcp", "domain": "5.180.253.105"}
        ]
    }
    dr = make_report(network=network)
    assert ("network.dynamic.ip", "5.180.253.105") in dr.network_tags
    assert ("network.dynamic.domain", "5.180.253.105") not in dr.network_tags


def test_tls_fingerprints_added_to_network_tags():
    network = {
        "flows": [
            {
                "id": 1,
                "dst": "1.2.3.4:443",
                "src": "10.0.0.1:5000",
                "proto": "tcp",
                "tls_ja3": "aabbcc",
                "tls_ja3s": "ddeeff",
                "tls_sni": "evil.com",
            }
        ]
    }
    dr = make_report(network=network)
    assert ("network.tls.ja3_hash", "aabbcc") in dr.network_tags
    assert ("network.tls.ja3s_hash", "ddeeff") in dr.network_tags
    assert ("network.tls.sni", "evil.com") in dr.network_tags


# ---------------------------------------------------------------------------
# HTTP and DNS request details from network.requests[]
# ---------------------------------------------------------------------------


def test_http_request_details_mapped_to_connection():
    network = {
        "flows": [{"id": 1, "dst": "1.2.3.4:80", "src": "10.0.0.1:5000", "proto": "tcp"}],
        "requests": [
            {
                "flow": 1,
                "index": 0,
                "http_request": {
                    "method": "GET",
                    "url": "http://evil.com/beacon",
                    "headers": ["Host: evil.com"],
                },
                "http_response": {
                    "status": 200,
                    "headers": ["Content-Type: text/plain"],
                },
            }
        ],
    }
    dr = make_report(network=network)
    conns = dr.ontology.get_network_connections()
    assert len(conns) == 1
    prim = conns[0].as_primitives()
    assert prim["connection_type"] == "http"
    assert prim["http_details"]["request_uri"] == "http://evil.com/beacon"
    assert prim["http_details"]["request_method"] == "GET"
    assert prim["http_details"]["request_headers"] == {"Host": "evil.com"}
    assert prim["http_details"]["response_status_code"] == 200
    assert prim["http_details"]["response_headers"] == {"Content-Type": "text/plain"}


def test_dns_request_details_mapped_to_connection():
    network = {
        "flows": [{"id": 2, "dst": "8.8.8.8:53", "src": "10.0.0.1:5000", "proto": "udp"}],
        "requests": [
            {
                "flow": 2,
                "index": 0,
                "dns_request": {
                    "domains": ["target.com"],
                    "questions": [{"name": "target.com", "type": "A"}],
                },
                "dns_response": {
                    "ip": ["9.9.9.9"],
                    "domains": ["target.com"],
                },
            }
        ],
    }
    dr = make_report(network=network)
    conns = dr.ontology.get_network_connections()
    prim = conns[0].as_primitives()
    assert prim["connection_type"] == "dns"
    assert prim["dns_details"]["domain"] == "target.com"
    assert prim["dns_details"]["resolved_ips"] == ["9.9.9.9"]
    assert prim["dns_details"]["lookup_type"] == "A"


def test_dns_request_without_response_does_not_raise():
    # DNS query with no response (resolved_ips=None) must not crash — empty list
    # was previously passed to NetworkDNS which rejected it as not "legitimate".
    network = {
        "flows": [{"id": 2, "dst": "8.8.8.8:53", "src": "10.0.0.1:5000", "proto": "udp"}],
        "requests": [
            {
                "flow": 2,
                "index": 0,
                "dns_request": {
                    "domains": ["target.com"],
                    "questions": [{"name": "target.com", "type": "A"}],
                },
            }
        ],
    }
    dr = make_report(network=network)
    conns = dr.ontology.get_network_connections()
    prim = conns[0].as_primitives()
    assert prim["connection_type"] == "dns"
    assert prim["dns_details"]["domain"] == "target.com"
    assert prim["dns_details"].get("resolved_ips") is None


def test_empty_network_initializes_empty_network_tags():
    dr = make_report(network={})
    assert dr.network_tags == []
