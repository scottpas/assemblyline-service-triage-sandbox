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

from triage_sandbox.network import _parse_http_headers
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


def test_add_processes_builds_id_objectid_map():
    procs_input = [
        {"procid": 1, "pid": 100, "ppid": 4, "image": "a.exe", "cmd": "a", "started": 1},
        {"procid": 2, "pid": 200, "ppid": 100, "image": "b.exe", "cmd": "b", "started": 2, "terminated": 5},
    ]
    dr = make_report(processes=procs_input)

    assert set(dr._id_objectid_map) == {1, 2}
    assert dr.ontology.get_process_by_objectid(dr._id_objectid_map[1]).pid == 100
    assert dr.ontology.get_process_by_objectid(dr._id_objectid_map[2]).pid == 200

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


def test_add_signatures_yara_rule_preferred_over_name():
    dr = make_report(
        signatures=[
            {
                "name": "Detects binaries (Windows and macOS) referencing many web browsers. "
                "Observed in information stealers",
                "score": 10,
                "indicators": [{"resource": "sample", "yara_rule": "INDICATOR_SUSPICIOUS_Binary_References_Browsers"}],
            }
        ]
    )
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert sigs[0].name == "INDICATOR_SUSPICIOUS_Binary_References_Browsers"
    # The verbose rule text has nowhere else to go once yara_rule is used as the name,
    # so it must be preserved as the signature's description.
    assert (
        dr.signature_descriptions["INDICATOR_SUSPICIOUS_Binary_References_Browsers"]
        == "Detects binaries (Windows and macOS) referencing many web browsers. Observed in information stealers"
    )


def test_add_signatures_yara_rule_ignored_for_non_sample_resource():
    """A behavioral signature can carry a yara_rule on a *file* indicator (resource is a
    task-relative path, not "sample") — that must not override the behavior's own name."""
    dr = make_report(
        signatures=[
            {
                "name": "Suspicious behavior: use of WriteProcessMemory",
                "score": 3,
                "indicators": [{"resource": "behavioral1/files/0x1-1.dat", "yara_rule": "r"}],
            }
        ]
    )
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert sigs[0].name == "writeprocessmemory"


def test_add_signatures_yara_rule_trusted_for_memory_dump_resource():
    """A static YARA match against a memory dump captured during execution (resource like
    '<task>/memory/<pid>-...-memory.dmp') is just as genuine as one against 'sample'."""
    dr = make_report(
        signatures=[
            {
                "name": "Detects executables containing artifacts associated with disabling Windows Defender",
                "score": 9,
                "indicators": [
                    {
                        "resource": "behavioral1/memory/3812-69-0x0000000000400000-0x0000000002985000-memory.dmp",
                        "yara_rule": "INDICATOR_SUSPICIOUS_DisableWinDefender",
                    }
                ],
            }
        ]
    )
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert sigs[0].name == "INDICATOR_SUSPICIOUS_DisableWinDefender"


def test_add_signatures_description_falls_back_to_indicator_text():
    """When a signature has no 'desc', per-indicator description/ioc text should be
    surfaced instead of leaving the signature with no description at all."""
    dr = make_report(
        signatures=[
            {
                "label": "suspicious_writeprocessmemory",
                "score": 5,
                "indicators": [
                    {"description": "PID 3396 wrote to memory of 4436", "pid": 3396, "procid_target": 84},
                    {"description": "PID 3396 wrote to memory of 4436", "pid": 3396, "procid_target": 84},
                    {"description": "PID 3260 wrote to memory of 2056", "pid": 3260, "procid_target": 101},
                ],
            }
        ]
    )
    assert dr.signature_descriptions["suspicious_writeprocessmemory"] == (
        "PID 3396 wrote to memory of 4436\nPID 3260 wrote to memory of 2056"
    )


def test_add_signatures_description_falls_back_to_indicator_ioc_with_description():
    """A single indicator's description and ioc should be combined into one line."""
    dr = make_report(
        signatures=[
            {
                "label": "modifies_service_image_registry",
                "score": 8,
                "indicators": [
                    {
                        "ioc": r"\REGISTRY\MACHINE\SYSTEM\Services\x\ImagePath = \"evil.exe\"",
                        "description": "Set value (str)",
                        "procid": 101,
                    }
                ],
            }
        ]
    )
    assert dr.signature_descriptions["modifies_service_image_registry"] == (
        'Set value (str): \\REGISTRY\\MACHINE\\SYSTEM\\Services\\x\\ImagePath = \\"evil.exe\\"'
    )


def test_add_signatures_no_description_when_indicators_have_no_text():
    """Indicators with only pid/procid (no description or ioc) leave no description."""
    dr = make_report(signatures=[{"label": "deletes_itself", "score": 7, "indicators": [{"pid": 2056}]}])
    assert "deletes_itself" not in dr.signature_descriptions


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


# ---------------------------------------------------------------------------
# 8. Signature descriptions
# ---------------------------------------------------------------------------


def test_signature_descriptions_populated_from_desc_field():
    """signatures[].desc must be captured in signature_descriptions keyed by name."""
    dr = make_report(
        signatures=[
            {
                "label": "darksiderat",
                "score": 10,
                "desc": "DarkSideRAT is a remote access trojan.",
                "tags": ["family:darksiderat"],
            },
            {
                "label": "interesting_sig",
                "score": 5,
                # No desc — must not appear in signature_descriptions
            },
        ]
    )
    assert "darksiderat" in dr.signature_descriptions
    assert dr.signature_descriptions["darksiderat"] == "DarkSideRAT is a remote access trojan."
    assert "interesting_sig" not in dr.signature_descriptions


def test_signature_descriptions_empty_when_no_desc():
    """When no signatures have desc, signature_descriptions must be empty."""
    dr = make_report(
        signatures=[
            {"label": "sig_without_desc", "score": 3},
        ]
    )
    assert dr.signature_descriptions == {}


# ---------------------------------------------------------------------------
# network._parse_http_headers
# ---------------------------------------------------------------------------


def test_parse_http_headers_dict_style():
    headers = [{"name": "Host", "value": "evil.com"}, {"name": "Accept", "value": "*/*"}]
    assert _parse_http_headers(headers) == {"Host": "evil.com", "Accept": "*/*"}


def test_parse_http_headers_skips_invalid_entries_and_empty_names():
    # A non-str/non-dict element is silently dropped; a string with an empty name
    # (before the ": " separator) is also dropped.
    headers = [123, ": no-name-value", "Host: evil.com"]
    assert _parse_http_headers(headers) == {"Host": "evil.com"}


def test_parse_http_headers_none_returns_empty_dict():
    assert _parse_http_headers(None) == {}


# ---------------------------------------------------------------------------
# __add_network - early return and request-detail edge cases
# ---------------------------------------------------------------------------


def test_add_network_direct_call_returns_early_when_network_falsy():
    """__add_network's own guard (independent of __post_init__'s) exits without setting flow_dict."""
    dr = make_report(network={})
    dr._DynamicReport__add_network()
    assert not hasattr(dr, "flow_dict")


def test_add_network_request_with_no_flow_id_is_skipped():
    network = {
        "flows": [{"id": 1, "dst": "1.2.3.4:80", "src": "10.0.0.1:5000", "proto": "tcp"}],
        "requests": [{"index": 0, "http_request": {"url": "http://x", "method": "GET"}}],
    }
    dr = make_report(network=network)
    conns = dr.ontology.get_network_connections()
    assert len(conns) == 1
    assert conns[0].as_primitives().get("connection_type") is None


def test_dns_request_domain_falls_back_to_question_name():
    network = {
        "flows": [{"id": 2, "dst": "8.8.8.8:53", "src": "10.0.0.1:5000", "proto": "udp"}],
        "requests": [
            {
                "flow": 2,
                "dns_request": {"questions": [{"name": "fallback.example.com", "type": "AAAA"}]},
            }
        ],
    }
    dr = make_report(network=network)
    conns = dr.ontology.get_network_connections()
    prim = conns[0].as_primitives()
    assert prim["dns_details"]["domain"] == "fallback.example.com"
    assert prim["dns_details"]["lookup_type"] == "AAAA"


def test_dns_request_with_no_domain_and_no_questions_adds_no_details():
    network = {
        "flows": [{"id": 2, "dst": "8.8.8.8:53", "src": "10.0.0.1:5000", "proto": "udp"}],
        "requests": [{"flow": 2, "dns_request": {}}],
    }
    dr = make_report(network=network)
    conns = dr.ontology.get_network_connections()
    assert conns[0].as_primitives().get("connection_type") is None


def test_request_with_neither_dns_nor_http_key_is_ignored():
    network = {
        "flows": [{"id": 3, "dst": "1.2.3.4:80", "src": "10.0.0.1:5000", "proto": "tcp"}],
        "requests": [{"flow": 3, "some_other_key": {}}],
    }
    dr = make_report(network=network)
    conns = dr.ontology.get_network_connections()
    assert conns[0].as_primitives().get("connection_type") is None


def test_flow_direction_unknown_when_addresses_are_not_ip(monkeypatch):
    # ip_address() raises ValueError on non-IP strings; direction must stay "unknown"
    # rather than propagate the exception. _split_addr is patched so hostnames survive
    # the "ip:port" parse that would otherwise reject them.
    import triage_sandbox.report as report_mod

    def _split_host_port(addr: str) -> tuple[str, int]:
        host, port = addr.rsplit(":", 1)
        return host, int(port)

    monkeypatch.setattr(report_mod, "_split_addr", _split_host_port)
    network = {"flows": [{"id": 1, "dst": "host.example.com:443", "src": "internal-host:5000", "proto": "tcp"}]}
    dr = make_report(network=network)
    conns = dr.ontology.get_network_connections()
    assert conns[0].as_primitives()["direction"] == "unknown"


# ---------------------------------------------------------------------------
# __add_signatures - remaining branches
# ---------------------------------------------------------------------------


def test_add_signatures_empty_name_is_skipped():
    """A signature with neither 'label' nor a usable 'name' contributes no signature."""
    dr = make_report(signatures=[{"label": "", "name": ""}])
    assert dr.ontology.get_signatures() == []


def test_add_signatures_unknown_ttp_id_adds_no_attack():
    dr = make_report(signatures=[{"label": "s", "score": 3, "ttp": ["T9999999"]}])
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert sigs[0].attacks == []


def test_add_signatures_indicator_attaches_attribute_to_process():
    procs_input = [{"procid": 1, "pid": 100, "ppid": 0, "image": "a.exe", "cmd": "a", "started": 1}]
    dr = make_report(
        processes=procs_input,
        signatures=[{"label": "s", "score": 3, "indicators": [{"procid": 1}]}],
    )
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert len(sigs[0].attributes) == 1
    assert sigs[0].attributes[0].source.ontology_id.startswith("process_")


def test_add_signatures_indicator_with_unknown_procid_attaches_nothing():
    dr = make_report(signatures=[{"label": "s", "score": 3, "indicators": [{"procid": 999}]}])
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert sigs[0].attributes == []


def test_add_signatures_indicator_procid_resolves_process_with_falsy_pid():
    """Resolution goes through the procid → ObjectID map, not pid, so a process with
    pid=0 (e.g. the Windows System Idle Process) still attaches correctly."""
    procs_input = [{"procid": 1, "pid": 0, "ppid": 0, "image": "a.exe", "cmd": "a", "started": 1}]
    dr = make_report(
        processes=procs_input,
        signatures=[{"label": "s", "score": 3, "indicators": [{"procid": 1}]}],
    )
    sigs = dr.ontology.get_signatures()
    assert len(sigs) == 1
    assert len(sigs[0].attributes) == 1
    assert sigs[0].attributes[0].source.ontology_id.startswith("process_")


def test_add_signatures_program_crash_captures_target_process():
    """For 'program_crash', procid is the crash-reporting process (e.g. WerFault.exe) and
    procid_target is the process that actually crashed — only the latter is captured."""
    procs_input = [
        {"procid": 100, "pid": 3340, "ppid": 0, "image": "WerFault.exe", "cmd": "WerFault.exe -p 3396", "started": 1},
        {"procid": 83, "pid": 3396, "ppid": 0, "image": "malware.exe", "cmd": "malware.exe", "started": 1},
    ]
    dr = make_report(
        processes=procs_input,
        signatures=[
            {
                "label": "program_crash",
                "score": 3,
                "indicators": [{"pid": 3340, "procid": 100, "pid_target": 3396, "procid_target": 83}],
            }
        ],
    )
    crashed = dr.crashed_processes["program_crash"]
    assert len(crashed) == 1
    assert crashed[0].pid == 3396
    assert crashed[0].image == "malware.exe"


def test_add_signatures_program_crash_ignored_for_other_signatures():
    """procid_target on a non-program_crash signature must not populate crashed_processes."""
    procs_input = [{"procid": 83, "pid": 3396, "ppid": 0, "image": "malware.exe", "cmd": "malware.exe", "started": 1}]
    dr = make_report(
        processes=procs_input,
        signatures=[
            {
                "label": "suspicious_setthreadcontext",
                "score": 5,
                "indicators": [{"pid": 3260, "procid": 94, "pid_target": 3396, "procid_target": 83}],
            }
        ],
    )
    assert dr.crashed_processes == {}


def test_add_signatures_program_crash_target_resolves_process_with_falsy_pid():
    """Resolution goes through the procid_target → ObjectID map, not pid, so a crashed
    process with pid=0 still gets captured correctly."""
    procs_input = [{"procid": 83, "pid": 0, "ppid": 0, "image": "malware.exe", "cmd": "malware.exe", "started": 1}]
    dr = make_report(
        processes=procs_input,
        signatures=[
            {
                "label": "program_crash",
                "score": 3,
                "indicators": [{"pid": 3340, "procid": 100, "pid_target": 0, "procid_target": 83}],
            }
        ],
    )
    crashed = dr.crashed_processes["program_crash"]
    assert len(crashed) == 1
    assert crashed[0].image == "malware.exe"


# ---------------------------------------------------------------------------
# __add_extracted - remaining branches
# ---------------------------------------------------------------------------


def test_add_extracted_config_without_rule_adds_no_signature():
    extracted = [{"config": {"family": "emotet", "c2": ["http://x.io"]}}]
    dr = make_report(extracted=extracted)
    assert len(dr.malware_config) == 1
    assert dr.ontology.get_signatures() == []


def test_add_extracted_duplicate_rule_reuses_existing_signature():
    """A second extracted item with the same rule reuses the existing Signature object
    (rather than constructing a new one). add_signature is still called each time, so
    the object appears twice in the list, but both entries are identical."""
    extracted = [
        {"config": {"family": "emotet", "rule": "EmotetRule"}},
        {"config": {"family": "emotet", "rule": "EmotetRule"}},
    ]
    dr = make_report(extracted=extracted)
    sigs = [s for s in dr.ontology.get_signatures() if s.name == "EmotetRule"]
    assert len(sigs) == 2
    assert sigs[0] is sigs[1]


def test_add_extracted_resource_pid_attaches_attribute_to_process():
    procs_input = [{"procid": 1, "pid": 2356, "ppid": 0, "image": "a.exe", "cmd": "a", "started": 1}]
    extracted = [
        {
            "config": {"family": "emotet", "rule": "EmotetRule"},
            "resource": "files/2356-behavioral1-0x1.dat",
        }
    ]
    dr = make_report(processes=procs_input, extracted=extracted)
    sigs = [s for s in dr.ontology.get_signatures() if s.name == "EmotetRule"]
    assert len(sigs) == 1
    assert len(sigs[0].attributes) == 1


def test_add_extracted_resource_pid_with_no_matching_process_attaches_nothing():
    """resource parses to a valid int pid, but no process with that pid was recorded."""
    extracted = [
        {
            "config": {"family": "emotet", "rule": "EmotetRule"},
            "resource": "files/4242-behavioral1-0x1.dat",
        }
    ]
    dr = make_report(extracted=extracted)
    sigs = [s for s in dr.ontology.get_signatures() if s.name == "EmotetRule"]
    assert len(sigs) == 1
    assert sigs[0].attributes == []


def test_add_extracted_resource_with_non_numeric_pid_is_ignored():
    """A malformed resource path must not raise; the signature is still created without an attribute."""
    extracted = [
        {
            "config": {"family": "emotet", "rule": "EmotetRule"},
            "resource": "files/not-a-pid.dat",
        }
    ]
    dr = make_report(extracted=extracted)
    sigs = [s for s in dr.ontology.get_signatures() if s.name == "EmotetRule"]
    assert len(sigs) == 1
    assert sigs[0].attributes == []
