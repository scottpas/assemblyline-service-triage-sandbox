"""
Unit tests for helper.DynamicReport and its private mapping methods.

Each DynamicReport is exercised via construction: __post_init__ runs all
the private __add_* methods automatically.

OntologyResults accessors used:
  - ontology.get_sandboxes()          -> list[Sandbox]
  - ontology.get_processes()          -> list[Process]
  - ontology.get_network_connections() -> list[NetworkConnection]
  - ontology.get_signatures()         -> list[Signature]
"""

from datetime import datetime

from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults

from helper import DynamicReport

# ---------------------------------------------------------------------------
# Construction helper
# ---------------------------------------------------------------------------


def make_report(**over):
    base = dict(
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
