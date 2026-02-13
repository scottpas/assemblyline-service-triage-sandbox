import os

from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults

from helper import DynamicReport, TriageClient, TriageResult


# Test TriageResult Class
def test_TriageResult(requests_mock):
    SAMPLE = os.path.join(os.path.dirname(__file__), "triage_responses", "240202-3y8f7sefen.json")
    BEHAVIORAL1 = os.path.join(os.path.dirname(__file__), "triage_responses",
                               "240202-3y8f7sefen-behavioral1-report_triage.json")
    BEHAVIORAL2 = os.path.join(os.path.dirname(__file__), "triage_responses",
                               "240202-3y8f7sefen-behavioral2-report_triage.json")
    with open(SAMPLE, "r") as f:
        sample_data = f.read()
    with open(BEHAVIORAL1, "r") as f:
        behavioral1_data = f.read()
    with open(BEHAVIORAL2, "r") as f:
        behavioral2_data = f.read()
    requests_mock.get("https://api.tria.ge/v0/samples/240202-3y8f7sefen", text=sample_data)
    requests_mock.get("https://api.tria.ge/v0/samples/240202-3y8f7sefen/behavioral1/report_triage.json",
                      text=behavioral1_data)
    requests_mock.get("https://api.tria.ge/v0/samples/240202-3y8f7sefen/behavioral2/report_triage.json",
                      text=behavioral2_data)
    client = TriageClient(token="TESTING")
    sample = client.sample_by_id("240202-3y8f7sefen")
    triage_result = TriageResult(client=client, sample=sample)

    network_connections = []
    for task in triage_result.sample.task_reports:
        network_connections.extend([i.as_primitives() for i in task.ontology.get_network_connections()])

    assert any(
        i.get("connection_type") == "dns"
        and i.get("dns_details", {}).get("domain")
        and i.get("dns_details", {}).get("lookup_type")
        for i in network_connections
    )
    assert any(
        i.get("connection_type") == "http"
        and i.get("http_details", {}).get("request_uri")
        and i.get("http_details", {}).get("request_method")
        for i in network_connections
    )
    assert any(
        i.get("connection_type") == "http"
        and i.get("http_details", {})
        .get("response_headers", {})
        .get("strict-transport-security")
        == "max-age=604800, max-age=31536000"
        for i in network_connections
    )


def test_headers_list_to_dict_merges_duplicate_headers():
    merged = DynamicReport._DynamicReport__headers_list_to_dict(
        [
            "strict-transport-security: max-age=604800",
            "content-type: text/html",
            "strict-transport-security: max-age=31536000",
            "Set-Cookie: a=1",
            "set-cookie: b=2",
            "malformed header entry",
        ]
    )

    assert merged["strict-transport-security"] == "max-age=604800, max-age=31536000"
    assert merged["content-type"] == "text/html"
    assert merged["set-cookie"] == "a=1, b=2"
    assert "malformed header entry" not in merged


def _build_dynamic_report(network):
    return DynamicReport(
        ontology=OntologyResults(service_name="Triage"),
        task_id="behavioral-test",
        version="1.0",
        sample={"id": "sample-1"},
        task={},
        analysis={
            "submitted": "2024-02-02T23:56:01Z",
            "reported": "2024-02-02T23:56:45Z",
            "resource": "host-1",
        },
        signatures=[],
        network=network,
    )


def test_dns_resolved_domains_come_from_answer_values():
    report = _build_dynamic_report(
        network={
            "flows": [
                {
                    "id": 10,
                    "dst": "8.8.8.8:53",
                    "src": "10.0.0.5:51515",
                    "proto": "udp",
                    "first_seen": 1,
                    "protocols": ["dns"],
                    "domain": "fallback.example",
                }
            ],
            "requests": [
                {
                    "flow": 10,
                    "index": 1,
                    "dns_request": {
                        "domains": ["query.example"],
                        "questions": [{"name": "query.example", "type": "IN A"}],
                    },
                },
                {
                    "flow": 10,
                    "index": 1,
                    "dns_response": {
                        "domains": ["query.example"],
                        "ip": ["203.0.113.10"],
                        "answers": [
                            {"name": "query.example", "type": "IN CNAME", "value": "edge.example.net"},
                            {"name": "edge.example.net", "type": "IN A", "value": "203.0.113.10"},
                            {"name": "query.example", "type": "IN CNAME", "value": "edge.example.net"},
                            {"name": "query.example", "type": "IN CNAME", "value": "cdn.example.org"},
                        ],
                    },
                },
            ],
        }
    )

    dns_connections = [
        connection.as_primitives()
        for connection in report.ontology.get_network_connections()
        if connection.as_primitives().get("connection_type") == "dns"
    ]

    assert len(dns_connections) == 1
    assert dns_connections[0]["dns_details"]["resolved_domains"] == ["edge.example.net", "cdn.example.org"]
    assert "query.example" not in dns_connections[0]["dns_details"]["resolved_domains"]


def test_dns_repeated_queries_on_same_flow_create_multiple_connections():
    report = _build_dynamic_report(
        network={
            "flows": [
                {
                    "id": 20,
                    "dst": "1.1.1.1:53",
                    "src": "10.0.0.5:52525",
                    "proto": "udp",
                    "first_seen": 1,
                    "protocols": ["dns"],
                }
            ],
            "requests": [
                {
                    "flow": 20,
                    "index": 1,
                    "dns_request": {
                        "domains": ["first.example"],
                        "questions": [{"name": "first.example", "type": "IN A"}],
                    },
                },
                {
                    "flow": 20,
                    "index": 1,
                    "dns_response": {
                        "ip": ["198.51.100.10"],
                        "answers": [{"name": "first.example", "type": "IN A", "value": "198.51.100.10"}],
                    },
                },
                {
                    "flow": 20,
                    "index": 2,
                    "dns_request": {
                        "domains": ["second.example"],
                        "questions": [{"name": "second.example", "type": "IN AAAA"}],
                    },
                },
                {
                    "flow": 20,
                    "index": 2,
                    "dns_response": {
                        "answers": [{"name": "second.example", "type": "IN CNAME", "value": "resolver.example.net"}],
                    },
                },
            ],
        }
    )

    dns_connections = [
        connection.as_primitives()
        for connection in report.ontology.get_network_connections()
        if connection.as_primitives().get("connection_type") == "dns"
    ]

    assert len(dns_connections) == 2
    assert [connection["dns_details"]["domain"] for connection in dns_connections] == [
        "first.example",
        "second.example",
    ]
    assert [connection["dns_details"]["lookup_type"] for connection in dns_connections] == ["A", "AAAA"]
