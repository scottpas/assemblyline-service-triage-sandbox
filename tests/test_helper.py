import os

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
            "malformed header entry",
        ]
    )

    assert merged["strict-transport-security"] == "max-age=604800, max-age=31536000"
    assert merged["content-type"] == "text/html"
    assert "malformed header entry" not in merged
