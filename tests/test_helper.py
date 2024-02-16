import os

from helper import TriageClient, TriageResult


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
    TriageResult(client=client, sample=sample)
