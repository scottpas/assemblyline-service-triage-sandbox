import itertools
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import List, Optional

import regex
from assemblyline.common.attack_map import attack_map
from assemblyline.odm.models.ontology.results import Process as ProcessModel
from assemblyline.odm.models.ontology.results import Signature as SignatureModel
from assemblyline.odm.models.ontology.results.malware_config import (
    FTP,
    HTTP,
    Cryptocurrency,
    GeneralConnection,
    MalwareConfig,
)
from assemblyline.odm.models.ontology.results.network import NetworkConnection as NetworkConnectionModel
from assemblyline.odm.models.ontology.results.sandbox import Sandbox as SandboxModel
from assemblyline_service_utilities.common.dynamic_service_helper import (
    Attribute,
    NetworkConnection,
    NetworkDNS,
    NetworkHTTP,
    OntologyResults,
    Process,
    Sandbox,
)
from triage import Client as TriageClient

# Ontology Result Constants
SANDBOX_NAME = "Triage Sandbox"
SERVICE_NAME = "Triage"

# Multiply scores by 100 so it matches AL scoring
SCORE_MULTIPLY_FACTOR = 100

# Fields that don't align to MalwareConfig model get added in as "other"
EXTRA_CONFIG_FIELDS = [
    "tags",
    "rule",
    "decoy",
    "webinject",
    "command_lines",
    "listen_addr",
    "listen_port",
    "listen_for",
    "shellcode",
    "attr",
]


def _split_addr(addr: str):
    """Parse 'ip:port' or '[ipv6]:port' into (ip_str, port_int)."""
    if addr.startswith("["):
        ip = addr[1 : addr.index("]")]
        port = int(addr[addr.index("]") + 2 :])
    else:
        ip, port_str = addr.rsplit(":", 1)
        port = int(port_str)
    return ip, port


_PROTO_PRIORITY: dict = {"dns": 0, "http": 1, "http2": 1, "tls": 2}


def _parse_http_headers(headers) -> dict:
    """Parse Triage HTTP headers (list of 'name: value' strings) into a dict."""
    result = {}
    for h in (headers or []):
        if isinstance(h, dict):
            result[h.get("name", "")] = h.get("value", "")
        elif isinstance(h, str):
            name, _, value = h.partition(": ")
            if name:
                result[name] = value
    return result


def _get_connection_type(protocols: list) -> Optional[str]:
    """Return AL connection_type for a Triage flow. Priority: dns > http/http2 > tls."""
    best_rank = None
    best = None
    for p in protocols:
        rank = _PROTO_PRIORITY.get(p)
        if rank is not None and (best_rank is None or rank < best_rank):
            best_rank = rank
            best = "http" if p in ("http", "http2") else p
    return best


# There is currently no way to get classification of signatures from Triage
DEFAULT_SIGNATURE_CLASSIFICATION = "TLP:CLEAR"


@dataclass
class Credentials:
    protocol: str
    username: str
    password: str
    flow: Optional[int] = None
    host: Optional[str] = None
    port: Optional[int] = None

    def create_MalwareConfig(self):
        data = {"config_extractor": SERVICE_NAME, "family": ["UNKNOWN"]}
        if self.protocol == "ftp":
            data["ftp"] = [
                FTP(
                    data={
                        "username": self.username,
                        "password": self.password,
                        "hostname": self.host,
                        "port": int(self.port),
                    }
                ).as_primitives()
            ]
        malware_config = MalwareConfig(data=data)
        return malware_config


@dataclass
class Ransom:
    """
    Ransom struct {
        Family  string   `json:"family,omitempty"`
        Target  string   `json:"target,omitempty"`
        Emails  []string `json:"emails,omitempty"`
        Wallets []string `json:"wallets,omitempty"`
        URLs    []string `json:"urls,omitempty"`
        Contact []string `json:"contact,omitempty"`
        Note    string   `json:"note"`
    }
    """

    note: str
    family: Optional[str] = None
    target: Optional[str] = None
    emails: Optional[List[str]] = None
    wallets: Optional[List[str]] = None
    urls: Optional[List[str]] = None
    contact: Optional[List[str]] = None

    def create_MalwareConfig(self):
        family = self.family.upper() if self.family else "UNKNOWN"
        data = {"config_extractor": SERVICE_NAME, "family": [family], "category": ["ransomware"]}
        if self.wallets:
            data["cryptocurrency"] = []
            for wallet in self.wallets:
                data["cryptocurrency"].append(Cryptocurrency(data={"address": wallet, "usage": "ransomware"}))
        malware_config = MalwareConfig(data=data)
        return malware_config


@dataclass
class Config:
    family: str
    tags: Optional[List[str]] = None
    rule: Optional[str] = None
    c2: Optional[List[str]] = None
    version: Optional[str] = None
    botnet: Optional[str] = None
    campaign: Optional[str] = None
    mutex: Optional[List[str]] = None
    decoy: Optional[List[str]] = None
    wallet: Optional[List[str]] = None
    dns: Optional[List[str]] = None
    keys: Optional[List[dict]] = None
    webinject: Optional[List[str]] = None
    command_lines: Optional[List[str]] = None
    listen_addr: Optional[str] = None
    listen_port: Optional[int] = None
    listen_for: Optional[List[str]] = None
    shellcode: Optional[List[bytearray]] = None
    extracted_pe: Optional[List[str]] = None
    credentials: Optional[List[dict]] = None
    attr: Optional[dict] = None
    raw: Optional[str] = None

    def create_MalwareConfig(self):
        data = {"config_extractor": "TriageSandbox", "family": [self.family.upper()]}
        if self.version:
            data["version"] = self.version
        if self.campaign:
            data["campaign_id"] = [self.campaign]
        if self.botnet:
            data["identifier"] = [self.botnet]
        if self.mutex:
            data["mutex"] = self.mutex
        if self.c2:
            http = []
            tcp = []
            for i in self.c2:
                if regex.match(pattern="^https?://", string=i):
                    http.append(HTTP(data={"uri": i}))
                else:
                    try:
                        host, port_int = _split_addr(regex.sub(r"^\w+://", "", i))
                    except (ValueError, IndexError):
                        continue
                    try:
                        ip_address(host)
                        tcp.append(
                            GeneralConnection(data={"server_ip": host, "server_port": port_int, "usage": "c2"})
                        )
                    except ValueError:
                        try:
                            tcp.append(
                                GeneralConnection(
                                    data={"server_domain": host, "server_port": port_int, "usage": "c2"}
                                )
                            )
                        except Exception:
                            continue
            if http:
                data["http"] = http
            if tcp:
                data["tcp"] = tcp
        if self.wallet:
            data["cryptocurrency"] = [Cryptocurrency(data={"address": i}) for i in self.wallet]
        if self.credentials:
            data["ftp"] = [
                FTP(
                    data={
                        "password": i.get("password", None),
                        "hostname": i.get("host", None),
                        "port": i.get("port", None),
                    }
                )
                for i in self.credentials
                if i.get("protocol", None) == "ftp"
            ]
            # If creds don't have a family, call it UNKNOWN
            if not self.family:
                data["family"] = ["UNKNOWN"]
        other = {}
        for i in EXTRA_CONFIG_FIELDS:
            if self.__getattribute__(i):
                other[i] = self.__getattribute__(i)
        data["other"] = other
        malware_config = MalwareConfig(data=data)
        return malware_config


@dataclass
class DynamicReport:
    ontology: OntologyResults
    task_id: str
    version: str
    sample: dict
    task: dict
    analysis: dict
    signatures: List[dict]
    network: dict
    processes: Optional[List[dict]] = None
    extracted: Optional[List[dict]] = None
    tags: Optional[List[dict]] = None
    dumped: Optional[List[dict]] = None
    errors: Optional[List[dict]] = None

    def __add_sandbox(self) -> None:
        oid = SandboxModel.get_oid(
            {
                "sandbox_name": SERVICE_NAME,
                "sandbox_version": self.version,
                "analysis_metadata": {
                    "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                    "end_time": self.end_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                },
            }
        )
        object_id = self.ontology.create_objectid(ontology_id=oid, tag=SERVICE_NAME, session=self.session)
        object_id.assign_guid()
        sandbox = self.ontology.create_sandbox(
            objectid=object_id,
            analysis_metadata=Sandbox.AnalysisMetadata(
                start_time=self.start_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                end_time=self.end_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                machine_metadata=Sandbox.AnalysisMetadata.MachineMetadata(hostname=self.analysis["resource"]),
            ),
            sandbox_name=SERVICE_NAME,
            sandbox_version=self.version,
        )
        self.ontology.add_sandbox(sandbox)
        pass

    def __relative_time_str(self, seconds: int) -> str:
        return (self.start_time + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.%f")

    def __add_processes(self) -> None:
        self._id_pid_map = {}
        for process in self.processes:
            self._id_pid_map[process["procid"]] = process["pid"]
            p_oid = ProcessModel.get_oid(
                {
                    "pid": process["pid"],
                    "ppid": process["ppid"],
                    "image": process["image"],
                    "command_line": process["cmd"],
                }
            )
            object_id = self.ontology.create_objectid(
                tag=Process.create_objectid_tag(process["image"]),
                ontology_id=p_oid,
                time_observed=self.__relative_time_str(process["started"]),
                session=self.session,
            )
            object_id.assign_guid()
            self.ontology.update_process(
                objectid=object_id,
                pid=process["pid"],
                ppid=process["ppid"],
                image=process["image"],
                command_line=process["cmd"],
                start_time=self.__relative_time_str(process["started"]),
                end_time=[
                    (
                        self.__relative_time_str(process["terminated"])
                        if process.get("terminated", None)
                        else "9999-12-31 23:59:59.999999"
                    )
                ][0],
            )
        pass

    def __add_network(self) -> None:
        if self.network:
            # Pre-process network.requests[] into a flow_id → details map
            request_details: dict = {}
            for req in self.network.get("requests", []):
                flow_id = req.get("flow")
                if flow_id is None:
                    continue
                if "dns_request" in req:
                    dns_req = req["dns_request"]
                    dns_res = req.get("dns_response", {})
                    questions = dns_req.get("questions", [])
                    domain = (dns_req.get("domains") or [None])[0]
                    if not domain and questions:
                        domain = questions[0].get("name", "")
                    lookup_type = questions[0].get("type", "A") if questions else "A"
                    if domain:
                        request_details[flow_id] = {
                            "dns_details": {
                                "domain": domain,
                                "resolved_ips": dns_res.get("ip") or None,
                                "resolved_domains": dns_res.get("domains") or None,
                                "lookup_type": lookup_type,
                            }
                        }
                elif "http_request" in req:
                    http_req = req["http_request"]
                    http_res = req.get("http_response", {})
                    request_details[flow_id] = {
                        "http_details": {
                            "request_uri": http_req.get("url", ""),
                            "request_method": http_req.get("method", "GET"),
                            "request_headers": _parse_http_headers(http_req.get("headers")) or None,
                            "response_headers": _parse_http_headers(http_res.get("headers")) or None,
                            "response_status_code": http_res.get("status"),
                        }
                    }

            self.flow_dict = {}
            for f in self.network.get("flows", []):
                _dst_ip, _dst_port = _split_addr(f["dst"])
                _src_ip, _src_port = _split_addr(f["src"])
                self.flow_dict[f["id"]] = {
                    "destination_ip": _dst_ip,
                    "destination_port": _dst_port,
                    "transport_layer_protocol": f["proto"],
                    "direction": "unknown",
                    "source_ip": _src_ip,
                    "source_port": _src_port,
                    "time_observed": [
                        (
                            self.__relative_time_str(f["first_seen"])
                            if f.get("first_seen", None)
                            else self.start_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                        )
                    ][0],
                }
                if (
                    ip_address(self.flow_dict[f["id"]]["source_ip"]).is_private
                    and ip_address(self.flow_dict[f["id"]]["destination_ip"]).is_global
                ):
                    self.flow_dict[f["id"]]["direction"] = "outbound"
                if f.get("pid", None):
                    self.flow_dict[f["id"]]["process"] = self.ontology.get_process_by_pid(f["pid"])

                # Triage sets flow.domain to the raw destination IP when no hostname
                # is resolved; AL rejects IPs in network.dynamic.domain
                if f.get("domain"):
                    try:
                        ip_address(f["domain"])
                        self.network_tags.append(("network.dynamic.ip", f["domain"]))
                    except ValueError:
                        self.network_tags.append(("network.dynamic.domain", f["domain"]))

                # TLS fingerprints → network tags
                for triage_key, tag_type in (
                    ("tls_ja3", "network.tls.ja3_hash"),
                    ("tls_ja3s", "network.tls.ja3s_hash"),
                    ("tls_sni", "network.tls.sni"),
                ):
                    if f.get(triage_key):
                        self.network_tags.append((tag_type, f[triage_key]))

                # Attach http/dns details from requests[] (also sets connection_type)
                req_detail = request_details.get(f["id"], {})
                if "http_details" in req_detail:
                    self.flow_dict[f["id"]]["http_details"] = req_detail["http_details"]
                    self.flow_dict[f["id"]]["connection_type"] = "http"
                if "dns_details" in req_detail:
                    self.flow_dict[f["id"]]["dns_details"] = req_detail["dns_details"]
                    self.flow_dict[f["id"]]["connection_type"] = "dns"

            for k, v in self.flow_dict.items():
                oid = NetworkConnectionModel.get_oid(v)
                tag = NetworkConnectionModel.get_tag(v)
                object_id = self.ontology.create_objectid(
                    tag=tag,
                    ontology_id=oid,
                    session=self.session,
                    time_observed=v.get("time_observed"),
                )
                object_id.assign_guid()
                v.pop("time_observed", None)
                # get_oid/get_tag consume plain dicts; convert to ODM objects before construction
                if isinstance(v.get("http_details"), dict):
                    d = v["http_details"]
                    v["http_details"] = NetworkHTTP(
                        request_uri=d["request_uri"],
                        request_method=d["request_method"],
                        request_headers=d.get("request_headers"),
                        response_headers=d.get("response_headers"),
                        response_status_code=d.get("response_status_code"),
                    )
                if isinstance(v.get("dns_details"), dict):
                    d = v["dns_details"]
                    v["dns_details"] = NetworkDNS(
                        domain=d["domain"],
                        resolved_ips=d.get("resolved_ips"),
                        resolved_domains=d.get("resolved_domains"),
                        lookup_type=d.get("lookup_type", "A"),
                    )
                self.ontology.add_network_connection(NetworkConnection(objectid=object_id, **v))

    def __add_signatures(self) -> None:
        for sig in self.signatures:
            name = sig.get(
                "label",
                sig.get("name", "")
                .replace("Suspicious behavior: ", "")
                .replace("use of ", "")
                .replace(" ", "_")
                .lower(),
            )
            if name != "":
                data = {"name": name, "type": "CUCKOO"}
                tag = SignatureModel.get_tag(data)
                oid = SignatureModel.get_oid(data)
                if sig.get("score", None):
                    score = sig["score"] * SCORE_MULTIPLY_FACTOR
                else:
                    score = 0
                attacks = []
                families = [i.split(":")[-1].upper() for i in sig.get("tags", []) if i.startswith("family:")]
                if sig.get("ttp", None):
                    for i in sig["ttp"]:
                        if attack_map.get(i, False):
                            attacks.append(
                                {
                                    "attack_id": i,
                                    "pattern": attack_map[i]["name"],
                                    "categories": attack_map[i]["categories"],
                                }
                            )
                object_id = self.ontology.create_objectid(
                    ontology_id=oid,
                    tag=tag,
                )
                object_id.assign_guid()
                al_sig = self.ontology.create_signature(
                    objectid=object_id,
                    name=name,
                    type="CUCKOO",
                    score=score,
                    attacks=attacks,
                    malware_families=families,
                    classification=DEFAULT_SIGNATURE_CLASSIFICATION,
                )
                if not any(sig.__getattribute__("objectid").tag == tag for sig in self.ontology.get_signatures()):
                    self.ontology.add_signature(al_sig)
                else:
                    al_sig = [
                        sig for sig in self.ontology.get_signatures() if sig.__getattribute__("objectid").tag == tag
                    ][0]
                for i in sig.get("indicators", []):
                    if i.get("procid", None):
                        try:
                            source_process = self.ontology.get_process_by_pid(
                                self._id_pid_map[i["procid"]]
                            ).__getattribute__("objectid")
                            source_process = source_process
                            attr = Attribute(source=source_process)
                            al_sig.add_attribute(attr)
                        except KeyError:
                            # ProcID not in mapping
                            continue
                        except Exception:
                            raise
        pass

    def __add_extracted(self):
        for i in self.extracted:
            if i.get("config", False):
                self.malware_config.append(Config(**i["config"]).create_MalwareConfig())
                if i["config"].get("rule", False):
                    name = i["config"]["rule"]
                    data = {"name": name, "type": "CUCKOO"}
                    tag = SignatureModel.get_tag(data)
                    oid = SignatureModel.get_oid(data)
                    score = 1000  # Assume malicious because it's a malware config
                    families = [i["config"].get("family", "UNKNOWN").upper()]
                    object_id = self.ontology.create_objectid(ontology_id=oid, tag=tag, session=self.session)
                    object_id.assign_guid()
                    al_sig = [i for i in self.ontology.get_signatures() if i.as_primitives()["objectid"]["tag"] == tag]
                    if len(al_sig) == 1:
                        al_sig = al_sig[0]
                    else:
                        al_sig = self.ontology.create_signature(
                            objectid=object_id,
                            name=name,
                            type="CUCKOO",
                            score=score,
                            malware_families=families,
                            classification=DEFAULT_SIGNATURE_CLASSIFICATION,
                        )
                    if i.get("resource", False):
                        try:
                            source = self.ontology.get_process_by_pid(int(i["resource"].split("/")[-1].split("-")[0]))
                            if source:
                                attr = Attribute(source=source.objectid)
                                al_sig.add_attribute(attr)
                        except ValueError:
                            # resource is not related to a process
                            pass
                    self.ontology.add_signature(al_sig)
            if i.get("ransom_note", False):
                self.malware_config.append(Ransom(**i["ransom_note"]).create_MalwareConfig())
            # TODO: make credentials work
            if i.get("credentials", False):
                self.malware_config.append(Credentials(**i["credentials"]).create_MalwareConfig())
        pass

    def __post_init__(self) -> None:
        self.start_time = datetime.fromisoformat(self.analysis["submitted"].replace("Z", ""))
        self.end_time = datetime.fromisoformat(self.analysis["reported"].replace("Z", ""))
        self.session = f"{self.sample['id']}/{self.task_id}"
        self.network_tags: List[tuple] = []
        self.__add_sandbox()
        if self.processes:
            self.__add_processes()
        if self.network:
            self.__add_network()
        if self.signatures:
            self.__add_signatures()
        self.malware_config = []
        if self.extracted:
            self.__add_extracted()


@dataclass
class Sample:
    id: str
    status: str
    kind: str
    tasks: List[dict]
    submitted: str
    sha256: Optional[str] = None
    filename: Optional[str] = None
    completed: Optional[str] = None
    url: Optional[str] = None
    private: Optional[bool] = None

    def get_task_reports(self, client: TriageClient):
        self.task_reports = []
        for task in self.tasks:
            if task["id"].startswith("behavioral") and task["status"] != "failed":
                api_response = client._req_json(
                    method="GET", path=f"/v0/samples/{self.id}/{task['id']}/report_triage.json"
                )

                expected_fields = {
                    "version",
                    "sample",
                    "task",
                    "analysis",
                    "signatures",
                    "network",
                    "processes",
                    "extracted",
                    "tags",
                    "dumped",
                    "errors",
                }
                filtered_response = {k: v for k, v in api_response.items() if k in expected_fields}

                self.task_reports.append(
                    DynamicReport(
                        task_id=task["id"],
                        ontology=OntologyResults(service_name=SERVICE_NAME),
                        **filtered_response,
                    )
                )
        pass


class TriageResult:
    def __init__(self, client: TriageClient, sample):
        self.sample = Sample(**sample)
        self.sample.get_task_reports(client)
        self.malware_config = list(itertools.chain(*[i.malware_config for i in self.sample.task_reports]))
        pass
