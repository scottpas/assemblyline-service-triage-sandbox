import itertools
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import List, Optional

import regex
from assemblyline.common.attack_map import attack_map
from assemblyline.odm.models.ontology.results import Process as ProcessModel
from assemblyline.odm.models.ontology.results import Signature as SignatureModel
from assemblyline.odm.models.ontology.results.malware_config import FTP, HTTP, Cryptocurrency, MalwareConfig
from assemblyline.odm.models.ontology.results.network import NetworkConnection as NetworkConnectionModel
from assemblyline.odm.models.ontology.results.sandbox import Sandbox as SandboxModel
from assemblyline_service_utilities.common.dynamic_service_helper import (
    Attribute,
    NetworkConnection,
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
    "attr"
]


@dataclass
class Credentials:
    protocol: str
    username: str
    password: str
    flow: Optional[int] = None
    host: Optional[str] = None
    port: Optional[int] = None

    def create_MalwareConfig(self):
        data = {
            "config_extractor": SERVICE_NAME,
            "family": ["UNKNOWN"]
        }
        if self.protocol == "ftp":
            data["ftp"] = [
                FTP(data={
                    "username": self.username,
                    "password": self.password,
                    "hostname": self.host,
                    "port": int(self.port)
                }).as_primitives()
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
    emails: Optional[List[str]] = None
    wallets: Optional[List[str]] = None
    urls: Optional[List[str]] = None
    contact: Optional[List[str]] = None

    def create_MalwareConfig(self):
        data = {
            "config_extractor": SERVICE_NAME,
            "family": [self.family.upper()],
            "category": "RANSOMWARE"
        }
        if self.wallets:
            data["cryptocurrency"] = []
            for wallet in self.wallets:
                data["cryptocurrency"] += Cryptocurrency(
                    data={"address": wallet, "usage": "ransomware"})
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
        data = {
            "config_extractor": "TriageSandbox",
            "family": [self.family.upper()]
        }
        if self.version:
            data["version"] = self.version
        if self.campaign:
            data['campaign_id'] = [self.campaign]
        if self.botnet:
            data["identifier"] = [self.botnet]
        if self.mutex:
            data["mutex"] = self.mutex
        if self.c2:
            data["http"] = []
            for i in self.c2:
                if regex.match(pattern="^https?://", string=i):
                    data["http"].append(HTTP(data={"uri": i}))
            # TODO: add TCP/UDP configs
            # tcp = []
            # udp = []
        if self.wallet:
            data["cryptocurrency"] = [Cryptocurrency(
                data={"address": i}) for i in self.wallet]
        if self.credentials:
            data["ftp"] = [
                FTP(data={
                    "password": i.get("password", None),
                    "host": i.get("host", None),
                    "port": i.get("port", None)
                }
                ) for i in self.credentials if i.get("protocol", None) == "ftp"
            ]
            # If creds don't have a family, call it UNKNOWN
            if not self.family:
                data["family"] = "UNKNOWN"
        other = {}
        for i in EXTRA_CONFIG_FIELDS:
            if self.__getattribute__(i):
                other[i] = self.__getattribute__(i)
        data['other'] = other
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
    processes: List[dict]
    signatures: List[dict]
    network: dict
    extracted: Optional[List[dict]] = None
    tags: Optional[List[dict]] = None
    dumped: Optional[List[dict]] = None

    def __add_sandbox(self) -> None:
        oid = SandboxModel.get_oid(
            {
                "sandbox_name": SERVICE_NAME,
                "sandbox_version": self.version,
                "analysis_metadata": {
                    "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                    "end_time": self.end_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                }
            }
        )
        object_id = self.ontology.create_objectid(
            ontology_id=oid,
            tag=SERVICE_NAME,
            session=self.session
        )
        object_id.assign_guid()
        sandbox = self.ontology.create_sandbox(
            objectid=object_id,
            analysis_metadata=Sandbox.AnalysisMetadata(
                start_time=self.start_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                end_time=self.end_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                machine_metadata=Sandbox.AnalysisMetadata.MachineMetadata(
                    hostname=self.analysis["resource"]
                )
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
                session=self.session
            )
            object_id.assign_guid()
            self.ontology.update_process(
                objectid=object_id,
                pid=process["pid"],
                ppid=process["ppid"],
                image=process["image"],
                command_line=process["cmd"],
                start_time=self.__relative_time_str(process["started"]),
                end_time=[self.__relative_time_str(process["terminated"])
                          if process.get("terminated", None) else "9999-12-31 23:59:59.999999"][0])
        pass

    def __add_network(self) -> None:
        if self.network:
            self.flow_dict = {}
            for f in self.network.get("flows", []):
                self.flow_dict[f['id']] = {
                    "destination_ip": f["dst"].split(":")[0],
                    "destination_port": int(f["dst"].split(":")[1]),
                    "transport_layer_protocol": f["proto"],
                    "direction": "unknown",
                    "source_ip": f["src"].split(":")[0],
                    "source_port": int(f["src"].split(":")[1]),
                    "time_observed": [
                        self.__relative_time_str(f["first_seen"])
                        if f.get("first_seen", None)
                        else self.start_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                    ][0]
                }
                if f.get("pid", False):
                    pass
                # TODO: #1 add connection details
                # if any(proto.startswith("http") for proto in f["protocols"]):
                #     self.flow_dict[f["id"]]["connection_type"] = "http"
                # elif any(proto == "dns" for proto in f["protocols"]):
                #     self.flow_dict[f["id"]]["connection_type"] = "dns"
                if ip_address(self.flow_dict[f["id"]]["source_ip"]).is_private and ip_address(
                        self.flow_dict[f["id"]]["destination_ip"]).is_global:
                    self.flow_dict[f["id"]]["direction"] = "outbound"
                if f.get("pid", None):
                    self.flow_dict[f["id"]]["process"] = self.ontology.get_process_by_pid(
                        f["pid"])
            for k, v in self.flow_dict.items():
                oid = NetworkConnectionModel.get_oid(v)
                tag = NetworkConnectionModel.get_tag(v)
                object_id = self.ontology.create_objectid(
                    tag=tag,
                    ontology_id=oid,
                    session=self.session,
                    **v)
                object_id.assign_guid()
                v.pop("time_observed", None)
                self.ontology.add_network_connection(
                    NetworkConnection(
                        objectid=object_id,
                        **v
                    ))

    def __add_signatures(self) -> None:
        for sig in self.signatures:
            name = sig.get("label", sig.get("name", "").replace("Suspicious behavior: ",
                           "").replace("use of ", "").replace(" ", "_").lower())
            if name != "":
                data = {
                    "name": name,
                    "type": "CUCKOO"
                }
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
                        attacks.append(attack_map[i])
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
                    malware_families=families
                )
                if not any(sig.__getattribute__("objectid").tag == tag for sig in self.ontology.get_signatures()):
                    self.ontology.add_signature(al_sig)
                else:
                    al_sig = [sig for sig in self.ontology.get_signatures()
                              if sig.__getattribute__("objectid").tag == tag][0]
                for i in sig.get("indicators", []):
                    if i.get("procid", None):
                        try:
                            source_process = self.ontology.get_process_by_pid(
                                self._id_pid_map[i["procid"]]).__getattribute__("objectid")
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
                    data = {
                        "name": name,
                        "type": "CUCKOO"
                    }
                    tag = SignatureModel.get_tag(data)
                    oid = SignatureModel.get_oid(data)
                    score = 1000  # Assume malicious because it's a malware config
                    families = [i["config"].get("family", "UNKNOWN").upper()]
                    object_id = self.ontology.create_objectid(
                        ontology_id=oid,
                        tag=tag,
                        session=self.session
                    )
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
                            malware_families=families
                        )
                    # TODO: #2 Tag processes related to signatures from resource dumps
                    # if i.get("resource", False):
                    #     source = self.ontology.get_process_by_pid(
                    #         int(i["resource"].split("/")[-1].split("-")[0]))
                    #     if source:
                    #         attr = Attribute(source=source.objectid)
                    #         al_sig.add_attribute(attr)
                    self.ontology.add_signature(al_sig)
            if i.get("ransom", False):
                self.malware_config.append(Ransom(**i["ransom"]).create_MalwareConfig())
            # TODO: make credentials work
            if i.get("credentials", False):
                self.malware_config.append(Credentials(**i["credentials"]).create_MalwareConfig())
        pass

    def __post_init__(self) -> None:
        self.start_time = datetime.fromisoformat(
            self.analysis["submitted"].replace("Z", ""))
        self.end_time = datetime.fromisoformat(
            self.analysis["reported"].replace("Z", ""))
        self.session = f'{self.sample["id"]}/{self.task_id}'
        self.__add_sandbox()
        self.__add_processes()
        self.__add_network()
        self.__add_signatures()
        self.malware_config = []
        if self.extracted:
            self.__add_extracted()


@dataclass
class Sample:
    id: str
    status: str
    kind: str
    private: bool
    tasks: List[dict]
    submitted: str
    sha256: Optional[str] = None
    filename: Optional[str] = None
    completed: Optional[str] = None
    url: Optional[str] = None

    def get_task_reports(self, client: TriageClient, ontology: OntologyResults):
        self.task_reports = []
        for task in self.tasks:
            if task['id'].startswith("behavioral"):
                self.task_reports.append(DynamicReport(
                    task_id=task['id'],
                    ontology=ontology, **client._req_json(
                        method="GET",
                        path=f"/v0/samples/{self.id}/{task['id']}/report_triage.json"
                    )
                )
                )
        pass


class TriageResult:

    def __init__(self, client: TriageClient, sample):
        self.sample = Sample(**sample)
        # self.ontology_results = OntologyResults(service_name=SERVICE_NAME)
        # self.sample.get_task_reports(client, ontology=self.ontology_results)
        self.sample.get_task_reports(client, ontology=OntologyResults(service_name=SERVICE_NAME))
        self.malware_config = list(itertools.chain(*[i.malware_config for i in self.sample.task_reports]))
        pass
