import itertools
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import Any, List, Optional, cast

from assemblyline.common.attack_map import attack_map
from assemblyline.odm.models.ontology.results import Process as ProcessModel
from assemblyline.odm.models.ontology.results import Signature as SignatureModel
from assemblyline.odm.models.ontology.results.malware_config import MalwareConfig
from assemblyline.odm.models.ontology.results.network import (
    NetworkConnection as NetworkConnectionModel,
)
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

from .constants import (
    DEFAULT_SIGNATURE_CLASSIFICATION,
    SCORE_MULTIPLY_FACTOR,
    SERVICE_NAME,
)
from .models import Config, Credentials, Ransom
from .network import _parse_http_headers, _split_addr


@dataclass
class DynamicReport:
    ontology: OntologyResults
    task_id: str
    version: str
    sample: dict  # type: ignore[type-arg]
    task: dict  # type: ignore[type-arg]
    analysis: dict  # type: ignore[type-arg]
    signatures: List[dict]  # type: ignore[type-arg]
    network: dict  # type: ignore[type-arg]
    processes: Optional[List[dict]] = None  # type: ignore[type-arg]
    extracted: Optional[List[dict]] = None  # type: ignore[type-arg]
    tags: Optional[List[dict]] = None  # type: ignore[type-arg]
    dumped: Optional[List[dict]] = None  # type: ignore[type-arg]
    errors: Optional[List[dict]] = None  # type: ignore[type-arg]

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

    def __relative_time_str(self, seconds: int) -> str:
        return (self.start_time + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.%f")

    def __add_processes(self) -> None:
        for process in self.processes or []:
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
                end_time=(
                    self.__relative_time_str(process["terminated"])
                    if process.get("terminated") is not None
                    else "9999-12-31 23:59:59.999999"
                ),
            )

    def __add_network(self) -> None:
        if not self.network:
            return

        # Pre-process network.requests[] into a flow_id details map
        request_details: dict[Any, dict[str, Any]] = {}
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

        self.flow_dict: dict[Any, dict[str, Any]] = {}
        for f in self.network.get("flows", []):
            _dst_ip, _dst_port = _split_addr(f["dst"])
            _src_ip, _src_port = _split_addr(f["src"])
            flow: dict[str, Any] = {
                "destination_ip": _dst_ip,
                "destination_port": _dst_port,
                "transport_layer_protocol": f["proto"],
                "direction": "unknown",
                "source_ip": _src_ip,
                "source_port": _src_port,
                "time_observed": (
                    self.__relative_time_str(f["first_seen"])
                    if f.get("first_seen") is not None
                    else self.start_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                ),
            }
            try:
                if ip_address(_src_ip).is_private and ip_address(_dst_ip).is_global:
                    flow["direction"] = "outbound"
            except ValueError:
                pass
            if f.get("pid"):
                flow["process"] = self.ontology.get_process_by_pid(f["pid"])

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
                flow["http_details"] = req_detail["http_details"]
                flow["connection_type"] = "http"
            if "dns_details" in req_detail:
                flow["dns_details"] = req_detail["dns_details"]
                flow["connection_type"] = "dns"

            self.flow_dict[f["id"]] = flow

        for flow in self.flow_dict.values():
            oid = NetworkConnectionModel.get_oid(flow)
            tag = NetworkConnectionModel.get_tag(flow)
            object_id = self.ontology.create_objectid(
                tag=tag,
                ontology_id=oid,
                session=self.session,
                time_observed=flow.get("time_observed"),
            )
            object_id.assign_guid()
            flow.pop("time_observed", None)
            # get_oid/get_tag consume plain dicts; convert to ODM objects before construction
            if isinstance(flow.get("http_details"), dict):
                d = cast(dict[str, Any], flow["http_details"])
                flow["http_details"] = NetworkHTTP(
                    request_uri=d["request_uri"],
                    request_method=d["request_method"],
                    request_headers=d.get("request_headers"),
                    response_headers=d.get("response_headers"),
                    response_status_code=d.get("response_status_code"),
                )
            if isinstance(flow.get("dns_details"), dict):
                d = cast(dict[str, Any], flow["dns_details"])
                flow["dns_details"] = NetworkDNS(
                    domain=d["domain"],
                    resolved_ips=d.get("resolved_ips") or None,  # ty: ignore[invalid-argument-type]
                    resolved_domains=d.get("resolved_domains") or None,  # ty: ignore[invalid-argument-type]
                    lookup_type=d.get("lookup_type", "A"),
                )
            self.ontology.add_network_connection(NetworkConnection(objectid=object_id, **flow))

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
            if not name:
                continue
            data = {"name": name, "type": "CUCKOO"}
            tag = SignatureModel.get_tag(data)
            oid = SignatureModel.get_oid(data)
            raw_score = sig.get("score")
            score = raw_score * SCORE_MULTIPLY_FACTOR if raw_score is not None else 0
            attacks = []
            families = [i.split(":")[-1].upper() for i in sig.get("tags", []) if i.startswith("family:")]
            if sig.get("ttp"):
                for ttp_id in sig["ttp"]:
                    if attack_map.get(ttp_id):
                        attacks.append(
                            {
                                "attack_id": ttp_id,
                                "pattern": attack_map[ttp_id]["name"],
                                "categories": attack_map[ttp_id]["categories"],
                            }
                        )
            object_id = self.ontology.create_objectid(ontology_id=oid, tag=tag)
            object_id.assign_guid()
            existing_by_tag = {cast(Any, s).objectid.tag: s for s in self.ontology.get_signatures()}
            if tag in existing_by_tag:
                al_sig = existing_by_tag[tag]
            else:
                al_sig = self.ontology.create_signature(
                    objectid=object_id,
                    name=name,
                    type="CUCKOO",
                    score=score,
                    attacks=attacks,
                    malware_families=families,
                    classification=DEFAULT_SIGNATURE_CLASSIFICATION,
                )
                self.ontology.add_signature(al_sig)
            # Capture human-readable description for display in result sections
            if sig.get("desc"):
                self.signature_descriptions[name] = sig["desc"]
            for indicator in sig.get("indicators", []):
                if indicator.get("procid") and indicator["procid"] in self._id_pid_map:
                    try:
                        source_process = self.ontology.get_process_by_pid(self._id_pid_map[indicator["procid"]])
                        if source_process:
                            attr = Attribute(source=cast(Any, source_process).objectid)
                            al_sig.add_attribute(attr)
                    except Exception:
                        raise

    def __add_extracted(self) -> None:
        for item in self.extracted or []:
            if item.get("config"):
                self.malware_config.append(Config(**item["config"]).create_MalwareConfig())
                if item["config"].get("rule"):
                    name = item["config"]["rule"]
                    data = {"name": name, "type": "CUCKOO"}
                    tag = SignatureModel.get_tag(data)
                    oid = SignatureModel.get_oid(data)
                    score = 1000
                    families = [item["config"].get("family", "UNKNOWN").upper()]
                    object_id = self.ontology.create_objectid(ontology_id=oid, tag=tag, session=self.session)
                    object_id.assign_guid()
                    existing_for_rule = [
                        s for s in self.ontology.get_signatures() if s.as_primitives()["objectid"]["tag"] == tag
                    ]
                    if len(existing_for_rule) == 1:
                        al_sig = existing_for_rule[0]
                    else:
                        al_sig = self.ontology.create_signature(
                            objectid=object_id,
                            name=name,
                            type="CUCKOO",
                            score=score,
                            malware_families=families,
                            classification=DEFAULT_SIGNATURE_CLASSIFICATION,
                        )
                    if item.get("resource"):
                        try:
                            source = self.ontology.get_process_by_pid(
                                int(item["resource"].split("/")[-1].split("-")[0])
                            )
                            if source:
                                attr = Attribute(source=cast(Any, source).objectid)
                                al_sig.add_attribute(attr)
                        except ValueError:
                            pass
                    self.ontology.add_signature(al_sig)
            if item.get("ransom_note"):
                self.malware_config.append(Ransom(**item["ransom_note"]).create_MalwareConfig())
            if item.get("credentials"):
                self.malware_config.append(Credentials(**item["credentials"]).create_MalwareConfig())

    def __post_init__(self) -> None:
        self.start_time = datetime.fromisoformat(self.analysis["submitted"].replace("Z", ""))
        self.end_time = datetime.fromisoformat(self.analysis["reported"].replace("Z", ""))
        self.session = f"{self.sample['id']}/{self.task_id}"
        self.network_tags: List[tuple] = []  # type: ignore[type-arg]
        self.malware_config: List[MalwareConfig] = []
        self._id_pid_map: dict[int, int] = {}
        # Maps normalized signature name → human-readable description (sig.desc)
        self.signature_descriptions: dict[str, str] = {}
        self.__add_sandbox()
        if self.processes:
            self.__add_processes()
        if self.network:
            self.__add_network()
        if self.signatures:
            self.__add_signatures()
        if self.extracted:
            self.__add_extracted()


_EXPECTED_REPORT_FIELDS = frozenset(
    {
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
)


@dataclass
class Sample:
    id: str
    status: str
    kind: str
    tasks: List[dict]  # type: ignore[type-arg]
    submitted: str
    sha256: Optional[str] = None
    filename: Optional[str] = None
    completed: Optional[str] = None
    url: Optional[str] = None
    private: Optional[bool] = None
    task_reports: List[DynamicReport] = field(default_factory=list)

    def get_task_reports(self, client: TriageClient) -> None:
        self.task_reports = []
        for task in self.tasks:
            if task["id"].startswith("behavioral") and task["status"] != "failed":
                api_response = client._req_json(
                    method="GET",
                    path=f"/v0/samples/{self.id}/{task['id']}/report_triage.json",
                )
                filtered = {k: v for k, v in api_response.items() if k in _EXPECTED_REPORT_FIELDS}
                self.task_reports.append(
                    DynamicReport(
                        task_id=task["id"],
                        ontology=OntologyResults(service_name=SERVICE_NAME),
                        **filtered,
                    )
                )


# Keys accepted by the Config dataclass; guards against unknown future Triage config fields
_CONFIG_DATACLASS_FIELDS = frozenset(
    {
        "family",
        "tags",
        "rule",
        "c2",
        "version",
        "botnet",
        "campaign",
        "mutex",
        "decoy",
        "wallet",
        "dns",
        "keys",
        "webinject",
        "command_lines",
        "listen_addr",
        "listen_port",
        "listen_for",
        "shellcode",
        "extracted_pe",
        "credentials",
        "attr",
        "raw",
    }
)


def _filter_config(cfg: dict) -> dict:  # type: ignore[type-arg]
    """Return only keys accepted by the Config dataclass; drops unknown future Triage fields."""
    return {k: v for k, v in cfg.items() if k in _CONFIG_DATACLASS_FIELDS}


class TriageResult:
    def __init__(self, client: TriageClient, sample: dict) -> None:  # type: ignore[type-arg]
        self.sample = Sample(**sample)
        self.sample.get_task_reports(client)
        self.malware_config = list(itertools.chain.from_iterable(r.malware_config for r in self.sample.task_reports))

        # Configs already recovered from behavioral reports (dedup key: family + sorted c2 list)
        behavioral_config_keys: set[tuple] = set()
        for report in self.sample.task_reports:
            for item in report.extracted or []:
                cfg = item.get("config") or {}
                if cfg.get("family"):
                    key = (cfg["family"].lower(), tuple(sorted(cfg.get("c2") or [])))
                    behavioral_config_keys.add(key)

        # Collect seen signature names across all behavioral tasks (for overview dedup)
        behavioral_sig_names: set[str] = set()
        for report in self.sample.task_reports:
            for sig in report.signatures or []:
                name = sig.get("label") or sig.get("name", "")
                if name:
                    behavioral_sig_names.add(name)

        self.overview_configs: list[dict] = []  # type: ignore[type-arg]
        self.overview_signatures: list[dict] = []  # type: ignore[type-arg]

        try:
            overview = client.overview_report(self.sample.id)
        except Exception:
            overview = {}

        if overview:
            for item in overview.get("extracted") or []:
                cfg = item.get("config") or {}
                family = cfg.get("family", "")
                if not family:
                    continue
                key = (family.lower(), tuple(sorted(cfg.get("c2") or [])))
                if key in behavioral_config_keys:
                    continue  # already extracted from a behavioral report
                filtered = _filter_config(cfg)
                try:
                    mc = Config(**filtered).create_MalwareConfig()
                    self.malware_config.append(mc)
                    self.overview_configs.append(cfg)
                    behavioral_config_keys.add(key)  # prevent double-adding if overview has dupes
                except Exception:
                    pass

            for sig in overview.get("signatures") or []:
                name = sig.get("label") or sig.get("name", "")
                if name and name not in behavioral_sig_names:
                    self.overview_signatures.append(sig)
                    behavioral_sig_names.add(name)
