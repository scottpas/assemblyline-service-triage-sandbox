import itertools
import json
import ntpath
import shlex
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any, List, Optional, cast

from assemblyline.common.attack_map import attack_map
from assemblyline.common.dict_utils import get_dict_fingerprint_hash
from assemblyline.odm.base import Domain as DomainField
from assemblyline.odm.models.ontology.results import Process as ProcessModel
from assemblyline.odm.models.ontology.results import Signature as SignatureModel
from assemblyline.odm.models.ontology.results.malware_config import MalwareConfig
from assemblyline.odm.models.ontology.results.network import (
    NetworkConnection as NetworkConnectionModel,
)
from assemblyline.odm.models.ontology.results.network import (
    NetworkDNS as NetworkDNSModel,
)
from assemblyline.odm.models.ontology.results.network import NetworkHTTP as NetworkHTTPModel
from assemblyline.odm.models.ontology.results.sandbox import Sandbox as SandboxModel
from assemblyline_service_utilities.common.dynamic_service_helper import (
    MAX_TIME,
    Attribute,
    NetworkConnection,
    NetworkDNS,
    NetworkHTTP,
    OntologyResults,
    Process,
    Sandbox,
)
from requests import RequestException

from .client import ServerError, TriageClient
from .constants import (
    DEFAULT_SIGNATURE_CLASSIFICATION,
    SCORE_MULTIPLY_FACTOR,
    SERVICE_NAME,
)
from .models import Config, Credentials, Ransom
from .network import (
    _network_transactions,
    _normalize_dns_lookup_type,
    _parse_http_headers,
    _response_mimetype,
    _split_addr,
)

# Same validator AL applies to network.dynamic.domain tags at result validation
_DOMAIN_FIELD = DomainField()


def _analysis_time(value: str) -> datetime:
    """Parse the upstream RFC3339 analysis time and normalize it to UTC."""
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Analysis timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _indicator_text(indicator: dict) -> Optional[str]:
    """Combine an indicator's human-readable description with its IOC value, if present."""
    desc = indicator.get("description")
    ioc = indicator.get("ioc")
    if desc and ioc:
        return f"{desc}: {ioc}"
    return desc or ioc


# Non-interactive service account SIDs are never "the current user" — Triage's own
# rules agree (e.g. its "reg_hku_write" signature fires for these, naming the hive HKU
# rather than treating it as a current-user write), so these stay under HKEY_USERS.
_HKU_WELL_KNOWN_SERVICE_SIDS = frozenset(
    {
        "S-1-5-18",  # SYSTEM
        "S-1-5-19",  # LOCAL SERVICE
        "S-1-5-20",  # NETWORK SERVICE
    }
)


def _process_ref(procid: Any, pid: Any) -> str:
    """Describe a raw process reference from whichever identifiers are present."""
    parts = [f"#{procid}" if procid is not None else "", f"PID {pid}" if pid is not None else ""]
    return " ".join(part for part in parts if part)


def _indicator_row(indicator: dict[str, Any], source: str, target: str) -> dict[str, Any]:
    """Tabulate one signature indicator; flow ids and resources are task-local references."""
    return {
        "Source": source,
        "Target": target,
        "Description": indicator.get("description") or "",
        "IOC": indicator.get("ioc") or "",
        "Flow": indicator.get("flow") or "",
        "Resource": indicator.get("resource") or "",
        "YARA rule": indicator.get("yara_rule") or "",
    }


def _normalize_registry_key(raw: str) -> Optional[str]:
    """Normalize a Triage indicator IOC into a conventional Win32 registry key path.

    Triage denotes registry keys using the native NT object namespace
    (e.g. ``\\REGISTRY\\MACHINE\\...``, ``\\REGISTRY\\USER\\<SID>\\...``) rather than
    the ``HKEY_*`` hive names analysts expect, and casing of the root tokens is
    inconsistent across Triage's own detection rules (``\\Registry\\Machine\\...`` is
    observed alongside ``\\REGISTRY\\MACHINE\\...``) — only those root tokens are
    case-normalized here, never the real key path that follows.

    A Triage sandbox VM has a single interactive user, so an ordinary per-machine
    user-profile SID is that session's current user; ``<SID>_Classes`` is the overlay
    hive mounted at ``HKEY_CURRENT_USER\\Software\\Classes``, and ``.DEFAULT`` is the
    non-logged-in default profile (kept under HKEY_USERS, since it isn't a "current
    user"). Well-known non-interactive service SIDs (SYSTEM, LOCAL SERVICE, NETWORK
    SERVICE) are also kept under HKEY_USERS rather than collapsed to HKEY_CURRENT_USER.
    Returns None if `raw` isn't a registry path.
    """
    key = raw.split(" = ", 1)[0]
    if not key.lower().startswith("\\registry\\"):
        return None
    # The startswith check above guarantees at least "\REGISTRY\", which always
    # splits into >= 3 parts ("", "REGISTRY", <rest, possibly empty>).
    parts = key.split("\\")
    hive, rest = parts[2].upper(), parts[3:]
    if hive == "MACHINE":
        return "\\".join(["HKEY_LOCAL_MACHINE", *rest])
    if hive == "USER":
        if not rest:
            return "HKEY_USERS"
        user_id, *tail = rest
        if user_id.upper() == ".DEFAULT":
            return "\\".join(["HKEY_USERS", ".DEFAULT", *tail])
        is_classes_hive = user_id.upper().endswith("_CLASSES")
        bare_sid = user_id[: -len("_Classes")] if is_classes_hive else user_id
        if bare_sid.upper() in _HKU_WELL_KNOWN_SERVICE_SIDS:
            # A service account's Classes overlay hive is still that service account's,
            # not the interactive user's — keep the SID rather than collapsing to HKCU.
            return "\\".join(["HKEY_USERS", user_id, *tail])
        if is_classes_hive:
            return "\\".join(["HKEY_CURRENT_USER", "Software", "Classes", *tail])
        return "\\".join(["HKEY_CURRENT_USER", *tail])
    return None


def _is_static_yara_resource(resource: Optional[str]) -> bool:
    """Whether an indicator's "resource" points to something a static YARA scan actually
    ran against (the submitted sample, or a memory dump captured during execution) —
    as opposed to a behavioral indicator that only incidentally carries a yara_rule.

    Triage's schema has no explicit field distinguishing these (see triage_service_gaps
    memory); this is inferred from observed resource path shapes, not a documented contract.
    """
    return resource == "sample" or (resource is not None and "/memory/" in resource)


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

    def __relative_time_str(self, milliseconds: Any, context: str) -> Optional[str]:
        """Convert Triage's integer millisecond offsets to the helper's UTC format.

        Missing optional values remain unknown. Reject offsets outside the reported
        analysis window instead of clamping them or trying another unit/epoch.
        """
        if milliseconds is None:
            return None
        if type(milliseconds) is not int or milliseconds < 0 or milliseconds > self._duration_ms:
            self.diagnostics.append(f"Task {self.task_id}, {context}: invalid millisecond offset {milliseconds!r}.")
            return None
        return (self.start_time + timedelta(milliseconds=milliseconds)).strftime("%Y-%m-%d %H:%M:%S.%f")

    def __add_processes(self) -> None:
        # The helper's add/update path identifies processes by PID and time: it merges a
        # reused PID into an earlier instance with no recorded termination and infers
        # parents from PPID. Triage's procid already identifies each instance, so build
        # every instance here and register the list directly.
        created: list[tuple[dict[str, Any], Any]] = []
        for process in self.processes or []:
            try:
                procid = process["procid"]
                if type(procid) is not int or procid in self._procid_process:
                    raise ValueError("Process instance identifiers must be unique integers")
                start_time = self.__relative_time_str(process.get("started"), f"process {procid} started")
                if start_time is None:
                    if process.get("started") is None:
                        self.diagnostics.append(
                            f"Task {self.task_id}, process {procid}: started time unknown; process omitted."
                        )
                    continue
                # Go's terminated,omitempty uses zero for no observed termination.
                terminated = process.get("terminated")
                end_time = self.__relative_time_str(
                    None if type(terminated) is int and terminated == 0 else terminated,
                    f"process {procid} terminated",
                )
                if end_time is not None and end_time < start_time:
                    self.diagnostics.append(f"Task {self.task_id}, process {procid}: terminated before started.")
                    end_time = None
                image = process.get("image") or "<unknown_image>"
                command = process.get("cmd")
                if isinstance(command, list):
                    # Argument arrays are rendered with POSIX quoting for display, never
                    # interpreted as an executable path or run as a shell command.
                    command = shlex.join(command) or None
                elif command is not None and not isinstance(command, str):
                    raise TypeError("Process command must be text or an argument array")
                p_oid = ProcessModel.get_oid(
                    {
                        "pid": process["pid"],
                        "ppid": process["ppid"],
                        "image": image,
                        "command_line": command,
                    }
                )
                object_id = self.ontology.create_objectid(
                    tag=Process.create_objectid_tag(image),
                    ontology_id=p_oid,
                    time_observed=start_time,
                    session=self.session,
                )
                object_id.assign_guid()
                data = dict(
                    objectid=object_id,
                    pid=process["pid"],
                    ppid=process["ppid"],
                    image=image,
                    command_line=command,
                    start_time=start_time,
                    end_time=end_time,
                )
                # Validate before mutating the ontology: helper objects accept values that
                # the Process ODM may reject later during result emission.
                ProcessModel({**data, "objectid": object_id.as_primitives()})
                instance = self.ontology.create_process(**data)
                self._procid_process[procid] = instance
                created.append((process, instance))
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                self.diagnostics.append(f"Task {self.task_id}: invalid process ({type(exc).__name__}).")
        procid_of = {id(instance): process["procid"] for process, instance in created}
        for _, instance in created:
            self._pid_instances.setdefault(instance.pid, []).append(instance)
        for process, instance in created:
            parent_procid = self.__set_parent(process, instance, procid_of)
            cmd = process.get("cmd")
            self.process_rows.append(
                {
                    "Process": process["procid"],
                    "Parent": parent_procid,
                    "PID": instance.pid,
                    "PPID": instance.ppid,
                    # Upstream marker, shown as-is: its meaning is not documented consistently.
                    "Triage orig": process["orig"] if type(process.get("orig")) is bool else "",
                    "Image": instance.image,
                    # Argument arrays keep their original boundaries here.
                    "Command": json.dumps(cmd) if isinstance(cmd, list) else cmd or "",
                }
            )
        self.ontology.set_processes([instance for _, instance in created])

    def __set_parent(self, process: dict[str, Any], child: Any, procid_of: dict[int, int]) -> Any:
        """Link a child to its parent instance and return the parent reference for display.

        Triage's procid_parent names the nearest recorded ancestor: forks that never exec
        are not recorded, so that ancestor's PID can differ from the reported PPID. The
        reported PPID is kept as-is. An explicit but unrecorded parent is not replaced by
        a PID guess; only reports without procid_parent fall back to a single process with
        the PPID that is alive when the child starts.
        """
        # Go omits a zero procid_parent, so zero also means "not reported".
        parent_procid = process.get("procid_parent")
        if parent_procid:
            parent = self._procid_process.get(parent_procid)
            if parent is None or parent is child:
                return f"{parent_procid} (not recorded)"
        else:
            # Helper times are fixed-width strings; open-ended instances end at MAX_TIME.
            live = [
                p
                for p in self._pid_instances.get(child.ppid, [])
                if p is not child and p.start_time <= child.start_time <= p.end_time
            ]
            if len(live) != 1:
                return ""
            parent = live[0]
        child.pobjectid = parent.objectid
        child.pimage = parent.image
        child.pcommand_line = parent.command_line
        return procid_of[id(parent)]

    def __process_for(self, procid: Any) -> Any:
        return self._procid_process.get(procid) if type(procid) is int else None

    def __record_process(self, record: dict[str, Any]) -> Any:
        """Resolve a flow or dump owner by procid; records without one fall back to a unique PID."""
        if "procid" in record:
            return self.__process_for(record["procid"])
        owners = self._pid_instances.get(record.get("pid")) or []
        return owners[0] if record.get("pid") and len(owners) == 1 else None

    def __process_label(self, indicator: dict[str, Any], procid_key: str, pid_key: str) -> str:
        """Describe an indicator's process reference by instance, falling back to its raw ids."""
        procid, pid = indicator.get(procid_key), indicator.get(pid_key)
        process = self.__process_for(procid)
        if process is not None:
            return f"#{procid} {ntpath.basename(process.image)} (PID {process.pid})"
        ref = _process_ref(procid, pid)
        return f"{ref} (not recorded)" if procid is not None else ref

    def __add_network(self) -> None:
        if not self.network:
            return

        records = self.network.get("requests", [])
        self.dns_evidence = [r for r in records if "dns_request" in r or "dns_response" in r]
        self.http_evidence = [r for r in records if "http_request" in r or "http_response" in r]
        request_details: dict[Any, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
        flow_ids = {f["id"] for f in self.network.get("flows", [])}
        for transaction in _network_transactions(records):
            flow_id = transaction.flow
            identity = {
                "index": transaction.index,
                "protocol": transaction.protocol,
                "occurrence": transaction.occurrence,
            }
            context = f"Task {self.task_id}, flow {flow_id}, index {transaction.index}"
            detail: dict[str, Any] = {}
            if transaction.request is None:
                self.diagnostics.append(
                    f"{context}: {transaction.protocol.upper()} response without request; "
                    f"request details omitted from ontology; see {transaction.protocol.upper()} evidence."
                )
            if flow_id not in flow_ids:
                continue
            if transaction.request is None:
                request_details.setdefault(flow_id, []).append((detail, identity))
                continue
            if transaction.protocol == "dns":
                dns_req = transaction.request
                dns_res = transaction.response or {}
                questions = dns_req.get("questions", [])
                domain = (dns_req.get("domains") or [None])[0]
                if not domain and questions:
                    domain = questions[0].get("name", "")
                raw_type = questions[0].get("type") if questions else None
                lookup_type = _normalize_dns_lookup_type(raw_type)
                # Keep one transaction even when its DNS fields cannot be exported.
                if lookup_type is None:
                    self.diagnostics.append(
                        f"Task {self.task_id}, flow {flow_id}: unsupported DNS question type {raw_type!r}; "
                        "DNS details omitted from ontology; see DNS evidence."
                    )
                elif domain:
                    dns_details = {
                        "domain": domain,
                        "resolved_ips": dns_res.get("ip") or None,
                        "resolved_domains": dns_res.get("domains") or None,
                        "lookup_type": lookup_type,
                    }
                    try:
                        NetworkDNSModel(dns_details)
                    except (ValueError, TypeError) as exc:
                        self.diagnostics.append(
                            f"Task {self.task_id}, flow {flow_id}: invalid DNS details ({type(exc).__name__}); "
                            "DNS details omitted from ontology; see DNS evidence."
                        )
                    else:
                        detail["dns_details"] = dns_details
                else:
                    self.diagnostics.append(
                        f"Task {self.task_id}, flow {flow_id}: missing DNS question domain; "
                        "DNS details omitted from ontology; see DNS evidence."
                    )
            else:
                http_req = transaction.request
                http_res = transaction.response or {}
                # Triage reports carry no HTTP message content: request/response hold
                # only the start lines and stream is the HTTP/2 stream number, so the
                # body fields stay unset. Full content is only in the task PCAP.
                http_details = {
                    "request_uri": http_req.get("url", ""),
                    "request_method": http_req.get("method", "GET"),
                    "response_status_code": http_res.get("status") or None,
                }
                for kind, half in (("request", http_req), ("response", http_res)):
                    # Drop only the header names AL cannot store; the raw evidence keeps them.
                    headers, dropped = _parse_http_headers(half.get("headers"))
                    http_details[f"{kind}_headers"] = headers
                    if dropped:
                        self.diagnostics.append(
                            f"{context}: {dropped} HTTP {kind} header(s) with unsupported names "
                            "omitted from ontology; see HTTP evidence."
                        )
                http_details["response_content_mimetype"] = _response_mimetype(http_res.get("headers"))
                try:
                    if not http_details["request_uri"]:
                        raise ValueError("Missing HTTP request URI")
                    http_details = NetworkHTTPModel(http_details).as_primitives()
                except (KeyError, ValueError, TypeError) as exc:
                    self.diagnostics.append(
                        f"{context}: invalid HTTP details ({type(exc).__name__}); "
                        "HTTP details omitted from ontology; see HTTP evidence."
                    )
                else:
                    detail["http_details"] = http_details
            request_details.setdefault(flow_id, []).append((detail, identity))

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
                "time_observed": self.__relative_time_str(f.get("first_seen"), f"flow {f['id']} first_seen"),
            }
            try:
                if ip_address(_src_ip).is_private and ip_address(_dst_ip).is_global:
                    flow["direction"] = "outbound"
            except ValueError:
                pass
            owner = self.__record_process(f)
            if owner is not None:
                flow["process"] = owner

            # Triage sets flow.domain to the raw destination IP when no hostname
            # is resolved; AL rejects IPs in network.dynamic.domain
            domain = f.get("domain")
            if isinstance(domain, str) and domain:
                try:
                    ip_address(domain)
                    self.network_tags.append(("network.dynamic.ip", domain))
                except ValueError:
                    # Guest hostnames are single-label; AL's domain tag rejects them
                    try:
                        _DOMAIN_FIELD.check(domain)
                    except ValueError:
                        self.untagged_flow_domains.append(domain)
                    else:
                        self.network_tags.append(("network.dynamic.domain", domain))

            # TLS fingerprints → network tags
            for triage_key, tag_type in (
                ("tls_ja3", "network.tls.ja3_hash"),
                ("tls_ja3s", "network.tls.ja3s_hash"),
                ("tls_sni", "network.tls.sni"),
            ):
                if f.get(triage_key):
                    self.network_tags.append((tag_type, f[triage_key]))

            self.flow_dict[f["id"]] = flow

        for flow_id, base_flow in self.flow_dict.items():
            for req_detail, identity in request_details.get(flow_id) or [({}, None)]:
                flow = {**base_flow, **req_detail}
                if "http_details" in flow:
                    flow["connection_type"] = "http"
                if "dns_details" in flow:
                    flow["connection_type"] = "dns"
                self.__add_network_connection(flow, flow_id, identity)

    def __add_network_connection(self, flow: dict[str, Any], flow_id: Any, identity: dict[str, Any] | None) -> None:
        # Keep repeated requests distinct even when their request fields are identical.
        occurrence = get_dict_fingerprint_hash({"session": self.session, "flow": flow_id, "transaction": identity})
        oid = f"{NetworkConnectionModel.get_oid(flow)}_{occurrence}"
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
                request_headers=d.get("request_headers") or None,
                response_headers=d.get("response_headers") or None,
                response_status_code=d.get("response_status_code"),
            )
            if d.get("response_content_mimetype"):
                # The helper has no parameter for this ODM field and update() ignores
                # undeclared attributes; as_primitives() exports every attribute set.
                flow["http_details"].response_content_mimetype = d["response_content_mimetype"]  # ty: ignore[unresolved-attribute]
        if isinstance(flow.get("dns_details"), dict):
            d = cast(dict[str, Any], flow["dns_details"])
            flow["dns_details"] = NetworkDNS(
                domain=d["domain"],
                resolved_ips=d.get("resolved_ips") or None,  # ty: ignore[invalid-argument-type]
                resolved_domains=d.get("resolved_domains") or None,  # ty: ignore[invalid-argument-type]
                lookup_type=d["lookup_type"],
            )
        owner = flow.pop("process", None)
        connection = NetworkConnection(objectid=object_id, **flow)
        self.ontology.add_network_connection(connection)
        # The helper re-resolves owners through its GUID map, which set_processes() does
        # not populate; attach the procid-resolved instance after adding.
        connection.set_process(owner)

    def __add_signatures(self) -> None:
        for sig in self.signatures:
            # Only trust yara_rule for genuine static YARA matches (sample or memory dump).
            # A behavioral signature can carry a yara_rule on a *file* indicator too, and
            # that must not override the behavior's own name.
            yara_rule = next(
                (
                    i["yara_rule"]
                    for i in sig.get("indicators", [])
                    if i.get("yara_rule") and _is_static_yara_resource(i.get("resource"))
                ),
                None,
            )
            name = (
                sig.get("label")
                or yara_rule
                or sig.get("name", "")
                .replace("Suspicious behavior: ", "")
                .replace("use of ", "")
                .replace(" ", "_")
                .lower()
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
            # Capture human-readable description for display in result sections.
            # When the yara_rule was used as the name, the verbose original "name" (the
            # rule's description text) has nowhere else to go, so surface it as the description.
            # Failing that, Triage often still provides per-indicator description/ioc text
            # (e.g. "PID 3396 wrote to memory of 4436") even when the signature has no "desc".
            indicator_texts = list(dict.fromkeys(t for i in sig.get("indicators", []) if (t := _indicator_text(i))))
            description = (
                sig.get("desc")
                or (sig.get("name") if name == yara_rule else None)
                or ("\n".join(indicator_texts) if indicator_texts else None)
            )
            # A repeated signature without its own explanation must not replace an earlier one;
            # its indicator evidence is kept in the indicator rows instead.
            if description and (sig.get("desc") or name not in self.signature_descriptions):
                self.signature_descriptions[name] = description
            registry_keys = self.signature_registry_keys.setdefault(name, [])
            for indicator in sig.get("indicators", []):
                registry_key = _normalize_registry_key(indicator.get("ioc") or "")
                if registry_key and registry_key not in registry_keys:
                    registry_keys.append(registry_key)
            if not registry_keys:
                del self.signature_registry_keys[name]
            rows = self.signature_indicators.setdefault(name, [])
            # Signatures can carry tens of thousands of indicators, so deduplicate through
            # key sets rather than list scans or the helper's add_attribute(), which
            # compares every existing attribute's primitives.
            seen_rows, seen_attributes = self._indicator_keys.setdefault(name, (set(), set()))
            for indicator in sig.get("indicators", []):
                source_process = self.__process_for(indicator.get("procid"))
                target_process = self.__process_for(indicator.get("procid_target"))
                row = _indicator_row(
                    indicator,
                    self.__process_label(indicator, "procid", "pid"),
                    self.__process_label(indicator, "procid_target", "pid_target"),
                )
                row_key = tuple(row.values())
                if any(row_key) and row_key not in seen_rows:
                    seen_rows.add(row_key)
                    rows.append(row)
                if source_process is not None:
                    target = target_process if target_process is not source_process else None
                    meta = _indicator_text(indicator)
                    attribute_key = (id(source_process), id(target), meta)
                    if attribute_key not in seen_attributes:
                        seen_attributes.add(attribute_key)
                        # No action is set: indicators do not state how source relates to target.
                        al_sig.attributes.append(
                            Attribute(
                                source=cast(Any, source_process).objectid,
                                target=cast(Any, target).objectid if target is not None else None,
                                meta=meta,
                            )
                        )
                # For "program_crash", procid is the crash-reporting process (e.g. WerFault.exe)
                # and procid_target is the process that actually crashed — surface the latter
                # separately so it can be rendered as its own process list.
                if name == "program_crash" and target_process is not None:
                    self.crashed_processes.setdefault(name, []).append(cast(Any, target_process))
            if not rows:
                del self.signature_indicators[name]

    def __resource_process(self, resource: Any) -> Any:
        """Resolve an extraction resource to the process instance its dump record names."""
        prefix = f"{self.task_id}/"
        if not isinstance(resource, str) or not resource.startswith(prefix):
            return None
        name = resource[len(prefix) :]
        dump = next((d for d in self.dumped or [] if isinstance(d, dict) and d.get("name") == name), None)
        return self.__record_process(dump) if dump is not None else None

    def __add_extracted(self) -> None:
        for item in self.extracted or []:
            if item.get("config"):
                try:
                    filtered = _filter_config(item["config"])
                    mc = Config(**filtered).create_MalwareConfig()
                    if _has_config_content(filtered):
                        self.malware_config.append(mc)
                        self.configs.append(item["config"])
                        self.config_resources.append(item.get("resource"))
                except Exception as exc:
                    # Isolate untrusted config conversion, including ODM validation errors.
                    self.diagnostics.append(f"Task {self.task_id}: invalid malware config ({type(exc).__name__}).")
                # Rule evidence is independent of ancillary config conversion. Only
                # valid signature metadata may proceed when the config was rejected.
                cfg = item["config"]
                if (
                    isinstance(cfg, dict)
                    and isinstance(cfg.get("rule"), str)
                    and cfg["rule"]
                    and (cfg.get("family") is None or isinstance(cfg["family"], str))
                ):
                    name = item["config"]["rule"]
                    data = {"name": name, "type": "CUCKOO"}
                    tag = SignatureModel.get_tag(data)
                    oid = SignatureModel.get_oid(data)
                    score = 1000
                    families = [(item["config"].get("family") or "").strip().upper() or "UNKNOWN"]
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
                    source = self.__resource_process(item.get("resource"))
                    if source is not None:
                        al_sig.add_attribute(Attribute(source=cast(Any, source).objectid))
                    self.ontology.add_signature(al_sig)
            if item.get("ransom_note"):
                self.malware_config.append(Ransom(**item["ransom_note"]).create_MalwareConfig())
            if item.get("credentials"):
                self.malware_config.append(Credentials(**item["credentials"]).create_MalwareConfig())

    def __post_init__(self) -> None:
        self.start_time = _analysis_time(self.analysis["submitted"])
        self.end_time = _analysis_time(self.analysis["reported"])
        if self.end_time < self.start_time:
            raise ValueError("Analysis reported time precedes submitted time")
        duration = self.end_time - self.start_time
        self._duration_ms = (duration.days * 86400 + duration.seconds) * 1000 + duration.microseconds // 1000
        self.session = f"{self.sample['id']}/{self.task_id}"
        self.network_tags: List[tuple] = []  # type: ignore[type-arg]
        self.untagged_flow_domains: list[str] = []
        self.malware_config: List[MalwareConfig] = []
        self.diagnostics: list[str] = []
        self.dns_evidence: list[dict[str, Any]] = []
        self.http_evidence: list[dict[str, Any]] = []
        self.configs: list[dict[str, Any]] = []
        self.config_resources: list[Optional[str]] = []
        # Maps procid → its process instance. The OS can reuse a pid within a task, so
        # signatures, flows and parents resolve through procid rather than pid lookups.
        self._procid_process: dict[int, Any] = {}
        self._pid_instances: dict[Any, list[Any]] = {}
        self.process_rows: list[dict[str, Any]] = []
        # Maps normalized signature name → human-readable description (sig.desc)
        self.signature_descriptions: dict[str, str] = {}
        # Maps normalized signature name → normalized registry keys touched (dynamic.registry_key)
        self.signature_registry_keys: dict[str, List[str]] = {}
        # Maps normalized signature name → distinct per-indicator evidence rows
        self.signature_indicators: dict[str, list[dict[str, Any]]] = {}
        self._indicator_keys: dict[str, tuple[set[tuple[Any, ...]], set[tuple[Any, ...]]]] = {}
        # Maps normalized signature name → processes it reports as crashed (program_crash only)
        self.crashed_processes: dict[str, List[Process]] = {}
        self.__add_sandbox()
        if self.processes:
            self.__add_processes()
        if self.network:
            self.__add_network()
        if self.signatures:
            self.__add_signatures()
        if self.extracted:
            self.__add_extracted()
        # OntologyResults requires an open-ended sentinel while correlating process
        # lifetimes. Clear it once mapping is complete, before either ontology or UI
        # serialization. Network references share these same Process objects.
        for process in self.ontology.get_processes():
            if process.end_time == MAX_TIME:
                cast(Any, process).end_time = None


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
    diagnostics: list[str] = field(default_factory=list, init=False)
    parse_error: Optional[Exception] = field(default=None, init=False, repr=False)

    def get_task_reports(self, client: TriageClient) -> None:
        self.task_reports = []
        self.diagnostics = []
        self.parse_error = None
        if self.status == "failed":
            self.diagnostics.append("Sample analysis failed; recovered evidence is incomplete.")
        fetch_error: Optional[Exception] = None
        for task in self.tasks:
            if task["id"].startswith("behavioral"):
                if task["status"] not in {"reported", "failed"}:
                    self.diagnostics.append(f"Task {task['id']}: {task['status']}; no behavioral report processed.")
                    continue
                if task["status"] == "failed":
                    self.diagnostics.append(
                        f"Task {task['id']}: failed execution ({task.get('failure') or 'reason unavailable'}); "
                        "analysis incomplete."
                    )
                # One bounded HTTP request per eligible task, including failed tasks.
                try:
                    api_response = client.task_report(self.id, task["id"])
                except (ServerError, RequestException, ValueError) as exc:
                    if isinstance(exc, ServerError) and exc.status == 404:
                        self.diagnostics.append(f"Task {task['id']}: report unavailable (HTTP 404).")
                        # A failed task may never have produced a report. A reported
                        # task's missing report still retains the previous outage behavior.
                        if task["status"] == "reported":
                            fetch_error = exc
                    else:
                        fetch_error = exc
                        self.diagnostics.append(f"Task {task['id']}: report fetch failed ({type(exc).__name__}).")
                    continue
                try:
                    filtered = {k: v for k, v in api_response.items() if k in _EXPECTED_REPORT_FIELDS}
                    report = DynamicReport(
                        task_id=task["id"],
                        ontology=OntologyResults(service_name=SERVICE_NAME),
                        **filtered,
                    )
                except (KeyError, TypeError, ValueError, AttributeError) as exc:
                    self.parse_error = exc
                    self.diagnostics.append(f"Task {task['id']}: report could not be parsed ({type(exc).__name__}).")
                    continue
                self.task_reports.append(report)
                if report.diagnostics:
                    self.diagnostics.append(f"Task {task['id']}: report partially parsed; valid evidence retained.")
                self.diagnostics.extend(report.diagnostics)
                for error in api_response.get("errors") or []:
                    self.diagnostics.append(f"Task {task['id']}: {error.get('reason') or 'unspecified analysis error'}")

        # Partial evidence remains useful, but a total fetch outage must not become
        # a successful, cacheable analysis. Missing reports on explicitly failed
        # tasks are expected; transport/server failures remain fetch errors.
        if fetch_error is not None and not self.task_reports:
            raise fetch_error


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


def _has_config_content(value: Any) -> bool:
    """Ignore empty containers and credential protocol placeholders, retaining zero/false settings."""
    if isinstance(value, dict):
        return any(_has_config_content(v) for k, v in value.items() if k not in {"protocol", "rule", "tags"})
    if isinstance(value, list):
        return any(_has_config_content(v) for v in value)
    if isinstance(value, str):
        return bool(value.strip())
    return value is not None


def _filter_sample(sample: dict) -> dict:  # type: ignore[type-arg]
    """Return only keys accepted by the Sample dataclass; drops unknown future Triage sample
    fields (e.g. user_id) so Sample construction never raises TypeError."""
    accepted = {f.name for f in fields(Sample) if f.init}
    return {k: v for k, v in sample.items() if k in accepted}


class TriageResult:
    def __init__(self, client: TriageClient, sample: dict) -> None:  # type: ignore[type-arg]
        self.sample = Sample(**_filter_sample(sample))
        self.sample.get_task_reports(client)
        self.diagnostics = list(self.sample.diagnostics)
        self.malware_config = list(itertools.chain.from_iterable(r.malware_config for r in self.sample.task_reports))

        # Configs already recovered from behavioral reports (dedup key: canonical JSON of filtered config)
        behavioral_config_keys: set[str] = set()
        for report in self.sample.task_reports:
            for cfg in report.configs:
                key = json.dumps(_filter_config(cfg), sort_keys=True)
                behavioral_config_keys.add(key)

        # Collect seen signature names across all behavioral tasks (for overview dedup)
        behavioral_sig_names: set[str] = set()
        for report in self.sample.task_reports:
            for sig in report.signatures or []:
                name = sig.get("label") or sig.get("name", "")
                if name:
                    behavioral_sig_names.add(name)

        self.overview_configs: list[dict] = []  # type: ignore[type-arg]
        self.overview_config_resources: list[Optional[str]] = []
        self.overview_signatures: list[dict] = []  # type: ignore[type-arg]

        try:
            overview = client.overview_report(self.sample.id)
        except Exception as exc:
            self.diagnostics.append(f"Overview report unavailable ({type(exc).__name__}).")
            overview = {}

        if overview:
            for item in overview.get("extracted") or []:
                try:
                    cfg = item.get("config") or {}
                    filtered = _filter_config(cfg)
                    if not _has_config_content(filtered):
                        continue
                    key = json.dumps(filtered, sort_keys=True)
                    if key in behavioral_config_keys:
                        continue  # already extracted from a behavioral report
                    mc = Config(**filtered).create_MalwareConfig()
                    self.malware_config.append(mc)
                    self.overview_configs.append(cfg)
                    self.overview_config_resources.append(item.get("resource"))
                    behavioral_config_keys.add(key)  # prevent double-adding if overview has dupes
                # Overview data is best-effort and may contain values rejected by
                # either the Config dataclass or Assemblyline ODM validation.
                except Exception as exc:
                    self.diagnostics.append(f"Overview: invalid malware config ({type(exc).__name__}).")

            for sig in overview.get("signatures") or []:
                name = sig.get("label") or sig.get("name", "")
                if name and name not in behavioral_sig_names:
                    self.overview_signatures.append(sig)
                    behavioral_sig_names.add(name)

        # A successful HTTP response can still contain an unusable report.
        # Allow overview recovery first, but do not cache an empty analysis after
        # parse failures. Expected missing reports on failed tasks remain informational.
        if (
            self.sample.parse_error is not None
            and not self.sample.task_reports
            and not self.overview_signatures
            and not self.overview_configs
        ):
            raise self.sample.parse_error
