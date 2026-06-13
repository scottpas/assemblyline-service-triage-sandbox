import json
import os
import tempfile
from typing import Any, cast

from assemblyline.odm.models.ontology.results import NetworkConnection as NetworkConnectionModel
from assemblyline.odm.models.ontology.results import Process as ProcessModel
from assemblyline.odm.models.ontology.results import Sandbox as SandboxModel
from assemblyline.odm.models.ontology.results import Signature as SignatureModel
from assemblyline.odm.models.ontology.results.malware_config import MalwareConfig
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults, extract_iocs_from_text_blob
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, ResultTableSection
from retrying import RetryError, retry
from triage import Client as TriageClient
from triage.client import ServerError

from .constants import SUPPORTED_FILE_TYPES
from .report import TriageResult

_PROCESS_MODEL_FIELDS = frozenset(ProcessModel.fields())

TRIAGE_POLL_DELAY = 10
try:
    MAX_ANALYSIS_TIMEOUT = int(os.environ["MAX_ANALYSIS_TIMEOUT"])
except KeyError:
    MAX_ANALYSIS_TIMEOUT = 600


def _filter_process_prims(prims: dict) -> dict:  # type: ignore[type-arg]
    return {k: v for k, v in prims.items() if k in _PROCESS_MODEL_FIELDS}


def _attach_dynamic_ontology(service: ServiceBase, ontres: OntologyResults) -> None:
    for process in ontres.get_processes():
        service.ontology.add_result_part(cast(Any, ProcessModel), _filter_process_prims(process.as_primitives()))
    for sandbox in ontres.get_sandboxes():
        service.ontology.add_result_part(cast(Any, SandboxModel), sandbox.as_primitives())
    for sig in ontres.get_signatures():
        service.ontology.add_result_part(cast(Any, SignatureModel), sig.as_primitives())
    for nc in ontres.get_network_connections():
        nc_prims = nc.as_primitives()
        if nc_prims.get("process"):
            nc_prims["process"] = _filter_process_prims(nc_prims["process"])
        service.ontology.add_result_part(cast(Any, NetworkConnectionModel), nc_prims)


def _is_submission_not_reported(submission: dict | None) -> bool:  # type: ignore[type-arg]
    if not submission:
        return True
    return submission.get("status") != "reported"


def _retry_on_not_found(exception: Exception) -> bool:
    return isinstance(exception, ServerError) and exception.status == 404


@retry(
    wait_fixed=TRIAGE_POLL_DELAY * 1000,
    stop_max_delay=MAX_ANALYSIS_TIMEOUT * 1000,
    stop_max_attempt_number=(MAX_ANALYSIS_TIMEOUT / TRIAGE_POLL_DELAY),
    retry_on_result=_is_submission_not_reported,
    retry_on_exception=_retry_on_not_found,
)
def wait_for_submission(service: Any, submission_id: str) -> dict:  # type: ignore[type-arg]
    submission = service.client.sample_by_id(submission_id)
    service.log.info(f"{submission['id']} status: {submission['status']}")
    return submission


class TriageSandbox(ServiceBase):
    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        root_url: str = self.config.get("root_url") or ""
        self.web_url = root_url.replace("api.", "").replace("/api", "").rstrip("/")

    def search_triage(self, request: ServiceRequest) -> dict | None:  # type: ignore[type-arg]
        submission = None
        try:
            if request.task.fileinfo.uri_info and request.get_param("submit_as_url"):
                submission = self.client.search(query=f'url:"{request.task.fileinfo.uri_info.uri}"', max=1).__next__()
            else:
                submission = self.client.search(query=f"sha256:{request.sha256}", max=1).__next__()
            self.log.debug(f"Submission: {submission['id']}")
        except StopIteration:
            self.log.debug(f"Existing sample not found: {request.sha256}")
        return submission

    def submit_triage(self, request: ServiceRequest) -> dict | None:  # type: ignore[type-arg]
        submission = None
        if request.task.fileinfo.uri_info and request.get_param("submit_as_url"):
            submission = self.client.submit_sample_url(url=request.task.fileinfo.uri_info.uri)
        elif request.file_type in SUPPORTED_FILE_TYPES:
            with open(request.file_path, "rb") as fh:
                submission = self.client.submit_sample_file(
                    filename=request.file_name,
                    file=fh,
                    network=request.get_param("network"),
                    timeout=request.get_param("analysis_timeout_in_seconds"),
                )
        return submission

    def start(self) -> None:
        self.log.info(f"start() from {self.service_attributes.name} service called")

    def execute(self, request: ServiceRequest) -> None:
        self.client = TriageClient(
            token=request.get_param("api_key") or self.config.get("api_key"), root_url=self.config.get("root_url")
        )
        self.allow_dynamic_submit = request.get_param("allow_dynamic_submit") and self.config.get(
            "allow_dynamic_submit"
        )
        try:
            submission = None
            if request.get_param("use_existing_submission"):
                self.log.debug("Searching for file...")
                submission = self.search_triage(request)
            if self.allow_dynamic_submit and not submission:
                self.log.debug("Submitting file...")
                submission = self.submit_triage(request)
            if not submission:
                self.log.info("File not found or submitted. Returning nothing.")
                return None
        except ServerError as e:
            self.log.error(f"Triage Server Error: {e.status} - {e.kind} - {e.message}")
            raise
        except Exception as e:
            self.log.error(e)
            raise

        try:
            wait_for_submission(service=self, submission_id=submission["id"])
            triage_result = TriageResult(self.client, self.client.sample_by_id(sample_id=submission["id"]))
            for mc in triage_result.malware_config:
                self.ontology.add_result_part(cast(Any, MalwareConfig), mc.as_primitives(strip_null=True))
            result = Result()
            sandbox_section = ResultSection("Sandbox Information")
            sandbox_section.add_line(f"URL: {self.web_url}/{triage_result.sample.id}")
            sandbox_section.add_line(f"Submitted: {triage_result.sample.submitted}")
            sandbox_section.add_line(f"Completed: {triage_result.sample.completed}")
            for task in triage_result.sample.task_reports:
                _attach_dynamic_ontology(self, task.ontology)
                task_section = ResultSection(f"Task: {task.task_id}")
                task_section.add_line(f"URL: {self.web_url}/{task.session}")
                process_tree = task.ontology.get_process_tree_result_section()
                process_tree.auto_collapse = True
                sigs_section = ResultSection(title_text="Signatures", auto_collapse=True)
                sig_subsections: dict[str, ResultSection] = {}
                for sig in task.ontology.get_signatures():
                    sig = cast(Any, sig)
                    name = sig.name.upper()
                    if name in sig_subsections:
                        for attr in sig.attributes:
                            if attr.source.ontology_id.startswith("process_"):
                                sig_subsections[name].add_tag(tag_type="dynamic.processtree_id", value=attr.source.tag)
                    else:
                        s = ResultSection(title_text=name)
                        s.add_tag(tag_type="dynamic.signature.name", value=name)
                        for f in sig.malware_families:
                            s.add_tag(tag_type="attribution.family", value=f)
                        score = sig.score
                        if score >= 1000:
                            s.set_heuristic(5, signature=name)
                        elif score >= 800:
                            s.set_heuristic(4, signature=name)
                        elif score >= 500:
                            s.set_heuristic(3, signature=name)
                        elif score >= 100:
                            s.set_heuristic(2, signature=name)
                        else:
                            s.set_heuristic(1, signature=name)
                        for attr in sig.attributes:
                            if attr.source.ontology_id.startswith("process_"):
                                s.add_tag(tag_type="dynamic.processtree_id", value=attr.source.tag)
                        sig_subsections[name] = s
                for sig_section in reversed(sorted(sig_subsections.values(), key=lambda s: s.heuristic.heur_id)):
                    sigs_section.add_subsection(sig_section)
                task_section.add_subsection(process_tree)
                task_section.add_subsection(sigs_section)
                ioc_section = ResultTableSection(title_text="Network IOCs", auto_collapse=True)
                extract_iocs_from_text_blob(blob=json.dumps(task.network), result_section=ioc_section)
                for tag_type, value in task.network_tags:
                    ioc_section.add_tag(tag_type=tag_type, value=value)
                task_section.add_subsection(ioc_section)
                if task.analysis.get("ttp"):
                    ttp_section = ResultSection("ATT&CK Techniques", auto_collapse=True)
                    for t in task.analysis["ttp"]:
                        ttp_sub = ResultSection(title_text=t)
                        ttp_sub.set_heuristic(10, attack_id=t)
                        ttp_section.add_subsection(ttp_sub)
                    task_section.add_subsection(ttp_section)
                if task.extracted:
                    malware_section = ResultSection(title_text="Malware Config", auto_collapse=True)
                    for e in task.extracted:
                        if e.get("config", {}).get("c2"):
                            m = ResultTableSection(title_text=f"{e['config']['family'].upper()}")
                            extract_iocs_from_text_blob(blob=json.dumps(e["config"]), result_section=m)
                            m.set_heuristic(100, signature=e["config"]["family"].upper())
                            m.add_tag(tag_type="attribution.family", value=e["config"]["family"].upper())
                            m.add_subsection(
                                ResultSection(
                                    title_text="Raw Config",
                                    body_format="JSON",
                                    body=json.dumps(e["config"]),
                                    auto_collapse=True,
                                )
                            )
                            malware_section.add_subsection(m)
                    if malware_section.subsections:
                        task_section.add_subsection(malware_section)
                sandbox_section.add_subsection(task_section)
                if request.get_param("extract_pcap"):
                    try:
                        pcap = self.client._req_file(
                            method="GET", path=f"/v0/samples/{triage_result.sample.id}/{task.task_id}/dump.pcapng"
                        )
                        fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
                        with os.fdopen(fd, "wb") as fh:
                            fh.write(pcap)
                        request.add_extracted(
                            path=temp_path,
                            name=f"{triage_result.sample.id}-{task.task_id}-dump.pcapng",
                            description=f"PCAP file from task {triage_result.sample.id}-{task.task_id}",
                        )
                    except Exception as e:
                        self.log.error(e)
                if task.dumped and (request.get_param("extract_memdump") or request.get_param("extract_dropped_files")):
                    for dump in task.dumped:
                        if dump["kind"] == "region" and request.get_param("extract_memdump"):
                            self.log.debug(f"Downloading {dump['name']}")
                            try:
                                file_data = self.client._req_file(
                                    method="GET",
                                    path=f"/v0/samples/{triage_result.sample.id}/{task.task_id}/{dump['name']}",
                                )
                                fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
                                with os.fdopen(fd, "wb") as fh:
                                    fh.write(file_data)
                                request.add_extracted(
                                    path=temp_path,
                                    name=dump["name"],
                                    description=f"Memdump file from task {triage_result.sample.id}-{task.task_id}",
                                )
                            except Exception as e:
                                self.log.error(e)
                        if dump["kind"] == "martian" and request.get_param("extract_dropped_files"):
                            self.log.debug(f"Downloading {dump['name']}")
                            try:
                                file_data = self.client._req_file(
                                    method="GET",
                                    path=f"/v0/samples/{triage_result.sample.id}/{task.task_id}/{dump['name']}",
                                )
                                fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
                                with os.fdopen(fd, "wb") as fh:
                                    fh.write(file_data)
                                request.add_extracted(
                                    path=temp_path,
                                    name=dump["name"],
                                    description=f"Dropped file from task {triage_result.sample.id}-{task.task_id}",
                                )
                            except Exception as e:
                                self.log.error(e)
            result.add_section(sandbox_section)
            request.result = result
        except RetryError:
            self.log.error("Max retries exceeded for sample.")
            raise
