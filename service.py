import json
import os
import tempfile

from assemblyline.odm.models.ontology.results.malware_config import MalwareConfig
from assemblyline_service_utilities.common.dynamic_service_helper import (
    attach_dynamic_ontology,
    extract_iocs_from_text_blob,
)
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, ResultTableSection
from helper import TriageResult
from retrying import RetryError, retry
from triage import Client as TriageClient
from triage.client import ServerError

# Ontology Result Constants
SANDBOX_NAME = "Triage Sandbox"
SERVICE_NAME = "TriageSandbox"

# Derived from: https://tria.ge/docs/cloud-api/filetypes/
# TODO: support archive files
SUPPORTED_FILE_TYPES = [
    "android/apk",
    "android/dex",
    "code/batch",
    "code/hta",
    "code/html",
    "code/javascript",
    "code/jscript",
    "code/perl",
    "code/ps1",
    "code/python",
    "code/shell",
    "code/vbe",
    "code/vbs",
    "code/wsc",
    "code/wsf",
    "document/email",
    "document/installer/windows",
    "document/odt/chart",
    "document/odt/formula",
    "document/odt/graphics",
    "document/odt/presentation",
    "document/odt/spreadsheet",
    "document/odt/text",
    "document/odt/web",
    "document/office/email",
    "document/office/excel",
    "document/office/hwp",
    "document/office/mhtml",
    "document/office/ole",
    "document/office/onenote",
    "document/office/passwordprotected",
    "document/office/powerpoint",
    "document/office/recoverystore",
    "document/office/rtf",
    "document/office/unknown",
    "document/office/word",
    "document/pdf",
    "executable/linux/elf32",
    "executable/linux/elf64",
    "executable/mach-o",
    "executable/windows/arm/dll64",
    "executable/windows/arm/pe64",
    "executable/windows/com",
    "executable/windows/dll32",
    "executable/windows/dll64",
    "executable/windows/dos",
    "executable/windows/ia/dll64",
    "executable/windows/ia/pe64",
    "executable/windows/pe",
    "executable/windows/pe32",
    "executable/windows/pe64",
    "java/jar",
    "shortcut/web",
    "shortcut/windows"
]

TRIAGE_POLL_DELAY = 10
try:
    MAX_ANALYSIS_TIMEOUT = int(os.environ["MAX_ANALYSIS_TIMEOUT"])
except KeyError:
    MAX_ANALYSIS_TIMEOUT = 600  # Default to 600 seconds


def _is_submission_not_reported(submission: dict) -> bool:
    if not submission:
        return True
    else:
        return submission.get("status", "none") != "reported"


def _retry_on_not_found(exception: Exception) -> bool:
    return isinstance(exception, ServerError) and exception.status == 404


@retry(
    wait_fixed=TRIAGE_POLL_DELAY * 1000,
    stop_max_delay=MAX_ANALYSIS_TIMEOUT * 1000,
    stop_max_attempt_number=(MAX_ANALYSIS_TIMEOUT / TRIAGE_POLL_DELAY),
    retry_on_result=_is_submission_not_reported,
    retry_on_exception=_retry_on_not_found
)
def wait_for_submission(service, submission_id):
    submission = service.client.sample_by_id(submission_id)
    service.log.info(f'{submission["id"]} status: {submission["status"]}')
    return submission


class TriageSandbox(ServiceBase):
    def __init__(self, config=None):
        super(TriageSandbox, self).__init__(config)
        self.web_url = self.config.get("root_url").replace("api.", "").replace("/api", "").rstrip("/")

    def search_triage(self, request: ServiceRequest):
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

    def submit_triage(self, request: ServiceRequest):
        if request.task.fileinfo.uri_info and request.get_param("submit_as_url"):
            submission = self.client.submit_sample_url(url=request.task.fileinfo.uri_info.uri)
        elif request.file_type in SUPPORTED_FILE_TYPES:
            submission = self.client.submit_sample_file(
                filename=request.file_name, file=open(request.file_path, "rb"),
                network=request.get_param("network"),
                timeout=request.get_param("analysis_timeout_in_seconds"))
        return submission

    def start(self):
        # ==================================================================
        # Startup actions:
        #   Your service might have to do some warming up on startup to make things faster
        # ==================================================================
        self.log.info(f"start() from {self.service_attributes.name} service called")

    def execute(self, request: ServiceRequest) -> None:
        self.client = TriageClient(
            token=request.get_param("api_key") or self.config.get("api_key"),
            root_url=self.config.get("root_url")
        )
        self.allow_dynamic_submit = request.get_param(
            "allow_dynamic_submit") and self.config.get("allow_dynamic_submit")
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
            # If you don't have a submission by now, just return nothing.
            if not submission:
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
            for i in triage_result.malware_config:
                self.ontology.add_result_part(MalwareConfig, i.as_primitives(strip_null=True))
            result = Result()
            sandbox_section = ResultSection("Sandbox Information")
            sandbox_section.add_line(
                f'URL: {self.web_url}/{triage_result.sample.id}')
            sandbox_section.add_line(f"Submitted: {triage_result.sample.submitted}")
            sandbox_section.add_line(f"Completed: {triage_result.sample.completed}")
            for task in triage_result.sample.task_reports:
                attach_dynamic_ontology(self, task.ontology)
                task_section = ResultSection(f"Task: {task.task_id}")
                task_section.add_line(
                    f'URL: {self.web_url}/{task.session}')
                process_tree = task.ontology.get_process_tree_result_section()
                process_tree.auto_collapse = True
                sigs_section = ResultSection(title_text="Signatures", auto_collapse=True)
                sig_subsections = {}
                for sig in task.ontology.get_signatures():
                    name = sig.name.upper()
                    if sig_subsections.get(name, False):
                        for attr in sig.attributes:
                            if attr.source.ontology_id.startswith("process_"):
                                sig_subsections[name].add_tag(
                                    tag_type="dynamic.processtree_id",
                                    value=attr.source.tag
                                )
                    else:
                        s = ResultSection(title_text=name)
                        s.add_tag(tag_type="dynamic.signature.name", value=name)
                        for f in sig.malware_families:
                            s.add_tag(tag_type="attribution.family", value=f)
                        if not s.heuristic:
                            if sig.score == 1000:
                                s.set_heuristic(5, signature=name)
                            elif sig.score >= 800 and sig.score < 1000:
                                s.set_heuristic(4, signature=name)
                            elif sig.score >= 500 and sig.score < 800:
                                s.set_heuristic(3, signature=name)
                            elif sig.score >= 100 and sig.score < 500:
                                s.set_heuristic(2, signature=name)
                            elif sig.score >= 0 and sig.score < 100:
                                s.set_heuristic(1, signature=name)
                        for attr in sig.attributes:
                            if attr.source.ontology_id.startswith("process_"):
                                s.add_tag(tag_type="dynamic.processtree_id", value=attr.source.tag)
                        sig_subsections[name] = s
                for i in reversed(sorted(sig_subsections.values(), key=lambda value: value.heuristic.heur_id)):
                    sigs_section.add_subsection(i)
                task_section.add_subsection(process_tree)
                task_section.add_subsection(sigs_section)
                ioc_section = ResultTableSection(title_text="Network IOCs", auto_collapse=True)
                extract_iocs_from_text_blob(blob=json.dumps(task.network), result_section=ioc_section)
                task_section.add_subsection(ioc_section)
                if task.analysis.get("ttp"):
                    ttp_section = ResultSection("ATT&CK Techniques", auto_collapse=True)
                    for t in task.analysis["ttp"]:
                        s = ResultSection(title_text=t)
                        s.set_heuristic(10, attack_id=t)
                        ttp_section.add_subsection(s)
                if task.extracted:
                    malware_section = ResultSection(title_text="Malware Config", auto_collapse=True)
                    for e in task.extracted:
                        if e.get("config", {}).get("c2", False):
                            m = ResultTableSection(title_text=f'{e["config"]["family"].upper()}')
                            extract_iocs_from_text_blob(blob=json.dumps(e["config"]), result_section=m)
                            m.set_heuristic(100, signature=e["config"]["family"].upper())
                            m.add_tag(tag_type="attribution.family", value=e["config"]["family"].upper())
                            m.add_subsection(
                                ResultSection(
                                    title_text="Raw Config", body_format="JSON",
                                    body=json.dumps(e["config"]),
                                    auto_collapse=True))
                            malware_section.add_subsection(m)
                    if len(malware_section.subsections) > 0:
                        task_section.add_subsection(malware_section)
                sandbox_section.add_subsection(task_section)
                if request.get_param("extract_pcap"):
                    try:
                        pcap = self.client._req_file(
                            method="GET",
                            path=f"/v0/samples/{triage_result.sample.id}/{task.task_id}/dump.pcapng"
                        )
                        fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
                        with os.fdopen(fd, "wb") as f:
                            f.write(pcap)
                        request.add_extracted(
                            path=temp_path,
                            name=f"{triage_result.sample.id}-{task.task_id}-dump.pcapng",
                            description=f"PCAP file from task {triage_result.sample.id}-{task.task_id}"
                        )
                    except Exception as e:
                        self.log.error(e)
                if task.dumped and (request.get_param("extract_memdump") or request.get_param("extract_dropped_files")):
                    for i in task.dumped:
                        if i["kind"] == "region" and request.get_param("extract_memdump"):
                            self.log.debug(f"Downloading{i['name']}")
                            try:
                                file = self.client._req_file(
                                    method="GET",
                                    path=f"/v0/samples/{triage_result.sample.id}/{task.task_id}/{i['name']}"
                                )
                                fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
                                with os.fdopen(fd, "wb") as f:
                                    f.write(file)
                                request.add_extracted(
                                    path=temp_path,
                                    name=i["name"],
                                    description=f"Memdump file from task {triage_result.sample.id}-{task.task_id}"
                                )
                            except Exception as e:
                                self.log.error(e)
                        if i["kind"] == "martian" and request.get_param("extract_dropped_files"):
                            self.log.debug(f"Downloading{i['name']}")
                            try:
                                file = self.client._req_file(
                                    method="GET",
                                    path=f"/v0/samples/{triage_result.sample.id}/{task.task_id}/{i['name']}"
                                )
                                fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
                                with os.fdopen(fd, "wb") as f:
                                    f.write(file)
                                request.add_extracted(
                                    path=temp_path,
                                    name=i["name"],
                                    description=f"Dropped file from task {triage_result.sample.id}-{task.task_id}"
                                )
                            except Exception as e:
                                self.log.error(e)
            result.add_section(sandbox_section)
            request.result = result
        except RetryError:
            self.log.error("Max retries exceeded for sample.")
            raise
