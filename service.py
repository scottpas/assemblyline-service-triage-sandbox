import json

import yaml
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
from triage.client import PrivateClient as TriagePrivateClient
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

TRIAGE_POLL_DELAY = 5


def _is_submission_reported(submission: dict) -> bool:
    if not submission:
        return True
    return False
    # return submission["status"] != "reported"


def strip_null(d: dict):
    # Source:
    # https://github.com/CybercentreCanada/assemblyline-service-configextractor/blob/master/configextractor_/configextractor_.py
    clean_config = {}
    for k, v in d.items():
        if v:
            if isinstance(v, dict):
                clean_config[k] = strip_null(v)
            elif isinstance(v, list) and isinstance(v[0], dict):
                clean_config[k] = [strip_null(vi) for vi in v]
            else:
                clean_config[k] = v
    return clean_config


class TriageSandbox(ServiceBase):
    def __init__(self, config=None):
        super(TriageSandbox, self).__init__(config)

    @retry(
        wait_fixed=TRIAGE_POLL_DELAY * 1000,
        stop_max_attempt_number=(600 / TRIAGE_POLL_DELAY),
        retry_on_result=_is_submission_reported
    )
    def wait_for_sample(self, submission_id):
        submission = self.client.sample_by_id(submission_id)
        self.log.info(f'{submission["id"]} status: {submission["status"]}')
        return submission

    def start(self):
        # ==================================================================
        # Startup actions:
        #   Your service might have to do some warming up on startup to make things faster
        # ==================================================================
        self.log.info(f"start() from {self.service_attributes.name} service called")
        self.client = TriageClient(token=self.config.get("api_key", None))
        self.allow_dyanmic_submit = self.config.get("allow_dynamic_submit", False)
        if self.config.get("private_client", False):
            self.client = TriagePrivateClient(token=self.config.get("api_key", None))

    def execute(self, request: ServiceRequest) -> None:
        try:
            submission = self.client.search(query=f"sha256:{request.sha256}", max=1).__next__()
            self.log.debug(f"Submission: {submission['id']}")
        except StopIteration:
            self.log.debug(f"Existing sample not found: {request.sha256}")
            if self.allow_dyanmic_submit:
                if request.file_type.startswith("uri"):
                    with open(request.file_path, "r") as f:
                        data = yaml.safe_load(f)
                    url = data.pop("uri")
                    submission = self.client.submit_sample_url(url=url)
                elif request.file_type in SUPPORTED_FILE_TYPES:
                    submission = self.client.submit_sample_file(
                        filename=request.file_name, file=open(request.file_path, "r"),
                        network=request.get_param("network"),
                        timeout=request.get_param("analysis_timeout_in_seconds"))
                else:
                    pass
        except ServerError as e:
            self.log.error(f"Triage Server Error: {e.status} - {e.kind} - {e.message}")
            raise
        except Exception as e:
            self.log.error(e)
            raise

        try:
            if submission["status"] != "reported":
                self.wait_for_sample(submission["id"])
            triage_result = TriageResult(self.client, self.client.sample_by_id(sample_id=submission["id"]))
            for i in triage_result.malware_config:
                self.ontology.add_result_part(MalwareConfig, i.as_primitives(strip_null=True))
            result = Result()
            sandbox_section = ResultSection("Sandbox Information")
            sandbox_section.add_line(f"URL: https://tria.ge/{triage_result.sample.id}")
            sandbox_section.add_line(f"Submitted: {triage_result.sample.submitted}")
            sandbox_section.add_line(f"Completed: {triage_result.sample.completed}")
            for task in triage_result.sample.task_reports:
                attach_dynamic_ontology(self, task.ontology)
                task_section = ResultSection(f"Task: {task.task_id}")
                task_section.add_line(f"URL: https://tria.ge/{task.session}")
                process_tree = task.ontology.get_process_tree_result_section()
                process_tree.auto_collapse = True
                sigs_section = ResultSection(title_text="Signatures")
                for sig in task.ontology.get_signatures():
                    name = sig.name.upper()
                    s = ResultSection(title_text=name)
                    # for section in sigs_section.subsections:
                    #     if section.title_text == name:
                    #         s = section
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
                    for a in sig.attacks:
                        a_section = ResultSection(title_text=f'ATT&CK Technique: {a["attack_id"]}', auto_collapse=True)
                        a_section.add_line(a["description"])
                        a_section.set_heuristic(10, attack_id=a["attack_id"])
                        s.add_subsection(a_section)
                    for attr in sig.attributes:
                        if attr.source.ontology_id.startswith("process_"):
                            s.add_tag(tag_type="dynamic.processtree_id", value=attr.source.tag)
                    sigs_section.add_subsection(s)
                task_section.add_subsection(process_tree)
                task_section.add_subsection(sigs_section)
                ioc_section = ResultTableSection(title_text="Network IOCs")
                extract_iocs_from_text_blob(blob=json.dumps(task.network), result_section=ioc_section)
                ioc_section.auto_collapse = True
                sandbox_section.add_subsection(ioc_section)
                if task.analysis.get("ttp"):
                    ttp_section = ResultSection("ATT&CK Techniques", auto_collapse=True)
                    for t in task.analysis["ttp"]:
                        s = ResultSection(title_text=t)
                        s.set_heuristic(10, attack_id=t)
                        ttp_section.add_subsection(s)
                for e in task.extracted:
                    if e.get("config", {}).get("c2", False):
                        m = ResultTableSection(title_text=f'Malware Config IOCs: {e["config"]["family"].upper()}')
                        extract_iocs_from_text_blob(blob=json.dumps(e["config"]), result_section=m)
                        m.set_heuristic(100, signature=e["config"]["family"].upper())
                        task_section.add_subsection(m)
                sandbox_section.add_subsection(task_section)
            result.add_section(sandbox_section)
            request.result = result
        except RetryError:
            self.log.error("Max retries exceeded for sample.")
