from dataclasses import asdict, dataclass
from ipaddress import ip_address
from typing import Any, List, Optional

import regex
from assemblyline.odm.models.ontology.results.malware_config import (
    DNS,
    FTP,
    HTTP,
    SMTP,
    Cryptocurrency,
    Encryption,
    GeneralConnection,
    MalwareConfig,
    Path,
)

from .constants import EXTRA_CONFIG_FIELDS, SERVICE_NAME
from .network import _split_addr


def _credential_entry(cred: dict[str, Any]) -> tuple[str, FTP | SMTP] | None:
    """Convert one Triage credential record to its MalwareConfig protocol model.

    Returns None for protocols MalwareConfig has no model for, and for records with no usable content.
    """
    protocol = str(cred.get("protocol") or "").lower()
    if protocol not in ("ftp", "smtp"):
        return None
    entry: dict[str, Any] = {
        "username": cred.get("username"),
        "password": cred.get("password"),
        "hostname": cred.get("host"),
    }
    try:
        entry["port"] = int(cred["port"])
    except (KeyError, TypeError, ValueError):
        pass
    if protocol == "smtp":
        recipients = cred.get("email_to")
        if isinstance(recipients, str):
            recipients = [recipients]
        if isinstance(recipients, (list, tuple)):
            entry["mail_to"] = [r for r in recipients if isinstance(r, str) and r]
    if not any(entry.values()):
        return None
    return protocol, (SMTP if protocol == "smtp" else FTP)(data=entry)


@dataclass
class Credentials:
    protocol: str
    username: Optional[str] = None
    password: Optional[str] = None
    flow: Optional[int] = None
    host: Optional[str] = None
    port: Optional[int] = None
    email_to: Optional[Any] = None

    def create_MalwareConfig(self) -> Optional[MalwareConfig]:
        """Return None when there is nothing MalwareConfig can represent, rather than an empty UNKNOWN config."""
        converted = _credential_entry(asdict(self))
        if converted is None:
            return None
        protocol, entry = converted
        data: dict[str, Any] = {
            "config_extractor": SERVICE_NAME,
            "family": ["UNKNOWN"],
            protocol: [entry.as_primitives()],
        }
        if self.flow is not None:
            data["other"] = {"flow": self.flow}
        return MalwareConfig(data=data)


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

    def create_MalwareConfig(self) -> MalwareConfig:
        family = self.family.upper() if self.family else "UNKNOWN"
        data: dict[str, Any] = {"config_extractor": SERVICE_NAME, "family": [family], "category": ["ransomware"]}
        if self.wallets:
            data["cryptocurrency"] = [
                Cryptocurrency(data={"address": wallet, "usage": "ransomware"}) for wallet in self.wallets
            ]
        return MalwareConfig(data=data)


@dataclass
class Config:
    family: Optional[str] = None
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
    keys: Optional[List[dict]] = None  # type: ignore[type-arg]
    webinject: Optional[List[str]] = None
    command_lines: Optional[List[str]] = None
    listen_addr: Optional[str] = None
    listen_port: Optional[int] = None
    listen_for: Optional[List[str]] = None
    shellcode: Optional[List[bytearray]] = None
    extracted_pe: Optional[List[str]] = None
    credentials: Optional[List[dict]] = None  # type: ignore[type-arg]
    attr: Optional[dict] = None  # type: ignore[type-arg]
    raw: Optional[str] = None

    def create_MalwareConfig(self) -> MalwareConfig:
        family = (self.family or "").strip().upper() or "UNKNOWN"
        data: dict[str, Any] = {"config_extractor": SERVICE_NAME, "family": [family]}
        if self.version:
            data["version"] = self.version
        if self.campaign:
            data["campaign_id"] = [self.campaign]
        if self.botnet:
            data["identifier"] = [self.botnet]
        if self.mutex:
            data["mutex"] = self.mutex
        if self.c2:
            http: list[HTTP] = []
            tcp: list[GeneralConnection] = []
            for entry in self.c2:
                if regex.match(pattern="^https?://", string=entry):
                    http.append(HTTP(data={"uri": entry}))
                else:
                    try:
                        host, port_int = _split_addr(regex.sub(r"^\w+://", "", entry))
                    except (ValueError, IndexError):
                        continue
                    try:
                        ip_address(host)
                        tcp.append(GeneralConnection(data={"server_ip": host, "server_port": port_int, "usage": "c2"}))
                    except ValueError:
                        try:
                            tcp.append(
                                GeneralConnection(data={"server_domain": host, "server_port": port_int, "usage": "c2"})
                            )
                        # Triage config is untrusted and ODM validation can raise several
                        # exception types. A malformed entry must not discard valid C2s.
                        except Exception:  # nosec B112
                            continue
            if http:
                data["http"] = http
            if tcp:
                data["tcp"] = tcp
        if self.wallet:
            data["cryptocurrency"] = [Cryptocurrency(data={"address": addr}) for addr in self.wallet]
        for cred in self.credentials or []:
            converted = _credential_entry(cred)
            if converted is not None:
                data.setdefault(converted[0], []).append(converted[1])
        # Map config.keys[] → MalwareConfig.encryption[]
        encryptions: list[Encryption] = []
        for key_entry in self.keys or []:
            kind = key_entry.get("kind", "") or ""
            raw_value = key_entry.get("value")
            if raw_value is None:
                continue
            encryptions.append(
                Encryption(
                    data={
                        "algorithm": kind.split(".")[0] if kind else None,
                        "key": str(raw_value),
                        "usage": "config",
                    }
                )
            )
        # Map config.dns[] → MalwareConfig.dns[]
        dns_entries: list[DNS] = []
        for dns_str in self.dns or []:
            try:
                ip_address(dns_str)
                dns_entries.append(DNS(data={"ip": dns_str, "usage": "c2"}))
            except ValueError:
                dns_entries.append(DNS(data={"hostname": dns_str, "usage": "c2"}))
        # Map config.attr → paths[], sleep_delay, encryption[] (additive; attr stays in other for full context)
        attr = self.attr if isinstance(self.attr, dict) else {}
        paths: list[Path] = []
        _INSTALL_PATH_KEYS = ("install_folder", "install_file", "install_name", "subdirectory")
        for path_key in _INSTALL_PATH_KEYS:
            if attr.get(path_key):
                paths.append(Path(data={"path": str(attr[path_key]), "usage": "install"}))
        if attr.get("log_directory"):
            paths.append(Path(data={"path": str(attr["log_directory"]), "usage": "logs"}))
        for delay_key in ("delay", "reconnect_delay", "sleep_delay"):
            if isinstance(attr.get(delay_key), int):
                data["sleep_delay"] = attr[delay_key]
                break
        if attr.get("encryption_key"):
            enc_data: dict[str, Any] = {"key": str(attr["encryption_key"]), "usage": "config"}
            if attr.get("key_salt"):
                enc_data["salt"] = str(attr["key_salt"])
            encryptions.append(Encryption(data=enc_data))
        if encryptions:
            data["encryption"] = encryptions
        if dns_entries:
            data["dns"] = dns_entries
        if paths:
            data["paths"] = paths
        other: dict[str, Any] = {}
        for field in EXTRA_CONFIG_FIELDS:
            value = getattr(self, field)
            if value is not None:
                other[field] = value
        data["other"] = other
        return MalwareConfig(data=data)
