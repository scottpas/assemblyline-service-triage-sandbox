from dataclasses import asdict, dataclass
from ipaddress import ip_address
from typing import Any

import regex
from assemblyline import odm
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

_EMAIL_FIELD = odm.Email()
_URI_FIELD = odm.URI()
# Note fields are raw scraped text that often still holds HTML; the literal value is kept
# as evidence and only addresses found inside it become indicators.
_EMBEDDED_EMAIL = regex.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_EMBEDDED_URL = regex.compile(r"""https?://[^\s<>"'`]+""", regex.IGNORECASE)
# Notes written as HTML carry doctype and namespace URLs that are not contact infrastructure.
_MARKUP_URL_PREFIX = regex.compile(r"https?://www\.w3\.org/", regex.IGNORECASE)


def clean_text(value: Any) -> str | None:
    """Return displayable text; Triage note and script dumps can carry NUL padding."""
    if not isinstance(value, str):
        return None
    return value.replace("\x00", "").strip() or None


def string_values(value: Any) -> list[str]:
    """Return the distinct non-empty strings of an untrusted string-or-list field."""
    values = value if isinstance(value, list) else [value]
    return list(dict.fromkeys(v for v in values if isinstance(v, str) and v))


def _embedded_emails(text: str) -> list[str]:
    found = []
    for match in _EMBEDDED_EMAIL.findall(text):
        try:
            found.append(_EMAIL_FIELD.check(match))
        except ValueError:
            continue
    return found


def _embedded_urls(text: str) -> list[str]:
    found = []
    for match in _EMBEDDED_URL.findall(text):
        url = match.rstrip(".,;:)]}!?")
        if _MARKUP_URL_PREFIX.match(url):
            continue
        try:
            found.append(_URI_FIELD.check(url))
        except ValueError:
            continue
    return found


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
    username: str | None = None
    password: str | None = None
    flow: int | None = None
    host: str | None = None
    port: int | None = None
    email_to: Any | None = None

    def create_MalwareConfig(self) -> MalwareConfig | None:
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

    note: str | None = None
    family: str | None = None
    target: str | None = None
    emails: list[str] | None = None
    wallets: list[str] | None = None
    urls: list[str] | None = None
    contact: list[str] | None = None

    def has_content(self) -> bool:
        """Report whether any field holds usable text, so an empty record makes no config."""
        return bool(
            clean_text(self.note)
            or clean_text(self.family)
            or clean_text(self.target)
            or string_values(self.emails)
            or string_values(self.wallets)
            or string_values(self.urls)
            or string_values(self.contact)
        )

    def contact_rows(self) -> list[dict[str, str]]:
        """Pair each original contact value with the validated indicators found inside it."""
        rows: dict[tuple[str, str], dict[str, str]] = {}
        for label, values, finders in (
            ("Email", self.emails, (_embedded_emails,)),
            ("URL", self.urls, (_embedded_urls,)),
            ("Contact", self.contact, (_embedded_emails, _embedded_urls)),
            ("Wallet", self.wallets, ()),
        ):
            for value in string_values(values):
                indicators = dict.fromkeys(found for finder in finders for found in finder(value))
                rows[(label, value)] = {"Type": label, "Value": value, "Indicator": ", ".join(indicators)}
        return list(rows.values())

    def indicators(self) -> tuple[list[str], list[str]]:
        """Return the distinct validated email addresses and URLs named by the note's contact fields."""
        emails = [*string_values(self.emails), *string_values(self.contact)]
        urls = [*string_values(self.urls), *string_values(self.contact)]
        return (
            list(dict.fromkeys(found for value in emails for found in _embedded_emails(value))),
            list(dict.fromkeys(found for value in urls for found in _embedded_urls(value))),
        )

    def create_MalwareConfig(self) -> MalwareConfig:
        family = (clean_text(self.family) or "UNKNOWN").upper()
        data: dict[str, Any] = {"config_extractor": SERVICE_NAME, "family": [family], "category": ["ransomware"]}
        wallets = string_values(self.wallets)
        if wallets:
            data["cryptocurrency"] = [
                Cryptocurrency(data={"address": wallet, "usage": "ransomware"}) for wallet in wallets
            ]
        _, urls = self.indicators()
        if urls:
            data["http"] = [HTTP(data={"uri": url, "usage": "ransom"}) for url in urls]
        # MalwareConfig has no note or contact fields; retain the original values for provenance.
        other: dict[str, Any] = {
            name: values
            for name, values in (
                ("emails", string_values(self.emails)),
                ("urls", string_values(self.urls)),
                ("contact", string_values(self.contact)),
            )
            if values
        }
        for name, value in (("note", clean_text(self.note)), ("target", clean_text(self.target))):
            if value:
                other[name] = value
        if other:
            data["other"] = other
        return MalwareConfig(data=data)


@dataclass
class Config:
    family: str | None = None
    tags: list[str] | None = None
    rule: str | None = None
    c2: list[str] | None = None
    version: str | None = None
    botnet: str | None = None
    campaign: str | None = None
    mutex: list[str] | None = None
    decoy: list[str] | None = None
    wallet: list[str] | None = None
    dns: list[str] | None = None
    keys: list[dict] | None = None  # type: ignore[type-arg]
    webinject: list[str] | None = None
    command_lines: list[str] | None = None
    listen_addr: str | None = None
    listen_port: int | None = None
    listen_for: list[str] | None = None
    shellcode: list[bytearray] | None = None
    extracted_pe: list[str] | None = None
    credentials: list[dict] | None = None  # type: ignore[type-arg]
    attr: dict | None = None  # type: ignore[type-arg]
    raw: str | None = None

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
