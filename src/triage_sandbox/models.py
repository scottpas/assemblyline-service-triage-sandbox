from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, List, Optional

import regex
from assemblyline.odm.models.ontology.results.malware_config import (
    FTP,
    HTTP,
    Cryptocurrency,
    GeneralConnection,
    MalwareConfig,
)

from .constants import EXTRA_CONFIG_FIELDS, SERVICE_NAME
from .network import _split_addr


@dataclass
class Credentials:
    protocol: str
    username: str
    password: str
    flow: Optional[int] = None
    host: Optional[str] = None
    port: Optional[int] = None

    def create_MalwareConfig(self) -> MalwareConfig:
        data: dict[str, Any] = {"config_extractor": SERVICE_NAME, "family": ["UNKNOWN"]}
        if self.protocol == "ftp":
            ftp_data: dict[str, Any] = {
                "username": self.username,
                "password": self.password,
                "hostname": self.host,
            }
            if self.port is not None:
                ftp_data["port"] = int(self.port)
            data["ftp"] = [FTP(data=ftp_data).as_primitives()]
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
        data: dict[str, Any] = {"config_extractor": SERVICE_NAME, "family": [self.family.upper()]}
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
                        except Exception:
                            continue
            if http:
                data["http"] = http
            if tcp:
                data["tcp"] = tcp
        if self.wallet:
            data["cryptocurrency"] = [Cryptocurrency(data={"address": addr}) for addr in self.wallet]
        if self.credentials:
            data["ftp"] = [
                FTP(
                    data={
                        "password": cred.get("password"),
                        "hostname": cred.get("host"),
                        "port": cred.get("port"),
                    }
                )
                for cred in self.credentials
                if cred.get("protocol") == "ftp"
            ]
            if not self.family:
                data["family"] = ["UNKNOWN"]
        other: dict[str, Any] = {}
        for field in EXTRA_CONFIG_FIELDS:
            value = getattr(self, field)
            if value is not None:
                other[field] = value
        data["other"] = other
        return MalwareConfig(data=data)
