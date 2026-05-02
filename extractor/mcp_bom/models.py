from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Language(str, Enum):
    PYTHON = "python"
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"
    GO = "go"
    UNKNOWN = "unknown"


class CategoryResult(BaseModel):
    detected: bool = False
    confidence: Confidence = Confidence.LOW
    evidence: list[str] = Field(default_factory=list)
    depth_raw: float = 0.0
    depth_adjusted: float = 0.0

    sub_fields: dict[str, Any] = Field(default_factory=dict)


class FilesystemResult(CategoryResult):
    read: bool = False
    write: bool = False
    delete: bool = False
    scope: str = "unknown"


class ShellResult(CategoryResult):
    direct: bool = False
    sandboxed: bool = False
    shell_interpreted: bool = False
    arbitrary_args: bool = False
    code_evaluation_vector: str | None = None


class EgressResult(CategoryResult):
    arbitrary_host: bool = False
    allowlisted_host: bool = False
    fixed_remote_datastore: bool = False
    protocols: list[str] = Field(default_factory=list)


class IngressResult(CategoryResult):
    bind: str = "none"
    auth: str = "none"
    tls_enabled: bool = False


class SecretsResult(CategoryResult):
    read: bool = False
    write: bool = False
    scope: str = "none"


class DelegationResult(CategoryResult):
    static: bool = False
    dynamic: bool = False
    count: int = 0


class ImpersonationResult(CategoryResult):
    channels: list[str] = Field(default_factory=list)
    approval_gate: bool = True


class DataSensitivityResult(CategoryResult):
    categories: list[str] = Field(default_factory=list)
    redaction_declared: bool = False


CategoryResultType = (
    FilesystemResult
    | ShellResult
    | EgressResult
    | IngressResult
    | SecretsResult
    | DelegationResult
    | ImpersonationResult
    | DataSensitivityResult
)


class CapabilityVector(BaseModel):
    server_id: str = ""
    filesystem: FilesystemResult = Field(default_factory=FilesystemResult)
    shell: ShellResult = Field(default_factory=ShellResult)
    egress: EgressResult = Field(default_factory=EgressResult)
    ingress: IngressResult = Field(default_factory=IngressResult)
    secrets: SecretsResult = Field(default_factory=SecretsResult)
    delegation: DelegationResult = Field(default_factory=DelegationResult)
    impersonation: ImpersonationResult = Field(default_factory=ImpersonationResult)
    data_sensitivity: DataSensitivityResult = Field(default_factory=DataSensitivityResult)

    def categories(self) -> dict[str, CategoryResultType]:
        return {
            "filesystem": self.filesystem,
            "shell": self.shell,
            "egress": self.egress,
            "ingress": self.ingress,
            "secrets": self.secrets,
            "delegation": self.delegation,
            "impersonation": self.impersonation,
            "data_sensitivity": self.data_sensitivity,
        }


class ProvenanceData(BaseModel):
    signed: bool = False
    active_maintenance: bool = True
    install_count: int = 0
    last_update_days: int = 0
    author_count: int = 1
    typosquat_suspicion: bool = False


class ExposureData(BaseModel):
    bind_address: str = "localhost"
    auth: str = "none"
    tls_enabled: bool = False


class ScoreBreakdown(BaseModel):
    breadth: float = 0.0
    depth: float = 0.0
    exposure: float = 0.0
    provenance: float = 0.0
    attack_surface_score: float = 0.0


class ServerReport(BaseModel):
    server_id: str
    source_path: str
    scope: str = "code"
    capability_vector: CapabilityVector
    provenance: ProvenanceData = Field(default_factory=ProvenanceData)
    exposure: ExposureData = Field(default_factory=ExposureData)
    score: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    languages_detected: list[Language] = Field(default_factory=list)
