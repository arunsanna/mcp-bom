from __future__ import annotations

import tomllib
from pathlib import Path

from mcp_bom.models import (
    CapabilityVector,
    Confidence,
    ProvenanceData,
    ExposureData,
    ScoreBreakdown,
)
from mcp_bom.models import (
    FilesystemResult,
    ShellResult,
    EgressResult,
    IngressResult,
    SecretsResult,
    DelegationResult,
    ImpersonationResult,
    DataSensitivityResult,
)


def load_weights(path: str | Path) -> dict:
    p = Path(path)
    with p.open("rb") as f:
        return tomllib.load(f)


def _confidence_multiplier(confidence: Confidence, config: dict) -> float:
    return config.get("confidence_multipliers", {}).get(confidence.value, 1.0)


def compute_depth_filesystem(result: FilesystemResult, config: dict) -> float:
    if not result.detected:
        return 0.0
    d = config["depth"]["filesystem"]
    score = 0.0
    if result.read:
        score += d["read"]
    if result.write:
        score += d["write"]
    if result.delete:
        score += d["delete"]
    if result.scope in ("system-wide", "arbitrary"):
        score += d.get("system_wide_scope_bonus", 2)
    return score


def compute_depth_shell(result: ShellResult, config: dict) -> float:
    if not result.detected:
        return 0.0
    d = config["depth"]["shell"]
    score = 0.0
    if result.direct:
        score = d["direct"]
    elif result.sandboxed:
        score = d["sandboxed"]
    elif result.code_evaluation_vector:
        score = d.get("code_evaluation", d.get("unsafe_deserialization", 8))
    if result.shell_interpreted:
        score += d.get("shell_interpreted_bonus", 1)
    if result.arbitrary_args:
        score += d.get("arbitrary_args_bonus", 1)
    return min(score, 10)


def compute_depth_egress(result: EgressResult, config: dict) -> float:
    if not result.detected:
        return 0.0
    d = config["depth"]["egress"]
    if result.arbitrary_host:
        return d["arbitrary_host"]
    if result.fixed_remote_datastore:
        return d["fixed_remote_datastore"]
    return d["allowlisted"]


def compute_depth_ingress(result: IngressResult, config: dict) -> float:
    if not result.detected:
        return 0.0
    d = config["depth"]["ingress"]
    if result.bind == "0.0.0.0" and result.auth == "none":
        return d["public_bind_no_auth"]
    if result.bind == "0.0.0.0":
        return d["public_bind_with_auth"]
    return d["localhost"]


def compute_depth_secrets(result: SecretsResult, config: dict) -> float:
    if not result.detected:
        return 0.0
    d = config["depth"]["secrets"]
    score = 0.0
    if result.scope == "cloud-kms":
        score = d["cloud_kms_read"]
    elif result.scope == "system-keychain":
        score = d["keychain_read"]
    elif result.scope == "arbitrary-env":
        score = d["arbitrary_or_exposed_env_read"]
    elif result.scope == "process-env":
        score = d["config_specific_env_read"]
    else:
        score = d["config_specific_env_read"]
    if result.write:
        score += d.get("write_bonus", 2)
    return score


def compute_depth_delegation(result: DelegationResult, config: dict) -> float:
    if not result.detected:
        return 0.0
    d = config["depth"]["delegation"]
    if result.dynamic:
        return d["dynamic"]
    return d["static"]


def compute_depth_impersonation(result: ImpersonationResult, config: dict) -> float:
    if not result.detected:
        return 0.0
    d = config["depth"]["impersonation"]
    score = d["per_channel"] * max(len(result.channels), 1)
    if not result.approval_gate:
        score += d.get("no_approval_gate_bonus", 3)
    return min(score, 10)


def compute_depth_data_sensitivity(result: DataSensitivityResult, config: dict) -> float:
    if not result.detected:
        return 0.0
    d = config["depth"]["data_sensitivity"]
    if not result.categories:
        return d["none"]
    max_val = d["none"]
    for cat in result.categories:
        max_val = max(max_val, d.get(cat, 0))
    return max_val


_DEPTH_FUNCS = {
    "filesystem": compute_depth_filesystem,
    "shell": compute_depth_shell,
    "egress": compute_depth_egress,
    "ingress": compute_depth_ingress,
    "secrets": compute_depth_secrets,
    "delegation": compute_depth_delegation,
    "impersonation": compute_depth_impersonation,
    "data_sensitivity": compute_depth_data_sensitivity,
}


def score_vector(
    vector: CapabilityVector,
    provenance: ProvenanceData | None = None,
    exposure: ExposureData | None = None,
    config: dict | None = None,
    config_path: str | Path | None = None,
) -> ScoreBreakdown:
    if config is None:
        if config_path is None:
            config_path = Path(__file__).resolve().parent.parent.parent / "score_function.toml"
            if not config_path.exists():
                config_path = Path("score_function.toml")
        config = load_weights(config_path)

    if provenance is None:
        provenance = ProvenanceData()
    if exposure is None:
        exposure = ExposureData()

    w = config["weights"]
    depth_denom = config.get("depth_denominator", 80)

    cats = vector.categories()
    detected_count = sum(1 for c in cats.values() if c.detected)
    breadth = (detected_count / config.get("category_count", 8)) * 100.0

    total_depth = 0.0
    for cat_name, cat_result in cats.items():
        func = _DEPTH_FUNCS.get(cat_name)
        if func and cat_result.detected:
            raw = func(cat_result, config)
            mult = _confidence_multiplier(cat_result.confidence, config)
            adjusted = raw * mult
            cat_result.depth_raw = raw
            cat_result.depth_adjusted = adjusted
            total_depth += adjusted

    depth_score = (total_depth / depth_denom) * 100.0

    exp = config["exposure_surface"]
    if exposure.bind_address == "localhost":
        if exposure.auth != "none":
            exposure_score = exp["localhost_auth_tls"]
        else:
            exposure_score = exp["localhost_no_auth"]
    else:
        if exposure.auth != "none" and exposure.tls_enabled:
            exposure_score = exp["public_auth_tls"]
        elif exposure.auth != "none":
            exposure_score = exp["public_auth_no_tls"]
        elif exposure.tls_enabled:
            exposure_score = exp["public_no_auth_tls"]
        else:
            exposure_score = exp["public_no_auth_no_tls"]

    prov = config["provenance"]
    if provenance.typosquat_suspicion:
        provenance_score = prov["typosquat_or_new_account"]
    elif provenance.author_count == 1 and provenance.install_count < 100 and provenance.last_update_days > 180:
        provenance_score = prov["single_author_low_install_stale"]
    elif not provenance.signed and provenance.last_update_days > 180:
        provenance_score = prov["unsigned_stale"]
    elif not provenance.signed:
        provenance_score = prov["unsigned_active"]
    elif provenance.last_update_days > 180:
        provenance_score = prov["signed_stale"]
    else:
        provenance_score = prov["signed_active_maintained_1k_plus_installs"]

    ass = (
        w["breadth"] * breadth
        + w["depth"] * depth_score
        + w["exposure"] * exposure_score
        + w["provenance"] * provenance_score
    )

    return ScoreBreakdown(
        breadth=round(breadth, 2),
        depth=round(depth_score, 2),
        exposure=round(exposure_score, 2),
        provenance=round(provenance_score, 2),
        attack_surface_score=round(ass, 2),
    )
