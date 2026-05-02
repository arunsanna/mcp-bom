from __future__ import annotations

from pathlib import Path

from mcp_bom.models import (
    CapabilityVector,
    ServerReport,
    Language,
    ProvenanceData,
    ExposureData,
)
from mcp_bom.patterns import (
    filesystem,
    shell,
    egress,
    ingress,
    secrets,
    delegation,
    impersonation,
    data_sensitivity,
)
from mcp_bom.scorer import score_vector

_EXT_LANG = {
    ".py": Language.PYTHON,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".go": Language.GO,
}

_SKIP_DIRS = {
    "node_modules",
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}


def _read_source_files(source_path: Path) -> tuple[dict[str, str], set[Language]]:
    source_files: dict[str, str] = {}
    languages: set[Language] = set()

    if source_path.is_file():
        ext = source_path.suffix
        lang = _EXT_LANG.get(ext)
        if lang and lang != Language.UNKNOWN:
            try:
                source_files[source_path.name] = source_path.read_text(errors="ignore")
                languages.add(lang)
            except Exception:
                pass
        return source_files, languages

    for fpath in sorted(source_path.rglob("*")):
        if not fpath.is_file():
            continue
        if any(part in _SKIP_DIRS for part in fpath.parts):
            continue
        ext = fpath.suffix
        lang = _EXT_LANG.get(ext)
        if lang and lang != Language.UNKNOWN:
            if "test" in fpath.name.lower() and fpath.stat().st_size < 200:
                continue
            try:
                rel = str(fpath.relative_to(source_path))
                source_files[rel] = fpath.read_text(errors="ignore")
                languages.add(lang)
            except Exception:
                pass

    return source_files, languages


def extract(
    source_path: str | Path,
    server_id: str = "",
) -> ServerReport:
    source_path = Path(source_path).resolve()

    if not source_path.exists():
        raise FileNotFoundError(f"Source path not found: {source_path}")

    source_files, languages = _read_source_files(source_path)

    if not server_id:
        server_id = source_path.name

    fs_result = filesystem.detect(source_files)
    sh_result = shell.detect(source_files)
    eg_result = egress.detect(source_files)
    ig_result = ingress.detect(source_files)
    se_result = secrets.detect(source_files)
    de_result = delegation.detect(source_files)
    im_result = impersonation.detect(source_files)
    ds_result = data_sensitivity.detect(source_files)

    vector = CapabilityVector(
        server_id=server_id,
        filesystem=fs_result,
        shell=sh_result,
        egress=eg_result,
        ingress=ig_result,
        secrets=se_result,
        delegation=de_result,
        impersonation=im_result,
        data_sensitivity=ds_result,
    )

    provenance = ProvenanceData()
    exposure = ExposureData(
        bind_address=ig_result.bind if ig_result.detected else "localhost",
        auth=ig_result.auth if ig_result.detected else "none",
        tls_enabled=ig_result.tls_enabled if ig_result.detected else False,
    )

    score = score_vector(vector, provenance, exposure)

    return ServerReport(
        server_id=server_id,
        source_path=str(source_path),
        capability_vector=vector,
        provenance=provenance,
        exposure=exposure,
        score=score,
        languages_detected=sorted(languages, key=lambda l: l.value),
    )
