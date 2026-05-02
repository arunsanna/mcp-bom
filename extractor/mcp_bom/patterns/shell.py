from __future__ import annotations

import ast
import re

from mcp_bom.models import Confidence, ShellResult

_PYTHON_DIRECT = [
    r"\bsubprocess\.run\b",
    r"\bsubprocess\.Popen\b",
    r"\bsubprocess\.call\b",
    r"\bsubprocess\.check_output\b",
    r"\bos\.system\b",
    r"\bos\.exec",
    r"\bos\.popen\b",
    r"\bpty\.spawn\b",
]

_PYTHON_EVAL = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
]

_PYTHON_UNSAFE_DESER = [
    r"\bpickle\.load",
    r"\bdill\.load",
    r"\bmarshal\.load",
    r"\byaml\.load\b(?!.*SafeLoader)",
    r"\byaml\.unsafe_load\b",
    r"\byaml\.full_load\b",
]

_TS_DIRECT = [
    r"\bchild_process\b",
    r"\bexecSync\b",
    r"\bspawnSync\b",
    r"\bexecFile\b",
    r"\bshelljs\b",
]

_TS_EVAL = [
    r"\bvm\.runIn",
    r"\bnew\s+Function\s*\(",
]

_GO_DIRECT = [
    r"\bos/exec\.Command\b",
    r"\bsyscall\.Exec\b",
]

SCHEMA_PATTERNS = [
    r'"command"',
    r'"shell"',
    r'"script"',
    r'"execute"',
    r'"run_command"',
    r'"exec"',
]


def _ast_python_shell(source: str) -> tuple[list[str], bool, bool]:
    direct_evidence: list[str] = []
    has_eval = False
    has_unsafe_deser = False

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return direct_evidence, has_eval, has_unsafe_deser

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                mod = ""
                if isinstance(node.func.value, ast.Name):
                    mod = node.func.value.id
                if mod == "subprocess" and attr in ("run", "Popen", "call", "check_output", "check_call"):
                    direct_evidence.append(f"subprocess.{attr}")
                if mod == "os" and attr in ("system", "popen"):
                    direct_evidence.append(f"os.{attr}")
                if mod == "pty" and attr == "spawn":
                    direct_evidence.append("pty.spawn")
            if isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec"):
                    has_eval = True

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("load", "loads"):
                mod = ""
                if isinstance(node.func.value, ast.Name):
                    mod = node.func.value.id
                if mod in ("pickle", "dill", "marshal"):
                    has_unsafe_deser = True
            if isinstance(node.func, ast.Attribute) and node.func.attr == "load":
                mod = ""
                if isinstance(node.func.value, ast.Name):
                    mod = node.func.value.id
                if mod == "yaml":
                    has_unsafe_deser = True

    return direct_evidence, has_eval, has_unsafe_deser


def _regex_scan(content: str, patterns: list[str]) -> list[str]:
    matches = []
    for pat in patterns:
        found = re.findall(pat, content, re.IGNORECASE)
        matches.extend(found)
    return matches


def detect(source_files: dict[str, str], scope: str = "code") -> ShellResult:
    result = ShellResult(detected=False)
    evidence: list[str] = []
    direct = False
    shell_interpreted = False
    arbitrary_args = False
    code_eval_vector: str | None = None

    for path, content in source_files.items():
        if path.endswith(".py"):
            ast_dir, ast_eval, ast_deser = _ast_python_shell(content)
            if ast_dir:
                direct = True
                evidence.extend(ast_dir)
            if ast_eval:
                code_eval_vector = "eval"
                evidence.append("eval/exec")
            if ast_deser:
                code_eval_vector = "unsafe_deserialization"
                evidence.append("unsafe_deserialization")

            evidence.extend(_regex_scan(content, _PYTHON_DIRECT))
            if _regex_scan(content, _PYTHON_EVAL):
                code_eval_vector = code_eval_vector or "eval"
                evidence.extend(_regex_scan(content, _PYTHON_EVAL))
            if _regex_scan(content, _PYTHON_UNSAFE_DESER):
                code_eval_vector = code_eval_vector or "unsafe_deserialization"
                evidence.extend(_regex_scan(content, _PYTHON_UNSAFE_DESER))

            if "shell=True" in content or "shell = True" in content:
                shell_interpreted = True
            if re.search(r"subprocess\.\w+\(.*\*", content, re.DOTALL):
                arbitrary_args = True

        elif path.endswith((".ts", ".js", ".tsx", ".jsx")):
            ts_dir = _regex_scan(content, _TS_DIRECT)
            if ts_dir:
                direct = True
                evidence.extend(ts_dir)
            if _regex_scan(content, _TS_EVAL):
                code_eval_vector = code_eval_vector or "eval"
                evidence.extend(_regex_scan(content, _TS_EVAL))
            if "shell: true" in content or "shell:true" in content:
                shell_interpreted = True

        elif path.endswith(".go"):
            go_dir = _regex_scan(content, _GO_DIRECT)
            if go_dir:
                direct = True
                evidence.extend(go_dir)

        schema = _regex_scan(content, SCHEMA_PATTERNS)
        if schema:
            evidence.extend(schema)

    if direct or code_eval_vector:
        result.detected = True
        result.confidence = Confidence.HIGH
        result.direct = direct
        result.sandboxed = not direct and code_eval_vector is not None
        result.shell_interpreted = shell_interpreted
        result.arbitrary_args = arbitrary_args
        result.code_evaluation_vector = code_eval_vector
    elif evidence:
        result.detected = True
        result.confidence = Confidence.LOW

    result.evidence = sorted(set(evidence))[:20]
    return result
