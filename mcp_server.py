import asyncio
import json
import platform
import re
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Platform-safe subprocess flags
# CREATE_NO_WINDOW is Windows-only — guard against Linux/macOS AttributeError
# ---------------------------------------------------------------------------
SUBPROCESS_FLAGS: Dict[str, Any] = {}
if platform.system() == "Windows":
    SUBPROCESS_FLAGS["creationflags"] = subprocess.CREATE_NO_WINDOW
    SUBPROCESS_FLAGS["stdin"] = subprocess.DEVNULL


# ---------------------------------------------------------------------------
# Plugin base class — subclass this to add new scanners (Semgrep, Trivy, …)
# ---------------------------------------------------------------------------
class BaseScanner(ABC):
    """
    Abstract base for security scanners.
    Each scanner is responsible for running its tool and normalizing output
    into the shared finding schema.
    """

    @abstractmethod
    async def scan(self, path: Path) -> Any:
        """Run the scanner against the given path and return raw output."""
        ...

    @abstractmethod
    def normalize(self, raw: Any) -> List[Dict]:
        """Normalize raw scanner output into the shared finding schema."""
        ...


# ---------------------------------------------------------------------------
# Bandit scanner
# ---------------------------------------------------------------------------
class BanditScanner(BaseScanner):

    async def scan(self, path: Path) -> Dict:
        if path.is_file():
            cmd = [sys.executable, "-m", "bandit", str(path), "-f", "json", "-q"]
        else:
            cmd = [
                sys.executable, "-m", "bandit",
                "-r", str(path),
                "-f", "json",
                "-q",
                "--exclude",
                "venv,.git,__pycache__,node_modules,.tox,dist,build,"
                ".pytest_cache,.mypy_cache,*.pyc,*.egg-info",
            ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=subprocess.DEVNULL,  # prevent hang waiting for input
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            stdout_text = stdout.decode("utf-8", errors="replace")

            # Bandit exits 0 (clean) or 1 (issues found) — both are valid
            if proc.returncode in [0, 1]:
                try:
                    return json.loads(stdout_text) if stdout_text.strip() else {"results": []}
                except json.JSONDecodeError:
                    return {
                        "results": [],
                        "error": "JSON parse failed",
                        "raw_output": stdout_text[:500],
                    }
            else:
                return {
                    "results": [],
                    "error": stderr.decode("utf-8", errors="replace") or f"Bandit exit code {proc.returncode}",
                }

        except asyncio.TimeoutError:
            return {"results": [], "error": "Bandit scan timed out (60s limit)"}
        except FileNotFoundError:
            return {"results": [], "error": "bandit not found — is it installed in this environment?"}
        except Exception as e:
            return {"results": [], "error": f"Unexpected error: {e}"}

    def normalize(self, raw: Dict) -> List[Dict]:
        normalized = []
        for issue in raw.get("results", []):
            normalized.append({
                "severity": issue.get("issue_severity", "UNKNOWN"),
                "confidence": issue.get("issue_confidence", "UNKNOWN"),
                "cwe": issue.get("issue_cwe", {}).get("id", "N/A"),
                "file": issue.get("filename"),
                "line": issue.get("line_number"),
                "code": issue.get("code"),
                "description": issue.get("issue_text"),
                "test_id": issue.get("test_id"),
            })
        return normalized


# ---------------------------------------------------------------------------
# Gitleaks scanner
# ---------------------------------------------------------------------------
class GitleaksScanner(BaseScanner):

    async def scan(self, path: Path) -> List:
        cmd = [
            "gitleaks", "detect",
            "--source", str(path),
            "--no-git",
            "-f", "json",
            "-v",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            stdout_text = stdout.decode("utf-8", errors="replace")

            if proc.returncode in [0, 1]:
                try:
                    return json.loads(stdout_text) if stdout_text.strip() else []
                except json.JSONDecodeError:
                    return [{"error": "JSON parse failed", "raw": stdout_text[:200]}]
            else:
                return [{"error": f"Gitleaks failed: {stderr.decode('utf-8', errors='replace')}"}]

        except asyncio.TimeoutError:
            return [{"error": "Gitleaks scan timed out (60s limit)"}]
        except FileNotFoundError:
            return [{"error": "gitleaks not found — is it installed and on PATH?"}]
        except Exception as e:
            return [{"error": f"Unexpected error: {e}"}]

    def normalize(self, raw: List) -> List[Dict]:
        if not isinstance(raw, list):
            return [{"error": "Invalid gitleaks data format"}]

        normalized = []
        for finding in raw:
            if not isinstance(finding, dict):
                continue
            if "error" in finding:
                normalized.append(finding)
                continue
            secret_value = finding.get("Secret", "")
            normalized.append({
                "rule_id": finding.get("RuleID"),
                "description": finding.get("Description"),
                "file": finding.get("File"),
                "line": finding.get("StartLine"),
                "column": finding.get("StartColumn"),
                # Raw secret redacted — use length only for triage
                "secret": "[REDACTED]",
                "secret_length": len(secret_value),
                "fingerprint": finding.get("Fingerprint"),
                "severity": "HIGH",
            })
        return normalized


# ---------------------------------------------------------------------------
# Orchestrator — wires scanners together and builds the response schema
# ---------------------------------------------------------------------------
class SecurityAuditor:

    def __init__(self):
        self._scanners: Dict[str, BaseScanner] = {
            "bandit": BanditScanner(),
            "gitleaks": GitleaksScanner(),
        }

    def register_scanner(self, name: str, scanner: BaseScanner) -> None:
        """Register a new scanner plugin at runtime."""
        self._scanners[name] = scanner

    async def audit(self, path: str) -> Dict[str, Any]:
        target_path = Path(path).resolve()

        if not target_path.exists():
            return {
                "vulnerabilities": [],
                "secrets": [],
                "summary": {
                    "vuln_count": 0,
                    "secret_count": 0,
                    "errors": [f"Path not found: {target_path}"],
                },
            }

        bandit: BanditScanner = self._scanners["bandit"]
        gitleaks: GitleaksScanner = self._scanners["gitleaks"]

        # Run both scanners concurrently — cuts total scan time roughly in half
        bandit_raw, gitleaks_raw = await asyncio.gather(
            bandit.scan(target_path),
            gitleaks.scan(target_path),
        )

        vulns = bandit.normalize(bandit_raw)
        secrets = gitleaks.normalize(gitleaks_raw)

        # Collect only non-empty error strings so the list stays clean
        errors: List[str] = []
        if bandit_raw.get("error"):
            errors.append(f"bandit: {bandit_raw['error']}")
        errors += [
            f"gitleaks: {g['error']}"
            for g in gitleaks_raw
            if isinstance(g, dict) and g.get("error")
        ]

        return {
            "vulnerabilities": vulns,
            "secrets": secrets,
            "summary": {
                # Counts derived from normalized output — always consistent
                "vuln_count": len(vulns),
                "secret_count": len(secrets),
                "errors": errors,
            },
        }


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------
mcp = FastMCP("MCPLiteServer")
_auditor = SecurityAuditor()

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@mcp.tool()
async def audit_codebase(path: str) -> Dict[str, Any]:
    """
    Run security audit (bandit + gitleaks) on a codebase path.

    Args:
        path: File or directory path. Examples: ".", "src/", "mcp_server.py"
    """
    return await _auditor.audit(path)


@mcp.tool()
def explain_vulnerability(cve_id: str) -> Dict[str, str]:
    """
    Explain a specific CVE vulnerability.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
    """
    if not CVE_PATTERN.match(cve_id):
        return {"error": f"Invalid CVE format: '{cve_id}'. Expected format: CVE-YYYY-NNNNN"}

    # TODO: integrate NVD API or local CVE database
    return {
        "cve_id": cve_id.upper(),
        "description": f"Lookup for {cve_id} not yet implemented.",
        "references": ["https://nvd.nist.gov/vuln/detail/" + cve_id.upper()],
        "severity": "Unknown",
    }


if __name__ == "__main__":
    mcp.run()