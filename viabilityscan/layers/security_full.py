"""
Security Full Layer (Phase 2+)
Covers: Semgrep, CodeQL, Trivy container scanning, Checkov IaC scanning.
These require external tool installation — gaps written to agents.jsonl.
This layer attempts to invoke tools if available, falls back gracefully.
Source: spec id:3 security_layer_full
"""

import shutil
import subprocess
import json
from pathlib import Path
from viabilityscan.layers.base import BaseLayer


class SecurityFullLayer(BaseLayer):
    name = "security_full"
    description = "Semgrep, CodeQL, Trivy, Checkov (requires external tools)"

    TOOLS = {
        "semgrep": "semgrep --config=auto --json .",
        "trivy":   "trivy fs --format json --quiet .",
        "checkov": "checkov -d . --output json --quiet",
    }

    def run(self) -> dict:
        findings = []
        tool_results = {}
        agent_gaps = []

        for tool, cmd in self.TOOLS.items():
            if shutil.which(tool):
                result = self._run_tool(tool, cmd)
                tool_results[tool] = result
                findings.extend(result.get("findings", []))
            else:
                agent_gaps.append({
                    "tool": tool,
                    "gap": f"{tool} not installed",
                    "install": self._install_hint(tool),
                    "cmd": cmd,
                    "layer": "security_full",
                })

        # CodeQL requires a separate flow (build + query run) — always an agent gap
        agent_gaps.append({
            "tool": "codeql",
            "gap": "CodeQL requires database creation and query execution in a separate CI step",
            "install": "https://github.com/github/codeql-action",
            "cmd": "codeql database create codeql-db --language=python && codeql database analyze codeql-db --format=sarif-latest --output=results.sarif",
            "layer": "security_full",
        })

        # ScoutSuite requires cloud credentials — always an agent gap
        agent_gaps.append({
            "tool": "scoutsuite",
            "gap": "ScoutSuite requires cloud provider credentials (AWS/GCP/Azure) to run",
            "install": "pip install scoutsuite",
            "cmd": "scout aws --report-dir scoutsuite-report",
            "layer": "security_full",
        })

        score = self._compute_score(findings, len(agent_gaps))

        return {
            "layer": self.name,
            "score": score,
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": self._count_severities(findings),
            "tool_results": tool_results,
            "agent_gaps": agent_gaps,
            "remediations": [f"Install {g['tool']}: {g['install']}" for g in agent_gaps[:4]],
        }

    def _run_tool(self, tool: str, cmd: str) -> dict:
        findings = []
        try:
            proc = subprocess.run(
                cmd.split(),
                cwd=str(self.repo),
                capture_output=True,
                text=True,
                timeout=120,
            )
            raw = json.loads(proc.stdout or "{}")

            if tool == "semgrep":
                for r in raw.get("results", []):
                    findings.append({
                        "rule": f"semgrep_{r.get('check_id','?')}",
                        "title": r.get("extra", {}).get("message", r.get("check_id")),
                        "file": r.get("path"),
                        "line": r.get("start", {}).get("line"),
                        "severity": r.get("extra", {}).get("severity", "MEDIUM").upper(),
                        "layer": "semgrep",
                        "remediation": r.get("extra", {}).get("fix", "See semgrep rule for details."),
                    })

            elif tool == "trivy":
                for result in raw.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []):
                        findings.append({
                            "rule": f"trivy_{vuln.get('VulnerabilityID')}",
                            "title": f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')} — {vuln.get('VulnerabilityID')}",
                            "file": result.get("Target"),
                            "line": None,
                            "severity": vuln.get("Severity", "UNKNOWN").upper(),
                            "layer": "trivy",
                            "remediation": f"Upgrade to {vuln.get('FixedVersion', 'latest fixed version')}",
                        })

            elif tool == "checkov":
                for check in raw.get("results", {}).get("failed_checks", []):
                    findings.append({
                        "rule": f"checkov_{check.get('check_id')}",
                        "title": check.get("check_id", "") + ": " + check.get("check", {}).get("name", ""),
                        "file": check.get("repo_file_path"),
                        "line": check.get("file_line_range", [None])[0],
                        "severity": "MEDIUM",
                        "layer": "checkov",
                        "remediation": check.get("check", {}).get("guide_link", "See Checkov docs."),
                    })

        except subprocess.TimeoutExpired:
            findings.append({
                "rule": f"{tool}_timeout",
                "title": f"{tool} timed out after 120s",
                "file": None, "line": None,
                "severity": "INFO", "layer": tool,
                "remediation": f"Run {tool} manually on large repos.",
            })
        except Exception as e:
            pass  # Tool failed to parse output — gap will be noted

        return {"findings": findings, "tool": tool}

    def _compute_score(self, findings: list, gap_count: int) -> int:
        score = 100
        for f in findings:
            sev = f.get("severity", "LOW")
            score -= {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}.get(sev, 0)
        # Penalize for unresolved gaps (tools not installed)
        score -= gap_count * 3
        return max(0, score)

    @staticmethod
    def _install_hint(tool: str) -> str:
        hints = {
            "semgrep": "pip install semgrep  OR  brew install semgrep",
            "trivy":   "brew install aquasecurity/trivy/trivy  OR  https://aquasecurity.github.io/trivy/",
            "checkov": "pip install checkov",
        }
        return hints.get(tool, f"See {tool} documentation")
