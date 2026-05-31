"""Base class for all ViabilityScan layers."""
from pathlib import Path


class BaseLayer:
    name: str = "base"
    description: str = ""

    def __init__(self, repo_path: Path):
        self.repo = repo_path

    def run(self) -> dict:
        raise NotImplementedError

    @staticmethod
    def _count_severities(findings: list) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
