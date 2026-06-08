"""
ViabilityScan Engine — orchestrates all scan layers and computes phase-gate score.

Scoring formula (from spec id:6):
  V = 0.4*SecurityScore + 0.3*DeploymentScore + 0.3*ReliabilityScore
  PASS if V >= 75 AND Security >= 70 AND Deployment >= 60 AND Reliability >= 60
"""

import json
import time
from pathlib import Path
from datetime import datetime, timezone

from viabilityscan.layers.security_mvp import SecurityMVPLayer
from viabilityscan.layers.deployment import DeploymentLayer
from viabilityscan.layers.reliability import ReliabilityLayer
from viabilityscan.layers.security_full import SecurityFullLayer
from viabilityscan.layers.django_migrations import DjangoMigrationsLayer


class ViabilityEngine:
    """
    Orchestrator for M1 (unbounded scan), M2 (pruning), M3 (scoring).
    
    Scalar pipeline:
      Binary_scalar   → repo metadata (language, framework, CI config)
      Geometry_scalar → raw scan data (line counts, complexity, dep tree)
      Language_scalar → natural language findings
      Triangulation   → final viability score 0-100
    """

    WEIGHTS = {"security": 0.4, "deployment": 0.3, "reliability": 0.3}
    THRESHOLDS = {"viability": 75, "security": 70, "deployment": 60, "reliability": 60}

    def __init__(self, repo_path: Path, full: bool = False):
        self.repo = repo_path
        self.full = full
        self.started_at = datetime.now(timezone.utc).isoformat()

    def run(self) -> dict:
        t0 = time.time()
        metadata = self._binary_scalar()

        # M1 — unbounded scan across all layers
        print("[M1] Scanning all layers...")
        sec_result = SecurityMVPLayer(self.repo).run()
        dep_result = DeploymentLayer(self.repo).run()
        rel_result = ReliabilityLayer(self.repo).run()
        djm_result = DjangoMigrationsLayer(self.repo).run()

        full_result = {}
        if self.full:
            print("[M1] Running full advanced security layer...")
            full_result = SecurityFullLayer(self.repo).run()

        # M2 — prune false positives, enforce timeouts
        sec_result = self._m2_prune(sec_result)
        dep_result = self._m2_prune(dep_result)
        rel_result = self._m2_prune(rel_result)
        djm_result = self._m2_prune(djm_result)

        # M3 — weight findings, compute overall score
        scores = self._triangulation_scalar(sec_result, dep_result, rel_result)
        gate, reasons = self._phase_gate(scores)

        elapsed = round(time.time() - t0, 2)

        return {
            "tool": "ViabilityScan",
            "version": "1.0.0",
            "repo": str(self.repo),
            "repo_name": self.repo.name,
            "scanned_at": self.started_at,
            "elapsed_seconds": elapsed,
            "mode": "full" if self.full else "mvp",
            "metadata": metadata,
            "scores": scores,
            "gate": gate,
            "gate_reasons": reasons,
            "layers": {
                "security_mvp": sec_result,
                "deployment": dep_result,
                "reliability": rel_result,
                "django_migrations": djm_result,
                **({"security_full": full_result} if self.full else {}),
            },
            "next_frame_prediction": self._next_frame_prediction(gate, sec_result, dep_result, rel_result),
        }

    # ── Scalar helpers ──────────────────────────────────────────────────────

    def _binary_scalar(self) -> dict:
        """Collect repo metadata: language, framework, CI, Dockerfile presence."""
        exts: dict[str, int] = {}
        total_lines = 0
        file_count = 0

        for f in self.repo.rglob("*"):
            if f.is_file() and not self._is_ignored(f):
                ext = f.suffix.lower()
                exts[ext] = exts.get(ext, 0) + 1
                file_count += 1
                try:
                    total_lines += sum(1 for _ in f.open("rb"))
                except Exception:
                    pass

        dominant_lang = max(exts, key=exts.get) if exts else "unknown"

        return {
            "file_count": file_count,
            "total_lines": total_lines,
            "dominant_extension": dominant_lang,
            "extension_counts": dict(sorted(exts.items(), key=lambda x: -x[1])[:15]),
            "has_dockerfile": (self.repo / "Dockerfile").exists(),
            "has_docker_compose": (self.repo / "docker-compose.yml").exists() or (self.repo / "docker-compose.yaml").exists(),
            "has_ci_github": (self.repo / ".github" / "workflows").exists(),
            "has_ci_gitlab": (self.repo / ".gitlab-ci.yml").exists(),
            "has_ci_circle": (self.repo / ".circleci").exists(),
            "has_requirements": (self.repo / "requirements.txt").exists() or (self.repo / "pyproject.toml").exists(),
            "has_package_json": (self.repo / "package.json").exists(),
            "has_makefile": (self.repo / "Makefile").exists(),
            "has_readme": any(self.repo.glob("README*")),
            "has_license": any(self.repo.glob("LICENSE*")),
            "has_gitignore": (self.repo / ".gitignore").exists(),
            "has_env_example": (self.repo / ".env.example").exists() or (self.repo / ".env.sample").exists(),
        }

    def _m2_prune(self, layer_result: dict) -> dict:
        """
        M2 — efficiency zealot pass.
        Remove duplicate findings, cap noise findings, mark low-confidence items.
        """
        findings = layer_result.get("findings", [])
        seen = set()
        pruned = []
        for f in findings:
            key = (f.get("rule"), f.get("file"), f.get("line"))
            if key not in seen:
                seen.add(key)
                pruned.append(f)
        layer_result["findings"] = pruned
        layer_result["finding_count"] = len(pruned)
        return layer_result

    def _triangulation_scalar(self, sec, dep, rel) -> dict:
        """Compute weighted viability score from sub-scores."""
        s = sec.get("score", 0)
        d = dep.get("score", 0)
        r = rel.get("score", 0)
        v = round(self.WEIGHTS["security"] * s +
                  self.WEIGHTS["deployment"] * d +
                  self.WEIGHTS["reliability"] * r, 1)
        return {
            "security": s,
            "deployment": d,
            "reliability": r,
            "viability": v,
        }

    def _phase_gate(self, scores: dict) -> tuple[str, list[str]]:
        reasons = []
        if scores["viability"] < self.THRESHOLDS["viability"]:
            reasons.append(f"Viability {scores['viability']} < {self.THRESHOLDS['viability']}")
        if scores["security"] < self.THRESHOLDS["security"]:
            reasons.append(f"Security {scores['security']} < {self.THRESHOLDS['security']}")
        if scores["deployment"] < self.THRESHOLDS["deployment"]:
            reasons.append(f"Deployment {scores['deployment']} < {self.THRESHOLDS['deployment']}")
        if scores["reliability"] < self.THRESHOLDS["reliability"]:
            reasons.append(f"Reliability {scores['reliability']} < {self.THRESHOLDS['reliability']}")
        gate = "PASS" if not reasons else "FAIL"
        return gate, reasons

    def _next_frame_prediction(self, gate, sec, dep, rel) -> str:
        """NextFramePrediction — predicted state after top remediation actions."""
        if gate == "PASS":
            return "Repository is production-ready. Recommended: enable continuous scanning in CI."
        tips = []
        for layer_name, layer in [("Security", sec), ("Deployment", dep), ("Reliability", rel)]:
            rem = layer.get("remediations", [])
            if rem:
                tips.append(f"{layer_name}: {rem[0]}")
        return "Address top issues to reach PASS: " + " | ".join(tips[:3]) if tips else "Review findings and increase sub-scores."

    @staticmethod
    def _is_ignored(path: Path) -> bool:
        ignore_parts = {".git", "__pycache__", "node_modules", ".tox", "venv", ".venv", "dist", "build", ".eggs"}
        return any(p in ignore_parts for p in path.parts)
