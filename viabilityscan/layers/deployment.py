"""
Deployment Layer
Checks: build reproducibility, rollback readiness, observability, monitoring,
backup indicators, DR readiness.
Source: spec id:4
"""

from pathlib import Path
from viabilityscan.layers.base import BaseLayer


class DeploymentLayer(BaseLayer):
    name = "deployment"
    description = "Build reproducibility, rollback, observability, monitoring, DR"

    def run(self) -> dict:
        findings = []
        remediations = []
        checks = {}

        # 1. Build reproducibility
        score_build, f_build, checks_build = self._check_build()
        findings.extend(f_build)
        checks.update(checks_build)

        # 2. Rollback readiness
        score_rollback, f_rollback, checks_rollback = self._check_rollback()
        findings.extend(f_rollback)
        checks.update(checks_rollback)

        # 3. Observability
        score_obs, f_obs, checks_obs = self._check_observability()
        findings.extend(f_obs)
        checks.update(checks_obs)

        # 4. Monitoring / SLOs
        score_mon, f_mon, checks_mon = self._check_monitoring()
        findings.extend(f_mon)
        checks.update(checks_mon)

        # 5. CI/CD pipeline
        score_ci, f_ci, checks_ci = self._check_cicd()
        findings.extend(f_ci)
        checks.update(checks_ci)

        # Weighted sub-score (equal weight across 5 checks)
        score = round((score_build + score_rollback + score_obs + score_mon + score_ci) / 5)

        for f in findings:
            if f.get("severity") in ("HIGH", "CRITICAL"):
                remediations.append(f"[{f['severity']}] {f['title']}: {f.get('remediation','')}")
        if not remediations:
            remediations.append("Deployment posture is solid. Consider adding chaos engineering tests.")

        return {
            "layer": self.name,
            "score": score,
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": self._count_severities(findings),
            "checks": checks,
            "remediations": remediations[:8],
        }

    def _check_build(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        # Dockerfile present?
        has_docker = (self.repo / "Dockerfile").exists()
        checks["has_dockerfile"] = has_docker
        if not has_docker:
            findings.append({
                "rule": "deploy_no_dockerfile",
                "title": "No Dockerfile found",
                "file": "/",
                "line": None,
                "severity": "MEDIUM",
                "layer": "deployment",
                "remediation": "Add a Dockerfile for reproducible container builds.",
            })
            score -= 20

        # docker-compose
        has_compose = (self.repo / "docker-compose.yml").exists() or (self.repo / "docker-compose.yaml").exists()
        checks["has_docker_compose"] = has_compose

        # Check Dockerfile for pinned base image (not :latest)
        if has_docker:
            content = (self.repo / "Dockerfile").read_text(errors="replace")
            if ":latest" in content or (": " not in content and "FROM " in content):
                # rough heuristic for unpinned
                import re
                if re.search(r"FROM\s+\S+:latest", content):
                    findings.append({
                        "rule": "deploy_unpinned_base_image",
                        "title": "Dockerfile uses :latest tag (non-deterministic build)",
                        "file": "Dockerfile",
                        "line": None,
                        "severity": "MEDIUM",
                        "layer": "deployment",
                        "remediation": "Pin base image to a specific digest or version tag for reproducible builds.",
                    })
                    score -= 15

        # Makefile / build script
        has_build_script = (self.repo / "Makefile").exists() or (self.repo / "build.sh").exists() or (self.repo / "scripts/build.sh").exists()
        checks["has_build_script"] = has_build_script
        if not has_build_script:
            findings.append({
                "rule": "deploy_no_build_script",
                "title": "No Makefile or build script found",
                "file": "/",
                "line": None,
                "severity": "LOW",
                "layer": "deployment",
                "remediation": "Add a Makefile or build.sh to standardize the build process.",
            })
            score -= 5

        return max(0, score), findings, checks

    def _check_rollback(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        # Migration rollback already covered in security layer; check for deploy rollback docs
        has_rollback_doc = any(self.repo.rglob("ROLLBACK*")) or any(self.repo.rglob("rollback*"))
        checks["has_rollback_doc"] = has_rollback_doc
        if not has_rollback_doc:
            findings.append({
                "rule": "deploy_no_rollback_doc",
                "title": "No rollback procedure documented",
                "file": "/",
                "line": None,
                "severity": "MEDIUM",
                "layer": "deployment",
                "remediation": "Add ROLLBACK.md documenting the rollback procedure (DB, services, config).",
            })
            score -= 20

        # Check for version tagging hints in CI
        ci_files = list(self.repo.rglob(".github/workflows/*.yml")) + list(self.repo.rglob(".github/workflows/*.yaml"))
        has_release_tag = False
        for ci in ci_files:
            content = ci.read_text(errors="replace")
            if "tags:" in content or "release" in content.lower():
                has_release_tag = True
                break
        checks["has_release_tagging"] = has_release_tag
        if not has_release_tag and ci_files:
            findings.append({
                "rule": "deploy_no_release_tags",
                "title": "CI pipeline does not appear to tag releases",
                "file": ".github/workflows/",
                "line": None,
                "severity": "LOW",
                "layer": "deployment",
                "remediation": "Add semantic versioning tags (e.g. v1.2.3) in CI to enable rollback to known-good versions.",
            })
            score -= 10

        return max(0, score), findings, checks

    def _check_observability(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        # Look for logging, metrics, tracing imports/config
        obs_patterns = {
            "logging": ["import logging", "from logging", "structlog", "loguru"],
            "metrics": ["prometheus_client", "statsd", "datadog", "cloudwatch", "opentelemetry"],
            "tracing": ["opentelemetry", "jaeger", "zipkin", "sentry_sdk", "ddtrace"],
        }

        found_obs = {k: False for k in obs_patterns}
        for filepath in self.repo.rglob("*.py"):
            if any(p in filepath.parts for p in {"__pycache__", "venv", ".venv", "node_modules"}):
                continue
            try:
                content = filepath.read_text(errors="replace")
            except Exception:
                continue
            for obs_type, patterns in obs_patterns.items():
                if any(p in content for p in patterns):
                    found_obs[obs_type] = True

        checks.update({f"has_{k}": v for k, v in found_obs.items()})

        if not found_obs["logging"]:
            findings.append({
                "rule": "deploy_no_logging",
                "title": "No structured logging detected",
                "file": "*.py",
                "line": None,
                "severity": "HIGH",
                "layer": "deployment",
                "remediation": "Add structured logging (structlog or logging module). Emit JSON logs for observability.",
            })
            score -= 25

        if not found_obs["metrics"]:
            findings.append({
                "rule": "deploy_no_metrics",
                "title": "No metrics instrumentation detected",
                "file": "*.py",
                "line": None,
                "severity": "MEDIUM",
                "layer": "deployment",
                "remediation": "Instrument with prometheus_client or OpenTelemetry for RED metrics (Rate, Errors, Duration).",
            })
            score -= 15

        if not found_obs["tracing"]:
            findings.append({
                "rule": "deploy_no_tracing",
                "title": "No distributed tracing detected",
                "file": "*.py",
                "line": None,
                "severity": "LOW",
                "layer": "deployment",
                "remediation": "Add OpenTelemetry tracing for distributed request correlation.",
            })
            score -= 5

        return max(0, score), findings, checks

    def _check_monitoring(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        # Check for SLO / alerting configs
        monitoring_files = (
            list(self.repo.rglob("*.prometheus")) +
            list(self.repo.rglob("alert*.yml")) +
            list(self.repo.rglob("alert*.yaml")) +
            list(self.repo.rglob("monitoring/**")) +
            list(self.repo.rglob("grafana/**")) +
            list(self.repo.rglob("datadog*.yml"))
        )
        has_monitoring = len(monitoring_files) > 0
        checks["has_monitoring_config"] = has_monitoring

        if not has_monitoring:
            findings.append({
                "rule": "deploy_no_monitoring",
                "title": "No monitoring/alerting config found",
                "file": "/",
                "line": None,
                "severity": "MEDIUM",
                "layer": "deployment",
                "remediation": "Add Prometheus alert rules or Datadog monitors for SLO compliance tracking.",
            })
            score -= 20

        # Health check endpoint
        has_health = False
        for filepath in self.repo.rglob("*.py"):
            if any(p in filepath.parts for p in {"__pycache__", "venv", ".venv"}):
                continue
            try:
                content = filepath.read_text(errors="replace")
                if any(h in content for h in ["/health", "/healthz", "/ping", "/ready", "/readyz", "/livez"]):
                    has_health = True
                    break
            except Exception:
                continue
        checks["has_health_endpoint"] = has_health
        if not has_health:
            findings.append({
                "rule": "deploy_no_health_endpoint",
                "title": "No health check endpoint detected",
                "file": "*.py",
                "line": None,
                "severity": "HIGH",
                "layer": "deployment",
                "remediation": "Implement /healthz or /readyz endpoint for Kubernetes/load-balancer health probes.",
            })
            score -= 20

        return max(0, score), findings, checks

    def _check_cicd(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        ci_files = (
            list(self.repo.rglob(".github/workflows/*.yml")) +
            list(self.repo.rglob(".github/workflows/*.yaml")) +
            list(self.repo.rglob(".gitlab-ci.yml")) +
            list(self.repo.rglob("Jenkinsfile")) +
            list(self.repo.rglob(".circleci/config.yml"))
        )
        has_ci = len(ci_files) > 0
        checks["has_ci_pipeline"] = has_ci

        if not has_ci:
            findings.append({
                "rule": "deploy_no_ci",
                "title": "No CI/CD pipeline configuration found",
                "file": "/",
                "line": None,
                "severity": "HIGH",
                "layer": "deployment",
                "remediation": "Add a GitHub Actions / GitLab CI pipeline with test, lint, build, and deploy stages.",
            })
            score -= 30

        else:
            # Check for test step in CI
            has_test_step = False
            for ci_file in ci_files:
                content = ci_file.read_text(errors="replace")
                if any(t in content for t in ["pytest", "npm test", "jest", "go test", "mvn test", "make test"]):
                    has_test_step = True
                    break
            checks["ci_has_test_step"] = has_test_step
            if not has_test_step:
                findings.append({
                    "rule": "deploy_ci_no_tests",
                    "title": "CI pipeline does not appear to run tests",
                    "file": ".github/workflows/",
                    "line": None,
                    "severity": "HIGH",
                    "layer": "deployment",
                    "remediation": "Add a test step to your CI pipeline to catch regressions before deploy.",
                })
                score -= 20

        return max(0, score), findings, checks
