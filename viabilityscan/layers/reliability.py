"""
Reliability Layer
Checks: test coverage indicators, test structure, complexity analysis,
performance baseline hints, mutation testing availability.
Source: spec id:5
"""

import re
from pathlib import Path
from viabilityscan.layers.base import BaseLayer


class ReliabilityLayer(BaseLayer):
    name = "reliability"
    description = "Test coverage, complexity, mutation testing, performance"

    def run(self) -> dict:
        findings = []
        remediations = []
        checks = {}

        score_tests, f_tests, c_tests = self._check_tests()
        findings.extend(f_tests)
        checks.update(c_tests)

        score_cov, f_cov, c_cov = self._check_coverage_config()
        findings.extend(f_cov)
        checks.update(c_cov)

        score_complexity, f_complexity, c_complexity = self._check_complexity()
        findings.extend(f_complexity)
        checks.update(c_complexity)

        score_mutation, f_mutation, c_mutation = self._check_mutation()
        findings.extend(f_mutation)
        checks.update(c_mutation)

        score_perf, f_perf, c_perf = self._check_performance()
        findings.extend(f_perf)
        checks.update(c_perf)

        score = round((score_tests + score_cov + score_complexity + score_mutation + score_perf) / 5)

        for f in findings:
            if f.get("severity") in ("HIGH", "CRITICAL"):
                remediations.append(f"[{f['severity']}] {f['title']}: {f.get('remediation', '')}")
        if not remediations:
            remediations.append("Reliability posture is solid. Add mutation testing for deeper assurance.")

        return {
            "layer": self.name,
            "score": score,
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": self._count_severities(findings),
            "checks": checks,
            "remediations": remediations[:8],
        }

    def _check_tests(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        # Find test files
        test_files = (
            list(self.repo.rglob("test_*.py")) +
            list(self.repo.rglob("*_test.py")) +
            list(self.repo.rglob("*.test.js")) +
            list(self.repo.rglob("*.spec.js")) +
            list(self.repo.rglob("*.test.ts")) +
            list(self.repo.rglob("*.spec.ts"))
        )
        # Exclude venv/node_modules
        test_files = [
            f for f in test_files
            if not any(p in f.parts for p in {"venv", ".venv", "node_modules", "__pycache__"})
        ]

        checks["test_file_count"] = len(test_files)
        checks["has_tests"] = len(test_files) > 0

        if not test_files:
            findings.append({
                "rule": "reliability_no_tests",
                "title": "No test files found",
                "file": "/",
                "line": None,
                "severity": "CRITICAL",
                "layer": "reliability",
                "remediation": "Add a test suite (pytest for Python, Jest for JS). Aim for ≥80% line coverage.",
            })
            score -= 50

        # Count source files vs test ratio
        src_py = [
            f for f in self.repo.rglob("*.py")
            if not any(p in f.parts for p in {"venv", ".venv", "__pycache__", "migrations", "alembic"})
            and "test" not in f.name
        ]
        checks["source_file_count"] = len(src_py)

        if src_py and test_files:
            ratio = len(test_files) / len(src_py)
            checks["test_to_source_ratio"] = round(ratio, 2)
            if ratio < 0.2:
                findings.append({
                    "rule": "reliability_low_test_ratio",
                    "title": f"Low test-to-source ratio: {ratio:.2f} (target ≥0.5)",
                    "file": "/",
                    "line": None,
                    "severity": "HIGH",
                    "layer": "reliability",
                    "remediation": "Increase test coverage. Add unit tests for all public functions and integration tests for API endpoints.",
                })
                score -= 20
            elif ratio < 0.5:
                findings.append({
                    "rule": "reliability_moderate_test_ratio",
                    "title": f"Moderate test-to-source ratio: {ratio:.2f} (target ≥0.5)",
                    "file": "/",
                    "line": None,
                    "severity": "MEDIUM",
                    "layer": "reliability",
                    "remediation": "Expand test coverage toward 0.5+ ratio. Prioritize edge cases and error paths.",
                })
                score -= 10

        # Check for conftest / fixtures
        has_conftest = len(list(self.repo.rglob("conftest.py"))) > 0
        checks["has_pytest_conftest"] = has_conftest

        # Assert usage vs test files
        total_asserts = 0
        for tf in test_files[:50]:  # cap for performance
            try:
                content = tf.read_text(errors="replace")
                total_asserts += len(re.findall(r"\bassert\b|\.assert[A-Z]|expect\(", content))
            except Exception:
                pass
        checks["total_assertions_sampled"] = total_asserts
        if test_files and total_asserts == 0:
            findings.append({
                "rule": "reliability_no_assertions",
                "title": "Test files found but no assertions detected",
                "file": "tests/",
                "line": None,
                "severity": "HIGH",
                "layer": "reliability",
                "remediation": "Add assertions to test files. Tests without assertions pass vacuously.",
            })
            score -= 15

        return max(0, score), findings, checks

    def _check_coverage_config(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        # .coveragerc, setup.cfg [coverage:], pyproject.toml [tool.coverage]
        has_coverage_config = (
            (self.repo / ".coveragerc").exists() or
            any("coverage" in (self.repo / f).read_text(errors="replace").lower()
                for f in ["setup.cfg", "pyproject.toml"]
                if (self.repo / f).exists())
        )
        checks["has_coverage_config"] = has_coverage_config

        # jest coverage config
        pj = self.repo / "package.json"
        if pj.exists():
            try:
                import json
                data = json.loads(pj.read_text(errors="replace"))
                if "jest" in data and "coverageThreshold" in str(data.get("jest", {})):
                    has_coverage_config = True
                    checks["has_jest_coverage_threshold"] = True
            except Exception:
                pass

        if not has_coverage_config:
            findings.append({
                "rule": "reliability_no_coverage_config",
                "title": "No test coverage configuration found",
                "file": "/",
                "line": None,
                "severity": "MEDIUM",
                "layer": "reliability",
                "remediation": "Add .coveragerc with fail_under=80 or equivalent. Enforce coverage in CI.",
            })
            score -= 20

        # Check if CI runs coverage
        ci_runs_coverage = False
        for ci_file in (list(self.repo.rglob(".github/workflows/*.yml")) +
                        list(self.repo.rglob(".github/workflows/*.yaml"))):
            try:
                content = ci_file.read_text(errors="replace")
                if "coverage" in content or "--cov" in content:
                    ci_runs_coverage = True
                    break
            except Exception:
                pass
        checks["ci_runs_coverage"] = ci_runs_coverage
        if not ci_runs_coverage:
            findings.append({
                "rule": "reliability_ci_no_coverage",
                "title": "CI pipeline does not enforce coverage thresholds",
                "file": ".github/workflows/",
                "line": None,
                "severity": "LOW",
                "layer": "reliability",
                "remediation": "Add `pytest --cov --cov-fail-under=80` to CI to gate merges on coverage.",
            })
            score -= 10

        return max(0, score), findings, checks

    def _check_complexity(self) -> tuple[int, list, dict]:
        """
        Estimate cyclomatic complexity via branch-count heuristic.
        Full analysis requires radon/lizard — noted as agent gap.
        """
        findings = []
        checks = {}
        score = 100

        BRANCH_KEYWORDS = re.compile(r"\b(if|elif|for|while|except|and|or|case)\b")
        high_complexity_files = []

        py_files = [
            f for f in self.repo.rglob("*.py")
            if not any(p in f.parts for p in {"venv", ".venv", "__pycache__", "node_modules"})
        ]

        total_complexity = 0
        analyzed = 0
        for filepath in py_files[:100]:  # cap for speed
            try:
                content = filepath.read_text(errors="replace")
            except Exception:
                continue
            functions = re.split(r"\ndef ", content)
            for func in functions[1:]:
                branch_count = len(BRANCH_KEYWORDS.findall(func[:500]))
                complexity = 1 + branch_count
                total_complexity += complexity
                if complexity > 15:
                    high_complexity_files.append((str(filepath.relative_to(self.repo)), complexity))
            analyzed += 1

        checks["files_analyzed_for_complexity"] = analyzed
        checks["high_complexity_file_count"] = len(high_complexity_files)
        avg_complexity = round(total_complexity / max(analyzed, 1), 1)
        checks["estimated_avg_complexity"] = avg_complexity

        for filepath, cx in sorted(high_complexity_files, key=lambda x: -x[1])[:5]:
            findings.append({
                "rule": "reliability_high_complexity",
                "title": f"High cyclomatic complexity ~{cx}: {filepath}",
                "file": filepath,
                "line": None,
                "severity": "MEDIUM" if cx < 25 else "HIGH",
                "layer": "reliability",
                "remediation": "Refactor to reduce complexity below 10. Extract helper functions. Consider radon for precise measurement.",
            })
            score -= 5 if cx < 25 else 10

        if avg_complexity > 20:
            score -= 10

        return max(0, score), findings, checks

    def _check_mutation(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        # Look for mutmut, stryker, pitest config
        has_mutation = (
            (self.repo / ".mutmut-cache").exists() or
            (self.repo / "mutmut_config.py").exists() or
            any(self.repo.rglob("stryker.conf*")) or
            any("mutmut" in (self.repo / f).read_text(errors="replace")
                for f in ["pyproject.toml", "Makefile", "tox.ini"]
                if (self.repo / f).exists())
        )
        checks["has_mutation_testing"] = has_mutation

        if not has_mutation:
            findings.append({
                "rule": "reliability_no_mutation_testing",
                "title": "No mutation testing configured",
                "file": "/",
                "line": None,
                "severity": "LOW",
                "layer": "reliability",
                "remediation": "Add mutmut (Python) or Stryker (JS) to validate test suite effectiveness.",
            })
            score -= 10  # low penalty — this is a nice-to-have for MVP

        return max(0, score), findings, checks

    def _check_performance(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        # Look for benchmark / perf test files
        bench_files = (
            list(self.repo.rglob("bench*.py")) +
            list(self.repo.rglob("perf*.py")) +
            list(self.repo.rglob("*benchmark*")) +
            list(self.repo.rglob("locustfile.py")) +
            list(self.repo.rglob("k6*.js"))
        )
        bench_files = [f for f in bench_files if not any(p in f.parts for p in {"venv", ".venv", "node_modules"})]
        checks["has_performance_tests"] = len(bench_files) > 0
        checks["performance_test_count"] = len(bench_files)

        if not bench_files:
            findings.append({
                "rule": "reliability_no_perf_tests",
                "title": "No performance or load tests found",
                "file": "/",
                "line": None,
                "severity": "LOW",
                "layer": "reliability",
                "remediation": "Add baseline performance tests with locust or k6. Define SLA targets (p95 latency, RPS).",
            })
            score -= 10

        # Check for N+1 patterns (ORM loop queries)
        n_plus_one_files = []
        for filepath in self.repo.rglob("*.py"):
            if any(p in filepath.parts for p in {"venv", ".venv", "__pycache__"}):
                continue
            try:
                content = filepath.read_text(errors="replace")
            except Exception:
                continue
            # Heuristic: query inside a for loop
            if re.search(r"for\s+\w+\s+in\s+.+:\s*\n\s+.*\.(filter|get|query|find|execute)\(", content, re.MULTILINE):
                n_plus_one_files.append(str(filepath.relative_to(self.repo)))

        checks["potential_n_plus_one_count"] = len(n_plus_one_files)
        for fp in n_plus_one_files[:3]:
            findings.append({
                "rule": "reliability_n_plus_one",
                "title": f"Possible N+1 query pattern: {fp}",
                "file": fp,
                "line": None,
                "severity": "MEDIUM",
                "layer": "reliability",
                "remediation": "Use select_related() / prefetch_related() (Django) or joinedload() (SQLAlchemy) to batch queries.",
            })
            score -= 8

        return max(0, score), findings, checks
