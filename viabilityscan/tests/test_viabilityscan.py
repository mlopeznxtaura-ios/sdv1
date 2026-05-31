"""
ViabilityScan test suite.
Run: pytest tests/ -v
"""

import json
import tempfile
from pathlib import Path
import pytest

from viabilityscan.engine import ViabilityEngine
from viabilityscan.layers.security_mvp import SecurityMVPLayer
from viabilityscan.layers.deployment import DeploymentLayer
from viabilityscan.layers.reliability import ReliabilityLayer


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def empty_repo(tmp_path):
    """Minimal empty repo."""
    (tmp_path / "README.md").write_text("# Test Repo")
    return tmp_path


@pytest.fixture
def clean_python_repo(tmp_path):
    """Clean Python repo with no obvious issues."""
    (tmp_path / "README.md").write_text("# Clean Repo")
    (tmp_path / "requirements.txt").write_text("flask==3.0.3\nrequests==2.31.0\n")
    (tmp_path / ".gitignore").write_text(".env\n__pycache__/\nvenv/\n")
    (tmp_path / ".env.example").write_text("DATABASE_URL=postgres://user:pass@localhost/db\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\nCOPY . /app\nRUN pip install -e .\n")
    (tmp_path / "Makefile").write_text("test:\n\tpytest tests/\n")

    src = tmp_path / "app"
    src.mkdir()
    (src / "__init__.py").write_text("")
    (src / "main.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n\n"
        "def run():\n"
        "    logger.info('starting')\n"
        "    return True\n"
    )

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "__init__.py").write_text("")
    (tests / "test_main.py").write_text(
        "from app.main import run\n\n"
        "def test_run():\n"
        "    assert run() is True\n"
    )

    ci = tmp_path / ".github" / "workflows"
    ci.mkdir(parents=True)
    (ci / "test.yml").write_text(
        "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: pytest tests/\n"
    )

    return tmp_path


@pytest.fixture
def dirty_repo(tmp_path):
    """Repo with intentional issues for finding detection."""
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        "DEBUG = True\n"
        "password = 'hardcoded123'\n"
        "def bad_hash(val):\n"
        "    return hashlib.md5(val.encode()).hexdigest()\n"
    )
    (tmp_path / ".env").write_text(
        "SECRET_KEY=supersecret\nDATABASE_PASSWORD=mypassword123\n"
    )
    (tmp_path / "requirements.txt").write_text(
        "django==3.2.0\nflask==2.0.0\nlodash==4.17.4\n"
    )
    return tmp_path


# ── Engine tests ─────────────────────────────────────────────────────────────

class TestViabilityEngine:

    def test_runs_on_empty_repo(self, empty_repo):
        engine = ViabilityEngine(empty_repo, full=False)
        result = engine.run()
        assert "gate" in result
        assert result["gate"] in ("PASS", "FAIL")
        assert "scores" in result
        assert 0 <= result["scores"]["viability"] <= 100

    def test_result_structure(self, clean_python_repo):
        engine = ViabilityEngine(clean_python_repo)
        result = engine.run()
        required_keys = ["tool", "version", "repo", "scanned_at", "scores", "gate",
                         "gate_reasons", "layers", "next_frame_prediction", "metadata"]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_scores_in_valid_range(self, clean_python_repo):
        result = ViabilityEngine(clean_python_repo).run()
        for key in ["viability", "security", "deployment", "reliability"]:
            val = result["scores"][key]
            assert 0 <= val <= 100, f"{key} score {val} out of range"

    def test_phase_gate_formula(self):
        engine = ViabilityEngine(Path("."), full=False)
        # Mock scores: all passing
        scores = {"security": 75, "deployment": 65, "reliability": 65}
        v = round(0.4 * 75 + 0.3 * 65 + 0.3 * 65, 1)
        gate, reasons = engine._phase_gate({**scores, "viability": v})
        assert gate == "PASS"
        assert reasons == []

    def test_phase_gate_fails_low_security(self):
        engine = ViabilityEngine(Path("."))
        scores = {"security": 60, "deployment": 65, "reliability": 65, "viability": 63.5}
        gate, reasons = engine._phase_gate(scores)
        assert gate == "FAIL"
        assert any("Security" in r for r in reasons)

    def test_binary_scalar_detects_files(self, clean_python_repo):
        engine = ViabilityEngine(clean_python_repo)
        meta = engine._binary_scalar()
        assert meta["has_dockerfile"] is True
        assert meta["has_ci_github"] is True
        assert meta["has_gitignore"] is True
        assert meta["file_count"] > 0


# ── Security MVP tests ───────────────────────────────────────────────────────

class TestSecurityMVPLayer:

    def test_detects_aws_key(self, dirty_repo):
        layer = SecurityMVPLayer(dirty_repo)
        result = layer.run()
        secret_findings = [f for f in result["findings"] if f["rule"] == "secret_detected"]
        assert len(secret_findings) > 0

    def test_detects_env_with_secrets(self, dirty_repo):
        layer = SecurityMVPLayer(dirty_repo)
        result = layer.run()
        env_findings = [f for f in result["findings"] if "env_committed" in f.get("rule", "")]
        assert len(env_findings) > 0

    def test_detects_debug_true(self, dirty_repo):
        layer = SecurityMVPLayer(dirty_repo)
        result = layer.run()
        debug_findings = [f for f in result["findings"] if "debug" in f.get("rule", "")]
        assert len(debug_findings) > 0

    def test_detects_weak_hash(self, dirty_repo):
        layer = SecurityMVPLayer(dirty_repo)
        result = layer.run()
        hash_findings = [f for f in result["findings"] if "weak_hash" in f.get("rule", "")]
        assert len(hash_findings) > 0

    def test_clean_repo_higher_score(self, clean_python_repo, dirty_repo):
        clean_score = SecurityMVPLayer(clean_python_repo).run()["score"]
        dirty_score = SecurityMVPLayer(dirty_repo).run()["score"]
        assert clean_score > dirty_score

    def test_result_has_required_keys(self, empty_repo):
        result = SecurityMVPLayer(empty_repo).run()
        for key in ["layer", "score", "findings", "finding_count", "severity_counts", "remediations"]:
            assert key in result

    def test_score_range(self, empty_repo):
        result = SecurityMVPLayer(empty_repo).run()
        assert 0 <= result["score"] <= 100

    def test_detects_vulnerable_dependency(self, dirty_repo):
        layer = SecurityMVPLayer(dirty_repo)
        result = layer.run()
        dep_findings = [f for f in result["findings"] if f.get("rule") == "vulnerable_dependency"]
        # django==3.2.0 should trigger
        assert len(dep_findings) > 0


# ── Deployment tests ─────────────────────────────────────────────────────────

class TestDeploymentLayer:

    def test_no_dockerfile_penalized(self, empty_repo):
        result = DeploymentLayer(empty_repo).run()
        dockerfile_findings = [f for f in result["findings"] if "no_dockerfile" in f.get("rule","")]
        assert len(dockerfile_findings) > 0

    def test_no_ci_penalized(self, empty_repo):
        result = DeploymentLayer(empty_repo).run()
        ci_findings = [f for f in result["findings"] if "no_ci" in f.get("rule","")]
        assert len(ci_findings) > 0

    def test_clean_repo_has_ci_detected(self, clean_python_repo):
        result = DeploymentLayer(clean_python_repo).run()
        assert result["checks"].get("has_ci_pipeline") is True

    def test_score_range(self, empty_repo):
        result = DeploymentLayer(empty_repo).run()
        assert 0 <= result["score"] <= 100


# ── Reliability tests ────────────────────────────────────────────────────────

class TestReliabilityLayer:

    def test_no_tests_penalized(self, empty_repo):
        result = ReliabilityLayer(empty_repo).run()
        no_test_findings = [f for f in result["findings"] if "no_tests" in f.get("rule","")]
        assert len(no_test_findings) > 0

    def test_clean_repo_has_tests_detected(self, clean_python_repo):
        result = ReliabilityLayer(clean_python_repo).run()
        assert result["checks"].get("has_tests") is True
        assert result["checks"].get("test_file_count", 0) > 0

    def test_score_range(self, empty_repo):
        result = ReliabilityLayer(empty_repo).run()
        assert 0 <= result["score"] <= 100

    def test_clean_repo_higher_than_empty(self, clean_python_repo, empty_repo):
        clean = ReliabilityLayer(clean_python_repo).run()["score"]
        empty = ReliabilityLayer(empty_repo).run()["score"]
        assert clean >= empty


# ── agents.jsonl integrity test ───────────────────────────────────────────────

class TestAgentsJsonl:

    def test_agents_jsonl_parseable(self):
        agents_file = Path(__file__).parent.parent / "agents.jsonl"
        assert agents_file.exists(), "agents.jsonl not found"
        with open(agents_file) as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                assert "id" in data, f"Line {i+1} missing 'id'"
                assert "title" in data, f"Line {i+1} missing 'title'"
                assert "resolution" in data, f"Line {i+1} missing 'resolution'"
