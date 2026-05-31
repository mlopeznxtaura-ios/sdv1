# ⬡ ViabilityScan v1.0

**Repository Viability & Deployment Readiness Engine**

Determines whether a repository is ready for production deployment using a
phase-gated scoring pipeline across Security, Deployment, and Reliability dimensions.

---

## Quick Start

```bash
# Install (zero heavy dependencies for MVP)
pip install -e .

# Scan current directory
viabilityscan scan .

# Full scan (uses Semgrep/Trivy/Checkov if installed)
viabilityscan scan /path/to/repo --full

# CI mode — exits 1 on FAIL to block pipeline
viabilityscan scan . --ci --output report.json

# Dashboard (requires: pip install nicegui)
python dashboard/app.py   # → http://localhost:8765
```

---

## Phase Gate Formula

```
V = 0.4 × SecurityScore + 0.3 × DeploymentScore + 0.3 × ReliabilityScore

PASS if:  V ≥ 75  AND  Security ≥ 70  AND  Deployment ≥ 60  AND  Reliability ≥ 60
FAIL otherwise → remediation report generated
```

---

## Scan Layers

### MVP (ships today, zero extra installs)

| Layer | Checks |
|-------|--------|
| **Security MVP** | Secret/credential detection (15 patterns), dependency CVE scan, migration validation (Alembic/Flyway), OWASP ASVS Level 1 |
| **Deployment** | Dockerfile hygiene, CI/CD pipeline, health endpoints, observability (logging/metrics/tracing), rollback docs |
| **Reliability** | Test file ratio, assertion coverage, coverage config, cyclomatic complexity heuristic, N+1 query detection |

### Full (`--full`, requires external tools)

| Tool | What it adds |
|------|-------------|
| `semgrep` | Deep SAST with auto rules |
| `trivy` | Container + filesystem CVE scanning |
| `checkov` | IaC scanning (Terraform, K8s, Dockerfile) |
| `codeql` | Deep semantic analysis (CI only — see agents.jsonl gap-004) |

---

## Output

```
============================================================
  ViabilityScan v1.0  —  my-repo
============================================================

────────────────────────────────────────────────────────────
  PHASE GATE:  ❌ FAIL
────────────────────────────────────────────────────────────
  Viability Score :   61.5  (threshold ≥75)
  Security        :   55.0  (threshold ≥70)
  Deployment      :   65.0  (threshold ≥60)
  Reliability     :   70.0  (threshold ≥60)
...
  📄  Full report saved: viability_report.json
```

JSON report structure:
```json
{
  "gate": "FAIL",
  "scores": { "viability": 61.5, "security": 55, "deployment": 65, "reliability": 70 },
  "gate_reasons": ["Viability 61.5 < 75", "Security 55 < 70"],
  "layers": { "security_mvp": {...}, "deployment": {...}, "reliability": {...} },
  "next_frame_prediction": "..."
}
```

---

## GitHub Actions Integration

Copy `.github/workflows/viabilityscan.yml` to your repo. On every PR:
- Runs the MVP scan
- Posts a score card comment to the PR
- Blocks merge if gate is FAIL

---

## Agent Gaps

`agents.jsonl` documents 15 known gaps — unresolved environment/network constraints,
tool dependencies, and calibration tasks. Each gap includes:
- `agent` — which agent type should resolve it
- `resolution` — exact command or approach
- `score_impact` — effect on viability score when resolved

Run `cat agents.jsonl | python -c "import sys,json; [print(json.loads(l)['id'], json.loads(l)['title']) for l in sys.stdin]"` to list all gaps.

---

## Architecture

```
ViabilityEngine (orchestrator)
  ├── M1 UnboundedThinker  — scans all layers, generates findings
  ├── M2 EfficiencyZealot  — prunes duplicates, caps noise
  ├── M3 MetaObserver      — weights findings, computes score
  │
  ├── SecurityMVPLayer     — secrets, SCA, migrations, ASVS
  ├── DeploymentLayer      — build, rollback, observability, CI
  ├── ReliabilityLayer     — tests, coverage, complexity, perf
  └── SecurityFullLayer    — Semgrep, Trivy, Checkov, CodeQL*
```

---

## Evolution Roadmap (from spec)

- **Phase 1** ✅ MVP (secret scanning, dep check, migration validation, ASVS L1)
- **Phase 2** Add Semgrep + CodeQL (gap-001, gap-004)
- **Phase 3** Container + IaC scanning (gap-002, gap-003)
- **Phase 4** Deployment checks: rollback drill, observability
- **Phase 5** Reliability: actual coverage %, mutation testing
- **Phase 6** Calibrate weights vs. known good/bad repos (gap-006)

---

## Sources & Verification

- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
- TruffleHog: https://docs.trufflesecurity.com/
- Alembic: https://alembic.sqlalchemy.org/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OSV vulnerability database: https://osv.dev/
