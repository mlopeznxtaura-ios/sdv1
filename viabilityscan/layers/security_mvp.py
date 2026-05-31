"""
Security MVP Layer
Covers: secret detection, dependency scanning, migration validation, ASVS Level 1 basics.
Sources: TruffleHog docs, OWASP Dependency-Check, Alembic/Flyway docs, OWASP ASVS
"""

import re
from pathlib import Path
from viabilityscan.layers.base import BaseLayer


# ── Secret pattern catalogue (regex-based TruffleHog-equivalent) ──────────
SECRET_PATTERNS = [
    ("AWS Access Key",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key",      re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("GitHub Token",        re.compile(r"ghp_[0-9a-zA-Z]{36}")),
    ("GitHub OAuth",        re.compile(r"gho_[0-9a-zA-Z]{36}")),
    ("GitHub App Token",    re.compile(r"ghs_[0-9a-zA-Z]{36}")),
    ("Slack Token",         re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}")),
    ("Stripe Secret Key",   re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Publishable",  re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("Google API Key",      re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Heroku API Key",      re.compile(r"[hH]eroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    ("Generic Password",    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
    ("Generic Secret",      re.compile(r"(?i)(secret|api_key|apikey|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("Private Key Header",  re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Basic Auth in URL",   re.compile(r"https?://[^:@\s]{1,40}:[^:@\s]{1,40}@")),
    ("Database URL w/ creds", re.compile(r"(postgres|mysql|mongodb)://[^:@\s]+:[^:@\s]+@")),
]

# Files/dirs to skip during secret scan
SECRET_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
                   ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
                   ".pyc", ".pyo", ".class", ".so", ".dll", ".exe", ".bin"}
SECRET_SKIP_DIRS = {".git", "__pycache__", "node_modules", "venv", ".venv", "dist", "build"}

# Known-vulnerable dependency patterns (representative subset; full list → agents.jsonl gap)
VULN_DEPS = {
    "django": [("< 4.2.8", "CVE-2024-27351", "HIGH", "Open redirect"),
               ("< 3.2.23", "CVE-2023-41164", "HIGH", "ReDoS")],
    "flask":  [("< 3.0.0", "CVE-2023-30861", "HIGH", "Cookie security")],
    "requests": [("< 2.31.0", "CVE-2023-32681", "MEDIUM", "Proxy header leak")],
    "cryptography": [("< 41.0.0", "CVE-2023-38325", "HIGH", "SSH cert bypass")],
    "pillow": [("< 10.0.1", "CVE-2023-44271", "HIGH", "DoS via crafted image")],
    "werkzeug": [("< 3.0.3", "CVE-2024-34069", "HIGH", "Debugger RCE")],
    "urllib3": [("< 2.0.7", "CVE-2023-45803", "MEDIUM", "Header injection")],
    "jinja2": [("< 3.1.3", "CVE-2024-22195", "MEDIUM", "XSS via HTML attrs")],
    "paramiko": [("< 3.4.0", "CVE-2023-48795", "MEDIUM", "Terrapin attack")],
    "sqlalchemy": [("< 2.0.0", "CVE-2019-7164", "MEDIUM", "SQL injection via order_by")],
    "express": [("< 4.19.0", "CVE-2024-29041", "MEDIUM", "Open redirect")],
    "lodash": [("< 4.17.21", "CVE-2021-23337", "HIGH", "Command injection")],
    "axios": [("< 1.6.0", "CVE-2023-45857", "MEDIUM", "CSRF token exposure")],
}


class SecurityMVPLayer(BaseLayer):
    """
    MVP Security Layer:
    1. Secret/credential scanning (TruffleHog-equivalent patterns)
    2. Dependency vulnerability scanning (OWASP Dependency-Check-equivalent)
    3. Migration file validation (Alembic/Flyway governance)
    4. ASVS Level 1 basic checks
    """

    name = "security_mvp"
    description = "Secret scanning, SCA, migration governance, ASVS L1"

    def run(self) -> dict:
        findings = []
        remediations = []

        # 1. Secret scanning
        secret_findings, secret_score_penalty = self._scan_secrets()
        findings.extend(secret_findings)

        # 2. Dependency scanning
        dep_findings, dep_score_penalty = self._scan_dependencies()
        findings.extend(dep_findings)

        # 3. Migration validation
        mig_findings, mig_score_penalty = self._scan_migrations()
        findings.extend(mig_findings)

        # 4. ASVS Level 1
        asvs_findings, asvs_score_penalty = self._scan_asvs_l1()
        findings.extend(asvs_findings)

        # Score: start at 100, subtract penalties
        total_penalty = min(100, secret_score_penalty + dep_score_penalty +
                            mig_score_penalty + asvs_score_penalty)
        score = max(0, 100 - total_penalty)

        # Build remediations from findings
        critical = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
        for f in critical[:5]:
            remediations.append(f"Fix {f['severity']}: {f['title']} in {f.get('file','?')}")
        if not remediations:
            remediations.append("No critical issues found. Maintain dependency updates.")

        return {
            "layer": self.name,
            "score": score,
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": self._count_severities(findings),
            "remediations": remediations,
            "checks_run": ["secret_scan", "dependency_scan", "migration_validation", "asvs_l1"],
            "sources": [
                "https://docs.trufflesecurity.com/",
                "https://owasp.org/www-project-dependency-check/",
                "https://alembic.sqlalchemy.org/",
                "https://owasp.org/www-project-application-security-verification-standard/"
            ]
        }

    # ── 1. Secret Scanning ─────────────────────────────────────────────────

    def _scan_secrets(self) -> tuple[list, int]:
        findings = []
        penalty = 0

        for filepath in self.repo.rglob("*"):
            if not filepath.is_file():
                continue
            if filepath.suffix.lower() in SECRET_SKIP_EXT:
                continue
            if any(p in filepath.parts for p in SECRET_SKIP_DIRS):
                continue
            # Skip .env files in gitignore (but flag if not gitignored)
            rel = filepath.relative_to(self.repo)
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for pattern_name, pattern in SECRET_PATTERNS:
                for m in pattern.finditer(content):
                    line_no = content[:m.start()].count("\n") + 1
                    sev = "CRITICAL" if pattern_name in ("Private Key Header", "AWS Access Key", "AWS Secret Key") else "HIGH"
                    findings.append({
                        "rule": "secret_detected",
                        "title": f"Potential secret: {pattern_name}",
                        "file": str(rel),
                        "line": line_no,
                        "severity": sev,
                        "layer": "secret_scan",
                        "remediation": f"Rotate the credential and use a secrets manager (Vault, AWS Secrets Manager). Remove from history with git-filter-repo.",
                    })
                    penalty += 20 if sev == "CRITICAL" else 10

        return findings, min(penalty, 60)

    # ── 2. Dependency Scanning ─────────────────────────────────────────────

    def _scan_dependencies(self) -> tuple[list, int]:
        findings = []
        penalty = 0
        deps = self._collect_deps()

        for dep_name, version_str in deps.items():
            dep_lower = dep_name.lower().replace("-", "").replace("_", "")
            for vuln_dep, vuln_list in VULN_DEPS.items():
                if dep_lower == vuln_dep.replace("-", "").replace("_", ""):
                    for constraint, cve, sev, desc in vuln_list:
                        findings.append({
                            "rule": "vulnerable_dependency",
                            "title": f"{dep_name} {version_str} — {cve}",
                            "file": "requirements.txt / package.json",
                            "line": None,
                            "severity": sev,
                            "layer": "dependency_scan",
                            "cve": cve,
                            "description": desc,
                            "remediation": f"Upgrade {dep_name} to version satisfying: {constraint}",
                        })
                        penalty += 15 if sev == "HIGH" else 8

        # Flag if no lockfile
        has_lockfile = any([
            (self.repo / "requirements.txt").exists(),
            (self.repo / "poetry.lock").exists(),
            (self.repo / "Pipfile.lock").exists(),
            (self.repo / "package-lock.json").exists(),
            (self.repo / "yarn.lock").exists(),
            (self.repo / "pnpm-lock.yaml").exists(),
        ])
        if not has_lockfile:
            findings.append({
                "rule": "no_lockfile",
                "title": "No dependency lockfile found",
                "file": "/",
                "line": None,
                "severity": "MEDIUM",
                "layer": "dependency_scan",
                "remediation": "Add a lockfile (poetry.lock, package-lock.json) for reproducible builds.",
            })
            penalty += 5

        return findings, min(penalty, 40)

    def _collect_deps(self) -> dict[str, str]:
        deps = {}
        # Python: requirements.txt
        req = self.repo / "requirements.txt"
        if req.exists():
            for line in req.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([>=<!]{1,2}.+)?", line)
                    if m:
                        deps[m.group(1)] = m.group(2) or "unspecified"
        # Node: package.json
        pj = self.repo / "package.json"
        if pj.exists():
            try:
                import json
                data = json.loads(pj.read_text(errors="replace"))
                for section in ("dependencies", "devDependencies"):
                    for k, v in data.get(section, {}).items():
                        deps[k] = v
            except Exception:
                pass
        return deps

    # ── 3. Migration Validation ────────────────────────────────────────────

    def _scan_migrations(self) -> tuple[list, int]:
        findings = []
        penalty = 0

        # Find migration directories
        migration_dirs = []
        for candidate in ["migrations", "alembic", "db/migrations", "database/migrations"]:
            p = self.repo / candidate
            if p.exists():
                migration_dirs.append(p)

        if not migration_dirs:
            # Not necessarily a problem — note it
            return [], 0

        for mdir in migration_dirs:
            migration_files = sorted(mdir.rglob("*.py")) + sorted(mdir.rglob("*.sql"))

            # Check for sequential naming (Alembic revision IDs or numeric prefixes)
            names = [f.stem for f in migration_files]
            duplicates = [n for n in names if names.count(n) > 1]
            for dup in set(duplicates):
                findings.append({
                    "rule": "migration_duplicate",
                    "title": f"Duplicate migration identifier: {dup}",
                    "file": str(mdir.relative_to(self.repo)),
                    "line": None,
                    "severity": "HIGH",
                    "layer": "migration_validation",
                    "remediation": "Ensure each migration has a unique revision ID. Regenerate conflicting migrations.",
                })
                penalty += 15

            # Check for missing downgrade (Alembic)
            for mf in mdir.rglob("*.py"):
                content = mf.read_text(errors="replace")
                if "def upgrade" in content and "def downgrade" not in content:
                    findings.append({
                        "rule": "migration_no_downgrade",
                        "title": f"Migration missing downgrade(): {mf.name}",
                        "file": str(mf.relative_to(self.repo)),
                        "line": None,
                        "severity": "MEDIUM",
                        "layer": "migration_validation",
                        "remediation": "Add a downgrade() function to support rollbacks. Required for production deployments.",
                    })
                    penalty += 5

        return findings, min(penalty, 25)

    # ── 4. ASVS Level 1 Basics ────────────────────────────────────────────

    def _scan_asvs_l1(self) -> tuple[list, int]:
        """
        OWASP ASVS Level 1 — basic automated checks.
        V1: Arch/Design, V2: Auth, V3: Session, V5: Validation, V9: Comms, V14: Config
        """
        findings = []
        penalty = 0

        # V9.1.1 — HTTPS enforcement check (look for http:// hardcoded endpoints)
        for filepath in self.repo.rglob("*.py"):
            if any(p in filepath.parts for p in SECRET_SKIP_DIRS):
                continue
            try:
                content = filepath.read_text(errors="replace")
            except Exception:
                continue
            rel = filepath.relative_to(self.repo)

            # V9: Hardcoded HTTP (non-localhost)
            for m in re.finditer(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[\w\.\-]+', content):
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "rule": "asvs_v9_http_not_https",
                    "title": f"Hardcoded HTTP URL (not HTTPS): {m.group()[:60]}",
                    "file": str(rel),
                    "line": line_no,
                    "severity": "MEDIUM",
                    "layer": "asvs_l1",
                    "remediation": "Use HTTPS for all external communications (ASVS V9.1.1).",
                })
                penalty += 3

            # V14.3.2 — Debug mode detection
            for m in re.finditer(r'(?i)(DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True)', content):
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "rule": "asvs_v14_debug_enabled",
                    "title": "Debug mode enabled in source",
                    "file": str(rel),
                    "line": line_no,
                    "severity": "HIGH",
                    "layer": "asvs_l1",
                    "remediation": "Set DEBUG=False in production. Use environment variable: DEBUG=$DEBUG (ASVS V14.3.2).",
                })
                penalty += 10

            # V2.1.1 — Weak hash algorithms
            for m in re.finditer(r'(?i)\b(md5|sha1)\s*\(', content):
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "rule": "asvs_v2_weak_hash",
                    "title": f"Weak cryptographic hash: {m.group(1).upper()}",
                    "file": str(rel),
                    "line": line_no,
                    "severity": "MEDIUM",
                    "layer": "asvs_l1",
                    "remediation": "Use SHA-256 or bcrypt/argon2 for passwords (ASVS V2.4.1).",
                })
                penalty += 5

            # V5.2 — SQL injection risk (string formatting in queries)
            for m in re.finditer(r'(?i)(execute|raw)\s*\(\s*[f"\'].*\{.*\}', content):
                line_no = content[:m.start()].count("\n") + 1
                findings.append({
                    "rule": "asvs_v5_sql_injection",
                    "title": "Possible SQL injection: f-string in query",
                    "file": str(rel),
                    "line": line_no,
                    "severity": "HIGH",
                    "layer": "asvs_l1",
                    "remediation": "Use parameterized queries or ORM methods. Never interpolate user input (ASVS V5.3.4).",
                })
                penalty += 12

        # V14.2.1 — .env file committed check
        env_file = self.repo / ".env"
        if env_file.exists():
            content = env_file.read_text(errors="replace")
            if any(p in content for p in ["SECRET", "PASSWORD", "KEY", "TOKEN"]):
                findings.append({
                    "rule": "asvs_v14_env_committed",
                    "title": ".env file with secrets appears committed",
                    "file": ".env",
                    "line": None,
                    "severity": "CRITICAL",
                    "layer": "asvs_l1",
                    "remediation": "Add .env to .gitignore immediately. Rotate all credentials. Use .env.example for documentation.",
                })
                penalty += 25

        return findings, min(penalty, 50)
