"""
Django Migration Versioning Layer
Checks: migration tracking, naming conventions, git-tracked migrations,
rollback readiness, migration safety tooling.
"""

import re
from pathlib import Path
from viabilityscan.layers.base import BaseLayer

# Known Django migration filename patterns
MIGRATION_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.py$")
INITIAL_RE = re.compile(r"^0001_initial\.py$")


class DjangoMigrationsLayer(BaseLayer):
    name = "django_migrations"
    description = "Migration versioning, git tracking, naming, safety tooling"

    def run(self) -> dict:
        findings = []
        remediations = []
        checks = {}

        # 0. Is this a Django project at all?
        is_django = self._is_django_project()
        checks["is_django_project"] = is_django

        if not is_django:
            return {
                "layer": self.name,
                "score": 100,
                "findings": [],
                "finding_count": 0,
                "severity_counts": self._count_severities([]),
                "checks": checks,
                "remediations": ["Not a Django project — migration checks skipped."],
            }

        # 1. Migration file naming & structure
        score_naming, f_naming, c_naming = self._check_naming()
        findings.extend(f_naming)
        checks.update(c_naming)

        # 2. Git tracking of migrations
        score_git, f_git, c_git = self._check_git_tracking()
        findings.extend(f_git)
        checks.update(c_git)

        # 3. Migration count & health
        score_count, f_count, c_count = self._check_migration_health()
        findings.extend(f_count)
        checks.update(c_count)

        # 4. Migration safety tooling
        score_tools, f_tools, c_tools = self._check_safety_tools()
        findings.extend(f_tools)
        checks.update(c_tools)

        # 5. Squashed / stale migrations
        score_squash, f_squash, c_squash = self._check_squashed()
        findings.extend(f_squash)
        checks.update(c_squash)

        score = round((score_naming + score_git + score_count + score_tools + score_squash) / 5)

        for f in findings:
            if f.get("severity") in ("HIGH", "CRITICAL"):
                remediations.append(
                    f"[{f['severity']}] {f['title']}: {f.get('remediation', '')}"
                )
        if not remediations:
            remediations.append(
                "Django migration hygiene is solid. Consider periodic migration squash and CI linting."
            )

        return {
            "layer": self.name,
            "score": score,
            "findings": findings,
            "finding_count": len(findings),
            "severity_counts": self._count_severities(findings),
            "checks": checks,
            "remediations": remediations[:8],
        }

    # ── helpers ──────────────────────────────────────────────────────────

    def _is_django_project(self) -> bool:
        """Heuristic: manage.py exists and has django imports, or settings.py exists."""
        manage = self.repo / "manage.py"
        if manage.exists():
            try:
                content = manage.read_text(errors="replace")
                if "django" in content.lower():
                    return True
            except Exception:
                pass
        # Also check for Django settings module
        for p in self.repo.rglob("settings.py"):
            try:
                content = p.read_text(errors="replace")
                if "django" in content.lower() and "SECRET_KEY" in content:
                    return True
            except Exception:
                continue
        return False

    def _find_migration_dirs(self) -> list[Path]:
        """Find all Django migrations/ directories."""
        dirs = []
        for p in self.repo.rglob("migrations"):
            if p.is_dir() and not any(x in p.parts for x in {"__pycache__", "venv", ".venv", "node_modules"}):
                # Must contain at least one migration .py file (not just __init__)
                py_files = [f for f in p.glob("*.py") if f.name != "__init__.py"]
                if py_files:
                    dirs.append(p)
        return dirs

    def _get_all_migration_files(self, migration_dirs: list[Path]) -> list[Path]:
        files = []
        for d in migration_dirs:
            for f in d.glob("*.py"):
                if f.name != "__init__.py":
                    files.append(f)
        return files

    # ── checks ───────────────────────────────────────────────────────────

    def _check_naming(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        migration_dirs = self._find_migration_dirs()
        all_files = self._get_all_migration_files(migration_dirs)
        checks["migration_dir_count"] = len(migration_dirs)
        checks["migration_file_count"] = len(all_files)

        bad_names = []
        for f in all_files:
            if not MIGRATION_RE.match(f.name):
                bad_names.append(str(f.relative_to(self.repo)))

        if bad_names:
            findings.append({
                "rule": "django_bad_migration_names",
                "title": f"{len(bad_names)} migration file(s) don't follow Django naming convention (NNNN_description.py)",
                "file": bad_names[0] if len(bad_names) == 1 else f"{bad_names[0]} (+{len(bad_names)-1} more)",
                "line": None,
                "severity": "MEDIUM",
                "layer": "django_migrations",
                "remediation": "Rename migrations to follow the NNNN_descriptive_name.py convention (e.g., 0002_add_email_field.py).",
            })
            score -= 20 * min(len(bad_names), 3)

        checks["badly_named_count"] = len(bad_names)
        return max(0, score), findings, checks

    def _check_git_tracking(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        git_dir = self.repo / ".git"
        if not git_dir.exists():
            checks["git_tracked"] = False
            findings.append({
                "rule": "django_no_git",
                "title": "No .git directory — cannot verify migration tracking",
                "file": "/",
                "line": None,
                "severity": "INFO",
                "layer": "django_migrations",
                "remediation": "Initialize git and commit migration files to ensure versioned schema history.",
            })
            return 100, findings, checks  # don't penalize — not their fault

        checks["git_tracked"] = True

        # Check for .gitignore patterns that might exclude migrations
        gitignore = self.repo / ".gitignore"
        excludes_migrations = False
        if gitignore.exists():
            try:
                for line in gitignore.read_text().splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        if "migrations" in stripped and not stripped.startswith("!"):
                            excludes_migrations = True
                            break
            except Exception:
                pass

        checks["gitignore_excludes_migrations"] = excludes_migrations
        if excludes_migrations:
            findings.append({
                "rule": "django_migrations_gitignored",
                "title": ".gitignore appears to exclude migration files",
                "file": ".gitignore",
                "line": None,
                "severity": "CRITICAL",
                "layer": "django_migrations",
                "remediation": "Remove 'migrations' from .gitignore. Django migrations MUST be tracked in version control. Only ignore __pycache__.",
            })
            score -= 50

        # Check if migration files are actually tracked (via git ls-files)
        import subprocess
        migration_dirs = self._find_migration_dirs()
        all_files = self._get_all_migration_files(migration_dirs)
        untracked = []
        for f in all_files:
            try:
                result = subprocess.run(
                    ["git", "ls-files", "--error-unmatch", str(f.relative_to(self.repo))],
                    cwd=str(self.repo), capture_output=True,
                )
                if result.returncode != 0:
                    untracked.append(str(f.relative_to(self.repo)))
            except Exception:
                continue

        checks["untracked_migration_count"] = len(untracked)
        if untracked:
            findings.append({
                "rule": "django_untracked_migrations",
                "title": f"{len(untracked)} migration file(s) not tracked by git",
                "file": untracked[0] if len(untracked) == 1 else f"{untracked[0]} (+{len(untracked)-1} more)",
                "line": None,
                "severity": "CRITICAL",
                "layer": "django_migrations",
                "remediation": "Run `git add <migration>` and commit. Untracked migrations break deploys across environments.",
            })
            score -= 40

        return max(0, score), findings, checks

    def _check_migration_health(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        migration_dirs = self._find_migration_dirs()
        all_files = self._get_all_migration_files(migration_dirs)

        if not all_files:
            findings.append({
                "rule": "django_no_migrations",
                "title": "No migration files found in any app",
                "file": "/",
                "line": None,
                "severity": "HIGH",
                "layer": "django_migrations",
                "remediation": "Run `python manage.py makemigrations` to generate initial migrations for your models.",
            })
            return 0, findings, checks

        # Check for initial migration presence
        has_initial = any(INITIAL_RE.match(f.name) for f in all_files)
        checks["has_initial_migration"] = has_initial
        if not has_initial:
            findings.append({
                "rule": "django_no_initial",
                "title": "No 0001_initial migration found — schema baseline missing",
                "file": "migrations/",
                "line": None,
                "severity": "HIGH",
                "layer": "django_migrations",
                "remediation": "Ensure each app has a 0001_initial.py migration defining the baseline schema.",
            })
            score -= 25

        # Check for sequential numbering gaps
        for mdir in migration_dirs:
            numbers = []
            for f in mdir.glob("*.py"):
                m = re.match(r"^(\d{4})_", f.name)
                if m and f.name != "__init__.py":
                    numbers.append(int(m.group(1)))
            numbers.sort()
            if numbers and numbers[0] != 1:
                findings.append({
                    "rule": "django_migration_gap",
                    "title": f"Migration numbering starts at {numbers[0]:04d}, not 0001",
                    "file": str(mdir.relative_to(self.repo)),
                    "line": None,
                    "severity": "MEDIUM",
                    "layer": "django_migrations",
                    "remediation": "Migration numbers should start at 0001. Squash and renumber if needed.",
                })
                score -= 10
                break

        # Check total migration count per app (flag if excessive)
        for mdir in migration_dirs:
            count = len([f for f in mdir.glob("*.py") if f.name != "__init__.py"])
            if count > 50:
                findings.append({
                    "rule": "django_too_many_migrations",
                    "title": f"App '{mdir.parent.name}' has {count} migrations — consider squashing",
                    "file": str(mdir.relative_to(self.repo)),
                    "line": None,
                    "severity": "LOW",
                    "layer": "django_migrations",
                    "remediation": "Run `python manage.py squashmigrations <app> <last_num>` to consolidate migration history.",
                })
                score -= 5

        checks["total_migration_dirs"] = len(migration_dirs)
        return max(0, score), findings, checks

    def _check_safety_tools(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        # Check for django-migration-linter
        has_linter = False
        for f in self.repo.rglob("*.cfg"):
            try:
                if "django_migration_linter" in f.read_text(errors="replace"):
                    has_linter = True
                    break
            except Exception:
                continue
        for f in self.repo.rglob("*.toml"):
            try:
                if "django-migration-linter" in f.read_text(errors="replace"):
                    has_linter = True
                    break
            except Exception:
                continue
        for f in self.repo.rglob("*.ini"):
            try:
                if "django_migration_linter" in f.read_text(errors="replace"):
                    has_linter = True
                    break
            except Exception:
                continue
        checks["has_migration_linter"] = has_linter

        if not has_linter:
            findings.append({
                "rule": "django_no_migration_linter",
                "title": "No django-migration-linter detected",
                "file": "pyproject.toml / setup.cfg",
                "line": None,
                "severity": "MEDIUM",
                "layer": "django_migrations",
                "remediation": "Add django-migration-linter to dev dependencies and CI to catch backward-incompatible migrations before deploy.",
            })
            score -= 15

        # Check for CI step that runs migration checks
        ci_files = (
            list(self.repo.rglob(".github/workflows/*.yml")) +
            list(self.repo.rglob(".github/workflows/*.yaml")) +
            list(self.repo.rglob(".gitlab-ci.yml"))
        )
        has_ci_migration_check = False
        for ci in ci_files:
            try:
                content = ci.read_text(errors="replace")
                if any(kw in content for kw in ("makemigrations --check", "migration-linter", "migrate --check")):
                    has_ci_migration_check = True
                    break
            except Exception:
                continue
        checks["ci_has_migration_check"] = has_ci_migration_check

        if not has_ci_migration_check and ci_files:
            findings.append({
                "rule": "django_no_ci_migration_check",
                "title": "CI pipeline does not check for missing migrations",
                "file": ".github/workflows/",
                "line": None,
                "severity": "HIGH",
                "layer": "django_migrations",
                "remediation": "Add `python manage.py makemigrations --check --dry-run` to CI to catch missing migrations before merge.",
            })
            score -= 20

        # Check for django-migration-checker or similar in requirements
        has_dep = False
        for f in self.repo.rglob("requirements*.txt"):
            try:
                if "django-migration" in f.read_text(errors="replace"):
                    has_dep = True
                    break
            except Exception:
                continue
        checks["has_migration_dependency"] = has_dep

        return max(0, score), findings, checks

    def _check_squashed(self) -> tuple[int, list, dict]:
        findings = []
        checks = {}
        score = 100

        migration_dirs = self._find_migration_dirs()
        all_files = self._get_all_migration_files(migration_dirs)

        # Check for squashed migrations
        squashed = [f for f in all_files if "squashed" in f.name.lower()]
        replaced = [f for f in all_files if f.name.replace(".py", "").endswith("_squashed_0001")]
        checks["squashed_migration_count"] = len(squashed)

        if squashed:
            # Good — they're squashing. But check if originals are still around.
            for sq in squashed:
                m = re.match(r"^(\d{4})_.*squashed.*_(\d{4})", sq.name)
                if m:
                    low, high = int(m.group(1)), int(m.group(2))
                    mdir = sq.parent
                    for f in mdir.glob("*.py"):
                        num_match = re.match(r"^(\d{4})_", f.name)
                        if num_match and f.name != "__init__.py" and f != sq:
                            num = int(num_match.group(1))
                            if low <= num <= high:
                                findings.append({
                                    "rule": "django_unsquashed_duplicates",
                                    "title": f"Migration {f.name} exists alongside squashed migration {sq.name}",
                                    "file": str(f.relative_to(self.repo)),
                                    "line": None,
                                    "severity": "MEDIUM",
                                    "layer": "django_migrations",
                                    "remediation": "After squashing, replace the original migrations in the `replaces` list with the squashed one, then delete or archive the originals.",
                                })
                                score -= 10
                                break

        return max(0, score), findings, checks