/**
 * Deep Heuristic Scanner — structural code analysis
 * Goes well beyond regex to analyze code quality, dependency risks, CI gaps, and architecture.
 */

export function deepScan(code, mode) {
  const findings = [];
  const metadata = extractMetadata(code);
  const lang = metadata.dominantLanguage;

  let secScore = 100, depScore = 100, relScore = 100;

  // ═══ SECURITY (40%) ═══
  secScore -= checkSecrets(code, findings);
  secScore -= checkDebugMode(code, findings);
  secScore -= checkInputValidation(code, findings, lang);
  secScore -= checkDependencyRisks(code, findings);
  secScore -= checkAuthPatterns(code, findings, lang);
  secScore -= checkFilePermissions(code, findings);
  secScore -= checkCORSConfig(code, findings);
  secScore -= checkSQLInjection(code, findings, lang);

  // ═══ DEPLOYMENT (30%) ═══
  depScore -= checkDockerQuality(code, findings);
  depScore -= checkHealthEndpoints(code, findings);
  depScore -= checkCICDPipeline(code, findings);
  depScore -= checkObservability(code, findings);
  depScore -= checkConfigManagement(code, findings);
  depScore -= checkBuildReproducibility(code, findings);

  // ═══ RELIABILITY (30%) ═══
  relScore -= checkErrorHandling(code, findings, lang);
  relScore -= checkLogging(code, findings, lang);
  relScore -= checkTestCoverage(code, findings);
  relScore -= checkTypeSafety(code, findings, lang);
  relScore -= checkDocumentation(code, findings);
  relScore -= checkConcurrencySafety(code, findings, lang);
  relScore -= checkGracefulShutdown(code, findings, lang);

  secScore = Math.max(0, Math.round(secScore));
  depScore = Math.max(0, Math.round(depScore));
  relScore = Math.max(0, Math.round(relScore));
  const viability = Math.round(0.4 * secScore + 0.3 * depScore + 0.3 * relScore);
  const gate = (viability >= 75 && secScore >= 70 && depScore >= 60 && relScore >= 60) ? 'PASS' : 'FAIL';
  const reasons = [];
  if (viability < 75) reasons.push(`Viability ${viability} < 75`);
  if (secScore < 70) reasons.push(`Security ${secScore} < 70`);
  if (depScore < 60) reasons.push(`Deployment ${depScore} < 60`);
  if (relScore < 60) reasons.push(`Reliability ${relScore} < 60`);

  return {
    tool: 'ViabilityScan', version: '1.1.0',
    scanned_at: new Date().toISOString(), mode: mode || 'mvp',
    metadata,
    scores: { security: secScore, deployment: depScore, reliability: relScore, viability },
    gate, gate_reasons: reasons,
    layers: {
      security_mvp: makeLayer('security_mvp', secScore, findings),
      deployment: makeLayer('deployment', depScore, findings),
      reliability: makeLayer('reliability', relScore, findings),
      django_migrations: {
        layer: 'django_migrations', score: 100, findings: [], finding_count: 0,
        severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        checks: { is_django_project: /django|manage\.py|makemigrations|migrations\./i.test(code) },
        remediations: [],
      },
    },
    next_frame_prediction: buildPrediction(gate, secScore, depScore, relScore, findings),
    driver: 'Deep Heuristic Engine v1.1',
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// SECURITY CHECKS
// ══════════════════════════════════════════════════════════════════════════════

function checkSecrets(code, findings) {
  let penalty = 0;
  const patterns = [
    { re: /(api[_-]?key|apikey|secret|token)\s*[:=]\s*['"][A-Za-z0-9_\-]{12,}['"]/gi, msg: 'Hardcoded API key/secret/token', sev: 'CRITICAL', rem: 'Use environment variables or a secrets manager (IBM Secrets Manager, Vault). Never commit secrets.' },
    { re: /(password|passwd|pwd)\s*[:=]\s*['"][^'"]{3,}['"]/gi, msg: 'Hardcoded password in source', sev: 'CRITICAL', rem: 'Store passwords in a secrets manager. Use hashed values only.' },
    { re: /sk-(live|test)-[A-Za-z0-9]{20,}/g, msg: 'Stripe/OpenAI-style secret key', sev: 'CRITICAL', rem: 'Move to environment variable immediately and rotate the key.' },
    { re: /gh[po]_[A-Za-z0-9]{20,}/g, msg: 'GitHub personal access token', sev: 'CRITICAL', rem: 'Revoke this token immediately. Use gh CLI OAuth or short-lived tokens.' },
    { re: /AKIA[0-9A-Z]{16}/g, msg: 'AWS access key ID exposed', sev: 'CRITICAL', rem: 'Use IAM roles or environment variables. Never hardcode AWS credentials.' },
    { re: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----/g, msg: 'Private key in source code', sev: 'CRITICAL', rem: 'Private keys must never be in source. Use HSMs or secure key stores.' },
    { re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, msg: 'JWT token in source (potential credential)', sev: 'HIGH', rem: 'JWTs in source may indicate leaked credentials. Verify and rotate if needed.' },
    { re: /mongodb(\+srv)?:\/\/[^@\s]+@/g, msg: 'Database connection string with credentials', sev: 'CRITICAL', rem: 'Use environment variables for connection strings. Never hardcode DB credentials.' },
    { re: /postgres(ql)?:\/\/[^@\s]+@/g, msg: 'Database URL with embedded credentials', sev: 'CRITICAL', rem: 'Move database URLs to environment variables.' },
  ];
  for (const p of patterns) {
    const matches = [...code.matchAll(p.re)];
    if (matches.length > 0) {
      // Skip if all matches are in test files
      const nonTestMatches = matches.filter(m => {
        const before = code.slice(0, m.index);
        const lastMarker = before.lastIndexOf('# === ');
        if (lastMarker === -1) return true;
        const section = before.slice(lastMarker, lastMarker + 100);
        return !/test/i.test(section);
      });
      if (nonTestMatches.length === 0) continue;
      
      findings.push({
        title: p.msg + (nonTestMatches.length > 1 ? ` (${nonTestMatches.length} instances)` : ''),
        severity: p.sev, file: 'source', line: null, layer: 'security_mvp',
        remediation: p.rem,
      });
      penalty += p.sev === 'CRITICAL' ? 30 : 15;
    }
  }
  return Math.min(penalty, 60);
}

function checkDebugMode(code, findings) {
  let penalty = 0;
  // Check for DEBUG=True, but skip test files
  const debugMatch = /\bDEBUG\s*=\s*True\b/i.exec(code) || /\bdebug\s*:\s*true\b/i.exec(code);
  if (debugMatch) {
    // Check if match is in a test section
    const before = code.slice(0, debugMatch.index);
    const lastMarker = before.lastIndexOf('# === ');
    if (lastMarker !== -1) {
      const section = before.slice(lastMarker, lastMarker + 100);
      if (!/test/i.test(section)) {
        findings.push({
          title: 'Debug mode enabled — leaks stack traces and internals',
          severity: 'HIGH', file: 'source', line: null, layer: 'security_mvp',
          remediation: 'Set DEBUG=False in production. Use environment-specific config.',
        });
        penalty += 20;
      }
    } else {
      findings.push({
        title: 'Debug mode enabled — leaks stack traces and internals',
        severity: 'HIGH', file: 'source', line: null, layer: 'security_mvp',
        remediation: 'Set DEBUG=False in production. Use environment-specific config.',
      });
      penalty += 20;
    }
  }
  // Console.log in non-CI code
  const consoleMatch = /console\.(log|dir|debug)\(/g.exec(code);
  if (consoleMatch) {
    const before = code.slice(0, consoleMatch.index);
    const lastMarker = before.lastIndexOf('# === ');
    if (lastMarker !== -1) {
      const section = before.slice(lastMarker, lastMarker + 100);
      if (!/workflows|\.github|ci/i.test(section)) {
        findings.push({
          title: 'Console debug output in production code',
          severity: 'MEDIUM', file: 'source', line: null, layer: 'security_mvp',
          remediation: 'Use a proper logger with log levels. Remove console.log from production paths.',
        });
        penalty += 10;
      }
    }
  }
  return penalty;
}

function checkInputValidation(code, findings, lang) {
  let penalty = 0;
  const hasValidation = /validate|sanitize|escape|bleach|re\.(match|search)|isinstance|assert\sis|argparse|add_argument|pydantic|marshmallow|cerberus|schema|zod|joi/i.test(code);
  const hasUserInput = /request\.(GET|POST|args|form|json|data)|input\(|prompt\(|readline|sys\.argv|os\.environ|\.get\(/i.test(code);
  if (hasUserInput && !hasValidation) {
    findings.push({
      title: 'User input accepted without visible validation/sanitization',
      severity: 'HIGH', file: 'source', line: null, layer: 'security_mvp',
      remediation: 'Validate all user input: type check, length limits, allowlists. Use libraries like pydantic (Python) or zod (JS).',
    });
    penalty += 20;
  }
  if (lang === 'python' && hasUserInput && !/pydantic|marshmallow|cerberus|schema/i.test(code)) {
    findings.push({
      title: 'No schema validation library detected (pydantic/marshmallow recommended)',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'security_mvp',
      remediation: 'Add pydantic models for input validation. This prevents injection and type confusion attacks.',
    });
    penalty += 10;
  }
  return penalty;
}

function checkDependencyRisks(code, findings) {
  let penalty = 0;
  // Check for unpinned dependencies
  const unpinnedPatterns = [
    /^\s*[a-z][\w-]+(?:\[.*?\])?\s*$/gm, // bare package name
    /^\s*[a-z][\w-]+\s*>=\s*[\d.]+/gm,   // >= without upper bound
  ];
  const reqMatch = code.match(/(?:requirements.*\.(?:txt|in)|pyproject\.toml|setup\.(?:py|cfg)|Pipfile|poetry\.lock)/i);
  if (reqMatch) {
    const depSection = extractDependencySection(code);
    const unpinned = [];
    for (const p of unpinnedPatterns) {
      for (const m of depSection.matchAll(p)) {
        const name = m[0].trim().split(/[\[>=<\s]/)[0];
        if (name && !unpinned.includes(name)) unpinned.push(name);
      }
    }
    if (unpinned.length > 3) {
      findings.push({
        title: `${unpinned.length} dependencies are unpinned (no version constraint)`,
        severity: 'HIGH', file: 'requirements / pyproject.toml', line: null, layer: 'security_mvp',
        remediation: `Pin all dependencies with exact versions or known-good ranges. Unpinned: ${unpinned.slice(0, 5).join(', ')}${unpinned.length > 5 ? '...' : ''}.`,
      });
      penalty += 20;
    }
  }
  // Check for known-vulnerable patterns (word-boundary safe)
  if (/\burllib2\b/i.test(code) || /\bpickle\.(loads?|dump)\s*\(/i.test(code) || /\byaml\.load\s*\(/i.test(code) || /\beval\s*\(/i.test(code) || /\bexec\s*\(/i.test(code)) {
    findings.push({
      title: 'Use of potentially unsafe deserialization (pickle/yaml.load/eval/exec)',
      severity: 'CRITICAL', file: 'source', line: null, layer: 'security_mvp',
      remediation: 'Use safe parsers: yaml.safe_load(), json.loads(). Avoid pickle for untrusted data. Never use eval/exec on user input.',
    });
    penalty += 30;
  }
  return penalty;
}

function checkAuthPatterns(code, findings, lang) {
  let penalty = 0;
  const hasAuth = /auth|oauth|jwt|session|login|token.*valid|@login_required|@jwt_required|authenticate|permission/i.test(code);
  const hasAPI = /@app\.(route|get|post)|@router\.|fetch\(|axios\.|requests\.(get|post)/i.test(code);
  if (hasAPI && !hasAuth && code.length > 500) {
    findings.push({
      title: 'API endpoints detected without visible authentication middleware',
      severity: 'HIGH', file: 'source', line: null, layer: 'security_mvp',
      remediation: 'Add authentication middleware (JWT, OAuth2, API keys). All non-public endpoints must require auth.',
    });
    penalty += 20;
  }
  if (lang === 'python' && hasAPI && !/@login_required|@permission|flask-login|django.contrib.auth|fastapi.*security|Depends\(.*auth/i.test(code)) {
    findings.push({
      title: 'Python web routes lack auth decorators/middleware',
      severity: 'HIGH', file: 'source', line: null, layer: 'security_mvp',
      remediation: 'Add auth decorators: @login_required (Flask), Depends(get_current_user) (FastAPI), @login_required (Django).',
    });
    penalty += 15;
  }
  return penalty;
}

function checkFilePermissions(code, findings) {
  let penalty = 0;
  if (/chmod\s*\(\s*['"]?0?777/i.test(code) || /chmod\s*.*\+\w+/i.test(code)) {
    findings.push({
      title: 'Overly permissive file permissions (0777 or +w)',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'security_mvp',
      remediation: 'Use restrictive permissions: 0600 for sensitive files, 0644 for configs. Never use 0777.',
    });
    penalty += 10;
  }
  return penalty;
}

function checkCORSConfig(code, findings) {
  let penalty = 0;
  if (/Access-Control-Allow-Origin\s*:\s*\*/i.test(code) && !/Authorization|credentials/i.test(code)) {
    findings.push({
      title: 'CORS set to wildcard (*) — allows any origin',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'security_mvp',
      remediation: 'Restrict CORS to specific origins. Wildcard (*) allows any website to make authenticated requests.',
    });
    penalty += 10;
  }
  return penalty;
}

function checkSQLInjection(code, findings, lang) {
  let penalty = 0;
  const hasRawSQL = /execute\s*\(\s*(['"`]|f['"`])/i.test(code) || /\.raw\(/i.test(code) || /cursor\.execute\(/i.test(code);
  const hasParam = /\?|%s|:[\w]+|%\([\w]+\)s/;
  if (hasRawSQL) {
    // Check if parameterized
    const lines = code.split('\n');
    let paramCount = 0, rawCount = 0;
    for (const line of lines) {
      if (/execute\(|\.raw\(/.test(line)) {
        if (hasParam.test(line) || /,\s*\[|,\s*\(/.test(line)) paramCount++;
        else rawCount++;
      }
    }
    if (rawCount > paramCount) {
      findings.push({
        title: `Potential SQL injection: ${rawCount} unparameterized queries detected`,
        severity: 'CRITICAL', file: 'source', line: null, layer: 'security_mvp',
        remediation: 'Always use parameterized queries. Python: cursor.execute("SELECT ...", [params]). JS: db.query("SELECT ...", [params]).',
      });
      penalty += 30;
    }
  }
  return penalty;
}

// ══════════════════════════════════════════════════════════════════════════════
// DEPLOYMENT CHECKS
// ══════════════════════════════════════════════════════════════════════════════

function checkDockerQuality(code, findings) {
  let penalty = 0;
  // Only check for actual Dockerfile content (FROM instruction), not just references
  const dockerContent = extractSection(code, /# === .*Dockerfile.*===\n/, 2000);
  const hasDockerfile = dockerContent && /^FROM\s+\S+/im.test(dockerContent);
  if (!hasDockerfile) {
    const isLibrary = /setup\.py|pyproject\.toml|package\.json|Cargo\.toml|go\.mod/i.test(code);
    if (isLibrary) return 0;
    findings.push({
      title: 'No container definition found (Dockerfile)',
      severity: 'MEDIUM', file: '/', line: null, layer: 'deployment',
      remediation: 'Add a Dockerfile for reproducible builds.',
    });
    penalty += 15;
    return penalty;
  }
  if (/:\s*latest\b/i.test(dockerContent)) {
    findings.push({
      title: 'Container base image uses :latest tag — non-deterministic builds',
      severity: 'HIGH', file: 'Dockerfile', line: null, layer: 'deployment',
      remediation: 'Pin base images to digest (sha256:...) or specific version tag for reproducible builds.',
    });
    penalty += 15;
  }
  if (!/USER\s+\S+/i.test(dockerContent) && !/root/i.test(dockerContent)) {
    findings.push({
      title: 'Dockerfile does not specify a non-root USER',
      severity: 'MEDIUM', file: 'Dockerfile', line: null, layer: 'deployment',
      remediation: 'Add "USER 1000" or similar to run the container as non-root for security.',
    });
    penalty += 10;
  }
  if (!/HEALTHCHECK/i.test(dockerContent)) {
    findings.push({
      title: 'No HEALTHCHECK in Dockerfile',
      severity: 'LOW', file: 'Dockerfile', line: null, layer: 'deployment',
      remediation: 'Add HEALTHCHECK instruction for container orchestration health monitoring.',
    });
    penalty += 5;
  }
  return penalty;
}

function checkHealthEndpoints(code, findings) {
  let penalty = 0;
  const hasHealth = /\/healthz?\b|\/readyz?\b|\/livez?\b|\/ping\b|health_check|@app\.(get|route).*health/i.test(code);
  const isWebApp = /@app\.(route|get|post)|express\(\)|fastapi|flask|nicegui|django|router\.(get|post)|createServer/i.test(code);
  if (isWebApp && !hasHealth) {
    findings.push({
      title: 'Web application has no health check endpoint',
      severity: 'HIGH', file: 'source', line: null, layer: 'deployment',
      remediation: 'Add /healthz endpoint returning 200 with service status. Required for Kubernetes, load balancers, and monitoring.',
    });
    penalty += 20;
  }
  return penalty;
}

function checkCICDPipeline(code, findings) {
  let penalty = 0;
  const ciContent = extractSection(code, /# === \.github\/workflows|\.github\/workflows\/|gitlab-ci\.yml|Jenkinsfile|circleci/i, 5000);
  if (!ciContent) {
    findings.push({
      title: 'No CI/CD pipeline configuration found',
      severity: 'HIGH', file: '/', line: null, layer: 'deployment',
      remediation: 'Add GitHub Actions or GitLab CI pipeline with test, lint, security scan, and deploy stages.',
    });
    penalty += 25;
    return penalty;
  }
  if (!/test|pytest|jest|go test|npm test|mvn test|make test/i.test(ciContent)) {
    findings.push({
      title: 'CI pipeline does not include a test step',
      severity: 'HIGH', file: '.github/workflows/', line: null, layer: 'deployment',
      remediation: 'Add a test job to CI. Tests should run on every PR and push to main.',
    });
    penalty += 20;
  }
  if (!/lint|eslint|ruff|flake8|golangci-lint|checkstyle/i.test(ciContent)) {
    findings.push({
      title: 'CI pipeline does not include a linting step',
      severity: 'MEDIUM', file: '.github/workflows/', line: null, layer: 'deployment',
      remediation: 'Add automated linting to CI to catch style issues and potential bugs early.',
    });
    penalty += 10;
  }
  if (!/security|snyk|trivy|semgrep|codeql|gitleaks/i.test(ciContent)) {
    findings.push({
      title: 'CI pipeline has no security scanning step',
      severity: 'MEDIUM', file: '.github/workflows/', line: null, layer: 'deployment',
      remediation: 'Add security scanning (CodeQL, Trivy, Snyk, or Semgrep) to CI pipeline.',
    });
    penalty += 10;
  }
  return penalty;
}

function checkObservability(code, findings) {
  let penalty = 0;
  const hasLogging = /logging|logger|loguru|winston|pino|log\.(info|error|warn|debug)|console\.(log|error)/i.test(code);
  const hasMetrics = /prometheus|metrics|statsd|datadog|opentelemetry|cloudwatch/i.test(code);
  const hasTracing = /tracing|jaeger|zipkin|opentelemetry.*trace|sentry/i.test(code);
  if (!hasLogging && code.length > 200) {
    findings.push({
      title: 'No structured logging detected',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'deployment',
      remediation: 'Add structured logging (JSON format). Python: structlog or logging. Node: pino or winston.',
    });
    penalty += 15;
  }
  if (!hasMetrics && code.length > 500) {
    findings.push({
      title: 'No metrics/monitoring instrumentation',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'deployment',
      remediation: 'Add Prometheus metrics or OpenTelemetry for RED metrics (Rate, Errors, Duration).',
    });
    penalty += 10;
  }
  return penalty;
}

function checkConfigManagement(code, findings) {
  let penalty = 0;
  const hasEnvConfig = /os\.(environ|getenv)|process\.env|env\.|config\(\)|\.env|getenv/i.test(code);
  const hasConfigFile = /\.ini|\.yaml|\.toml|\.json.*config|configparser|yaml\.(safe_)?load|toml\.load/i.test(code);
  const hasHardcodedConfig = /host\s*=\s*['"]\d{1,3}\.\d{1,3}|port\s*=\s*\d{2,5}|url\s*=\s*['"]https?:/i.test(code);
  if (hasHardcodedConfig && !hasEnvConfig) {
    findings.push({
      title: 'Configuration values appear hardcoded (URLs, hosts, ports)',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'deployment',
      remediation: 'Externalize configuration: use environment variables, config files, or a config service (Consul, etcd).',
    });
    penalty += 15;
  }
  if (!hasEnvConfig && !hasConfigFile && code.length > 300) {
    findings.push({
      title: 'No configuration management pattern detected',
      severity: 'LOW', file: 'source', line: null, layer: 'deployment',
      remediation: 'Use environment variables (12-factor app) or config files for all environment-specific settings.',
    });
    penalty += 5;
  }
  return penalty;
}

function checkBuildReproducibility(code, findings) {
  let penalty = 0;
  const hasLockfile = /poetry\.lock|package-lock\.json|yarn\.lock|pnpm-lock|Pipfile\.lock|requirements.*lock.*\.txt|requirements-lock|cargo\.lock|go\.sum/i.test(code);
  if (!hasLockfile && code.length > 500) {
    findings.push({
      title: 'No dependency lockfile detected — builds are not reproducible',
      severity: 'MEDIUM', file: '/', line: null, layer: 'deployment',
      remediation: 'Commit lockfiles (poetry.lock, package-lock.json). They ensure identical dependency trees across environments.',
    });
    penalty += 15;
  }
  return penalty;
}

// ══════════════════════════════════════════════════════════════════════════════
// RELIABILITY CHECKS
// ══════════════════════════════════════════════════════════════════════════════

function checkErrorHandling(code, findings, lang) {
  let penalty = 0;
  const hasTryCatch = /try\s*\{|try\s*:|catch\s*\(|catch\s+\w+:|except\s|\.catch\s*\(/i.test(code);
  const hasThrows = /raise\s+\w+|throw\s+new\s+\w+/i.test(code);
  const hasExternalCall = /fetch\(|requests\.(get|post|put|delete)|http\.(get|request)|urllib|axios|curl|subprocess/i.test(code);
  if (hasExternalCall && !hasTryCatch) {
    findings.push({
      title: 'External calls (HTTP, subprocess) without visible error handling',
      severity: 'HIGH', file: 'source', line: null, layer: 'reliability',
      remediation: 'Wrap all external calls in try/catch. Handle timeouts, connection errors, and non-200 responses.',
    });
    penalty += 20;
  }
  if (hasThrows && !hasTryCatch && code.length > 300) {
    findings.push({
      title: 'Code raises exceptions but lacks try/except blocks for recovery',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'reliability',
      remediation: 'Add error boundaries. Catch exceptions at service boundaries and convert to meaningful responses.',
    });
    penalty += 10;
  }
  if (/except\s*:/i.test(code) || /catch\s*\(/i.test(code) && !/catch\s*\(\s*\w+\s*\)/i.test(code)) {
    findings.push({
      title: 'Bare except / catch-all without specific exception types',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'reliability',
      remediation: 'Catch specific exceptions. Bare except hides bugs and makes debugging impossible.',
    });
    penalty += 10;
  }
  return penalty;
}

function checkLogging(code, findings, lang) {
  let penalty = 0;
  const hasProperLogging = /logging\.(getLogger|basicConfig)|logger\s*=|loguru|winston\.create|pino\(/i.test(code);
  const hasPrint = /print\(|console\.log\(|echo\s/i.test(code);
  if (code.length > 500 && !hasProperLogging && hasPrint) {
    findings.push({
      title: 'Using print/console.log instead of structured logging',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'reliability',
      remediation: 'Replace print() with proper logging. Use log levels (INFO, WARN, ERROR). Emit JSON for log aggregation.',
    });
    penalty += 10;
  }
  return penalty;
}

function checkTestCoverage(code, findings) {
  let penalty = 0;
  // Look for actual test file markers
  const testSection = extractSection(code, /(?:# === .*test.*\.py ===|import pytest|import unittest|from pytest|def test_|class Test)/i, 8000);
  if (!testSection) {
    findings.push({
      title: 'No test files or test code detected',
      severity: 'HIGH', file: '/', line: null, layer: 'reliability',
      remediation: 'Add unit tests (pytest, jest). Aim for >70% coverage on critical paths. Tests prevent regressions.',
    });
    penalty += 25;
    return penalty;
  }
  const testLines = testSection.split('\n').filter(l => l.trim() && !l.trim().startsWith('#') && !l.trim().startsWith('//'));
  const assertCount = (testSection.match(/\bassert\b|expect\(|\.should\.|\.to\.|assertEquals|assertEqual|self\.assert|assertTrue|assertFalse/g) || []).length;
  if (assertCount < 3) {
    findings.push({
      title: `Tests exist but only ${assertCount} assertions found — insufficient coverage`,
      severity: 'MEDIUM', file: 'tests/', line: null, layer: 'reliability',
      remediation: 'Add more test assertions covering edge cases, error paths, and boundary conditions.',
    });
    penalty += 15;
  }
  // Check test-to-source ratio
  const totalLines = code.split('\n').length;
  const testRatio = testLines.length / Math.max(totalLines, 1);
  if (testRatio < 0.2) {
    findings.push({
      title: `Low test ratio: ${Math.round(testRatio * 100)}% of codebase (target >20%)`,
      severity: 'HIGH', file: '/', line: null, layer: 'reliability',
      remediation: 'Increase test coverage. Add tests for all public functions, API endpoints, and error handling paths.',
    });
    penalty += 15;
  }
  return penalty;
}

function checkTypeSafety(code, findings, lang) {
  let penalty = 0;
  if (lang === 'python') {
    const hasTypeHints = /def\s+\w+\s*\([^)]*:\s*\w+/g.test(code) || /->\s*\w+/g.test(code);
    if (!hasTypeHints && code.length > 300) {
      findings.push({
        title: 'Python code lacks type hints — increases bug risk',
        severity: 'LOW', file: 'source', line: null, layer: 'reliability',
        remediation: 'Add type hints to function signatures. Use mypy or pyright for static type checking.',
      });
      penalty += 5;
    }
  }
  if (lang === 'javascript' || lang === 'typescript') {
    if (!/typescript|\.ts['":]/.test(code) && code.length > 300) {
      findings.push({
        title: 'JavaScript without TypeScript — lacks type safety',
        severity: 'MEDIUM', file: 'source', line: null, layer: 'reliability',
        remediation: 'Migrate to TypeScript for type safety. At minimum, add JSDoc type annotations.',
      });
      penalty += 10;
    }
  }
  return penalty;
}

function checkDocumentation(code, findings) {
  let penalty = 0;
  const hasDocstring = /"""[^"]{10,}"""|'''[^']{10,}'''|\/\*\*[\s\S]{10,}\*\//.test(code);
  const hasReadme = /readme/i.test(code);
  const functionCount = (code.match(/\bdef\s+\w+|function\s+\w+/g) || []).length;
  if (functionCount > 5 && !hasDocstring) {
    findings.push({
      title: `${functionCount} functions found with no docstrings/JSDoc`,
      severity: 'LOW', file: 'source', line: null, layer: 'reliability',
      remediation: 'Add docstrings (Python) or JSDoc (JS) to all public functions describing parameters, returns, and behavior.',
    });
    penalty += 5;
  }
  return penalty;
}

function checkConcurrencySafety(code, findings, lang) {
  let penalty = 0;
  const hasThreading = /threading|asyncio|concurrent|goroutine|Promise\.all|async\s+function|\.then\(/i.test(code);
  const hasLock = /Lock\(|mutex|semaphore|RLock|with\s+lock|synchronized/i.test(code);
  const isGuiThread = /Thread\(target=|daemon|nicegui|tkinter|PyQt|wx\./i.test(code);
  // GUI background threads are usually safe without explicit locks
  if (hasThreading && !hasLock && !isGuiThread && code.length > 500) {
    findings.push({
      title: 'Concurrent code without visible synchronization (locks/semaphores)',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'reliability',
      remediation: 'Add thread synchronization: threading.Lock() (Python), Mutex (Go), or use async/await patterns properly.',
    });
    penalty += 10;
  }
  return penalty;
}

function checkGracefulShutdown(code, findings, lang) {
  let penalty = 0;
  const isServer = /app\.run\(|server\.listen|uvicorn\.run|gunicorn|http\.createServer|express\(\)\.listen/i.test(code);
  const hasShutdown = /signal\.signal|SIGTERM|SIGINT|atexit|graceful|shutdown|process\.on\(.*SIG/i.test(code);
  if (isServer && !hasShutdown) {
    findings.push({
      title: 'Server process lacks graceful shutdown handling',
      severity: 'MEDIUM', file: 'source', line: null, layer: 'reliability',
      remediation: 'Handle SIGTERM/SIGINT: stop accepting new requests, finish in-flight work, close DB connections, then exit.',
    });
    penalty += 10;
  }
  return penalty;
}

// ══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════════════════════

function extractMetadata(code) {
  const lines = code.split('\n');
  const extCounts = {};
  let lang = 'unknown';
  for (const line of lines) {
    if (line.startsWith('# === ') && line.endsWith(' ===')) {
      const name = line.slice(5, -4);
      const ext = name.split('.').pop()?.toLowerCase();
      if (ext) extCounts[ext] = (extCounts[ext] || 0) + 1;
    }
  }
  if (extCounts['py'] > (extCounts['js'] || 0)) lang = 'python';
  else if (extCounts['js'] || extCounts['ts']) lang = extCounts['ts'] ? 'typescript' : 'javascript';
  return { dominantLanguage: lang, totalLines: lines.length, extensionCounts: extCounts, fileCount: Object.values(extCounts).reduce((a,b)=>a+b,0) || 1 };
}

function extractSection(code, marker, maxLen) {
  const idx = code.search(marker);
  if (idx === -1) return null;
  return code.slice(idx, idx + (maxLen || 3000));
}

function extractDependencySection(code) {
  const markers = ['requirements', 'pyproject.toml', 'setup.py', 'setup.cfg', 'Pipfile', 'package.json'];
  for (const m of markers) {
    const idx = code.indexOf(m);
    if (idx !== -1) return code.slice(idx, idx + 3000);
  }
  return code;
}

function makeLayer(name, score, findings) {
  const f = findings.filter(x => x.layer === name);
  return {
    layer: name, score, findings: f, finding_count: f.length,
    severity_counts: countSeverities(f),
    checks: {},
    remediations: f.filter(x => x.severity === 'CRITICAL' || x.severity === 'HIGH')
      .map(x => `[${x.severity}] ${x.title}: ${x.remediation}`).slice(0, 5),
  };
}

function countSeverities(fs) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  fs.forEach(f => { c[f.severity || 'INFO']++; });
  return c;
}

function buildPrediction(gate, sec, dep, rel, findings) {
  if (gate === 'PASS') {
    const lowFindings = findings.filter(f => f.severity === 'LOW' || f.severity === 'MEDIUM');
    if (lowFindings.length > 0) {
      return `PASS with warnings. Address ${lowFindings.length} medium/low findings to reach production excellence. Top: ${lowFindings[0].title.slice(0, 60)}.`;
    }
    return 'Production-ready across all dimensions. Enable continuous scanning and SLO monitoring.';
  }
  const critical = findings.filter(f => f.severity === 'CRITICAL');
  const high = findings.filter(f => f.severity === 'HIGH');
  if (critical.length > 0) {
    return `BLOCKED: ${critical.length} CRITICAL finding(s) must be resolved first. ${critical[0].title.slice(0, 80)}.`;
  }
  return `FAIL: Address ${high.length} HIGH severity findings. ${high[0]?.title?.slice(0, 80) || 'Review findings'}.`;
}