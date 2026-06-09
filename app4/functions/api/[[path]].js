/**
 * ViabilityScan Pages Function — IBM Watsonx + Cloudflare Edge
 * 
 * Handles all /api/* routes.
 * POST /api/scan  — Analyze code with IBM Granite model
 * POST /api/fetch — Fetch repository metadata
 */

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (url.pathname === '/api/scan' && request.method === 'POST') {
    return handleScan(request, env);
  }
  if (url.pathname === '/api/fetch' && request.method === 'POST') {
    return handleFetch(request, env);
  }

  return new Response('Not found', { status: 404 });
}

/**
 * POST /api/scan
 * Body: { code, url, mode }
 * Calls IBM Watsonx.ai Granite model to analyze code.
 */
async function handleScan(request, env) {
  try {
    const { code, url, mode } = await request.json();
    const input = code || url;

    if (!input) {
      return json({ error: 'No code or URL provided' }, 400);
    }

    const ibmKey = env.IBM_CLOUD_API_KEY;
    const wxProjectId = env.WATSONX_PROJECT_ID;

    let result;
    if (ibmKey && wxProjectId) {
      // Use IBM Watsonx.ai Granite model
      result = await scanWithWatsonx(input, mode, ibmKey, wxProjectId);
    } else {
      // Fallback: heuristic scan (no IBM key configured)
      result = scanHeuristic(input, mode);
    }

    return json(result);
  } catch (e) {
    console.error('Scan error:', e);
    return json({ error: e.message || 'Scan failed' }, 500);
  }
}

/**
 * POST /api/fetch
 * Body: { url }
 * Fetches basic repo metadata.
 */
async function handleFetch(request, env) {
  try {
    const { url } = await request.json();
    if (!url) return json({ error: 'No URL' }, 400);

    let content = '';
    let files = 0;
    let lines = 0;

    // Try fetching the URL
    try {
      const resp = await fetch(url, {
        headers: { 'User-Agent': 'ViabilityScan/1.0', 'Accept': 'text/plain,text/html,*/*' },
        redirect: 'follow',
        signal: AbortSignal.timeout(10000),
      });
      if (resp.ok) {
        const text = await resp.text();
        content = text.slice(0, 50000);
        lines = content.split('\n').length;
        files = 1;
      }
    } catch (e) {
      // Can't fetch — return URL as content
      content = `# Repository: ${url}\n# Unable to fetch content directly.\n# Paste your code below for analysis.`;
    }

    return json({ content, files, lines, summary: `Fetched ${files} file(s), ~${lines} lines` });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ── IBM Watsonx.ai Integration ──────────────────────────────────────────────

async function scanWithWatsonx(code, mode, apiKey, projectId) {
  // Get IAM token
  const token = await getIBMToken(apiKey);
  
  // Build prompt for Granite model
  const prompt = buildScanPrompt(code, mode);

  // Call Watsonx.ai text generation
  const wxUrl = 'https://us-south.ml.cloud.ibm.com/ml/v1/text/generation?version=2023-05-29';
  
  const resp = await fetch(wxUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      model_id: 'ibm/granite-13b-chat-v2',
      project_id: projectId,
      input: prompt,
      parameters: {
        max_new_tokens: 2000,
        temperature: 0.2,
        stop_sequences: ['```'],
      },
    }),
  });

  if (!resp.ok) {
    const err = await resp.text();
    console.error('Watsonx error:', resp.status, err);
    throw new Error(`IBM Watsonx returned ${resp.status}`);
  }

  const data = await resp.json();
  const text = data.results?.[0]?.generated_text || '';

  // Parse the AI response into structured report
  return parseAIResponse(text, code, mode);
}

async function getIBMToken(apiKey) {
  const resp = await fetch('https://iam.cloud.ibm.com/identity/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
    },
    body: `grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=${encodeURIComponent(apiKey)}`,
  });

  if (!resp.ok) {
    throw new Error(`IBM IAM auth failed: ${resp.status}`);
  }

  const data = await resp.json();
  return data.access_token;
}

function buildScanPrompt(code, mode) {
  const depth = mode === 'full' ? 'deep' : 'standard';
  return `You are ViabilityScan, a repository deployment readiness engine. Analyze the following code for production viability.

Perform a ${depth} analysis covering:

1. SECURITY (weight 40%): Look for hardcoded secrets, missing input validation, unsafe dependencies, debug mode enabled, missing authentication, CORS misconfigurations.

2. DEPLOYMENT (weight 30%): Check for Dockerfile quality (pinned images, no :latest), CI/CD configuration, health check endpoints, monitoring/observability, rollback procedures.

3. RELIABILITY (weight 30%): Assess test coverage indicators, error handling patterns, logging practices, configuration management, dependency pinning.

Return a JSON object with this exact structure:
{
  "scores": {
    "security": <0-100>,
    "deployment": <0-100>,
    "reliability": <0-100>,
    "viability": <0-100>
  },
  "gate": "PASS" or "FAIL",
  "gate_reasons": ["reason1", "reason2"],
  "findings": [
    {
      "title": "brief description",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "file": "filename or path",
      "line": null or number,
      "layer": "security_mvp|deployment|reliability",
      "remediation": "how to fix"
    }
  ],
  "next_frame_prediction": "summary of next steps"
}

Gate rules: PASS if viability >= 75 AND security >= 70 AND deployment >= 60 AND reliability >= 60.

Here is the code to analyze:
\`\`\`
${code.slice(0, 8000)}
\`\`\`

Return ONLY the JSON, no other text.`;
}

function parseAIResponse(text, code, mode) {
  // Try to extract JSON from the AI response
  try {
    // Find JSON block
    const match = text.match(/\{[\s\S]*\}/);
    if (match) {
      const parsed = JSON.parse(match[0]);
      return normalizeReport(parsed, code, mode);
    }
  } catch (e) {
    console.error('Failed to parse AI response:', e);
  }
  
  // Fallback to heuristic if AI response can't be parsed
  return scanHeuristic(code, mode);
}

// ── Heuristic Fallback Scanner ──────────────────────────────────────────────

function scanHeuristic(code, mode) {
  const findings = [];
  const checks = {};

  // Security checks
  let secScore = 100;
  if (hasSecretPattern(code)) {
    findings.push({
      title: 'Potential hardcoded secret or API key detected',
      severity: 'CRITICAL', file: 'pasted code', line: null,
      layer: 'security_mvp',
      remediation: 'Move secrets to environment variables or a secrets manager (Vault, IBM Secrets Manager).',
    });
    secScore -= 30;
  }
  if (/\bDEBUG\s*=\s*True\b/i.test(code) || /\bdebug\s*:\s*true\b/i.test(code)) {
    findings.push({
      title: 'Debug mode enabled in source',
      severity: 'HIGH', file: 'pasted code', line: null,
      layer: 'security_mvp',
      remediation: 'Set DEBUG=False in production. Use environment variables.',
    });
    secScore -= 20;
  }
  if (/(password|passwd|pwd)\s*=\s*['"][^'"]+['"]/i.test(code)) {
    findings.push({
      title: 'Hardcoded password detected',
      severity: 'CRITICAL', file: 'pasted code', line: null,
      layer: 'security_mvp',
      remediation: 'Never hardcode passwords. Use a secrets manager.',
    });
    secScore -= 30;
  }
  checks.has_secret_scan = true;

  // Deployment checks
  let depScore = 100;
  const hasDocker = /FROM\s+\S+/i.test(code);
  const hasLatest = /:\s*latest\b/i.test(code);
  checks.has_dockerfile = hasDocker;

  if (!hasDocker && mode === 'full') {
    findings.push({
      title: 'No Dockerfile or container definition found',
      severity: 'MEDIUM', file: 'pasted code', line: null,
      layer: 'deployment',
      remediation: 'Add a Dockerfile for reproducible container builds.',
    });
    depScore -= 15;
  }
  if (hasLatest) {
    findings.push({
      title: 'Container image uses :latest tag (non-deterministic)',
      severity: 'MEDIUM', file: 'pasted code', line: null,
      layer: 'deployment',
      remediation: 'Pin base image to a specific digest or version tag.',
    });
    depScore -= 10;
  }
  if (!/\/health|healthz|readyz|livez/i.test(code)) {
    findings.push({
      title: 'No health check endpoint detected',
      severity: 'HIGH', file: 'pasted code', line: null,
      layer: 'deployment',
      remediation: 'Implement /healthz or /readyz for Kubernetes health probes.',
    });
    depScore -= 15;
  }

  // Reliability checks
  let relScore = 100;
  if (!/try\b|catch\b|except\b|\.catch\(/i.test(code) && code.length > 100) {
    findings.push({
      title: 'Limited error handling detected',
      severity: 'MEDIUM', file: 'pasted code', line: null,
      layer: 'reliability',
      remediation: 'Add try/catch blocks for external calls and edge cases.',
    });
    relScore -= 15;
  }
  if (!/log|logger|console\.(log|error|warn)/i.test(code) && code.length > 100) {
    findings.push({
      title: 'No logging detected',
      severity: 'LOW', file: 'pasted code', line: null,
      layer: 'reliability',
      remediation: 'Add structured logging for production debugging.',
    });
    relScore -= 5;
  }

  secScore = Math.max(0, secScore);
  depScore = Math.max(0, depScore);
  relScore = Math.max(0, relScore);

  const viability = Math.round(0.4 * secScore + 0.3 * depScore + 0.3 * relScore);
  const gate = (viability >= 75 && secScore >= 70 && depScore >= 60 && relScore >= 60) ? 'PASS' : 'FAIL';
  const gateReasons = [];
  if (viability < 75) gateReasons.push(`Viability ${viability} < 75`);
  if (secScore < 70) gateReasons.push(`Security ${secScore} < 70`);
  if (depScore < 60) gateReasons.push(`Deployment ${depScore} < 60`);
  if (relScore < 60) gateReasons.push(`Reliability ${relScore} < 60`);

  return {
    tool: 'ViabilityScan',
    version: '1.0.0',
    scanned_at: new Date().toISOString(),
    mode: mode || 'mvp',
    scores: { security: secScore, deployment: depScore, reliability: relScore, viability },
    gate,
    gate_reasons: gateReasons,
    layers: {
      security_mvp: {
        layer: 'security_mvp',
        score: secScore,
        findings: findings.filter(f => f.layer === 'security_mvp'),
        finding_count: findings.filter(f => f.layer === 'security_mvp').length,
        severity_counts: countSeverities(findings.filter(f => f.layer === 'security_mvp')),
        checks: { has_secret_scan: true, has_auth_check: /auth|oauth|jwt|token/i.test(code) },
        remediations: findings.filter(f => f.layer === 'security_mvp' && (f.severity === 'CRITICAL' || f.severity === 'HIGH')).map(f => `[${f.severity}] ${f.title}: ${f.remediation}`).slice(0, 5),
      },
      deployment: {
        layer: 'deployment',
        score: depScore,
        findings: findings.filter(f => f.layer === 'deployment'),
        finding_count: findings.filter(f => f.layer === 'deployment').length,
        severity_counts: countSeverities(findings.filter(f => f.layer === 'deployment')),
        checks: { has_dockerfile: hasDocker, has_ci_github: /github.*workflow|actions\//i.test(code) },
        remediations: findings.filter(f => f.layer === 'deployment' && (f.severity === 'CRITICAL' || f.severity === 'HIGH')).map(f => `[${f.severity}] ${f.title}: ${f.remediation}`).slice(0, 5),
      },
      reliability: {
        layer: 'reliability',
        score: relScore,
        findings: findings.filter(f => f.layer === 'reliability'),
        finding_count: findings.filter(f => f.layer === 'reliability').length,
        severity_counts: countSeverities(findings.filter(f => f.layer === 'reliability')),
        checks: { has_tests: /test|spec|pytest|jest|mocha/i.test(code) },
        remediations: findings.filter(f => f.layer === 'reliability' && (f.severity === 'CRITICAL' || f.severity === 'HIGH')).map(f => `[${f.severity}] ${f.title}: ${f.remediation}`).slice(0, 5),
      },
      django_migrations: {
        layer: 'django_migrations',
        score: 100,
        findings: [],
        finding_count: 0,
        severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        checks: { is_django_project: /django|manage\.py|makemigrations/i.test(code) },
        remediations: [],
      },
    },
    next_frame_prediction: gate === 'PASS'
      ? 'Repository is production-ready. Enable continuous scanning in CI.'
      : 'Address findings above to reach PASS. Focus on CRITICAL and HIGH severity items first.',
  };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function hasSecretPattern(code) {
  const patterns = [
    /(api[_-]?key|apikey|secret|token|password|passwd)\s*[:=]\s*['"][A-Za-z0-9_\-]{8,}['"]/i,
    /sk-[A-Za-z0-9]{20,}/,
    /ghp_[A-Za-z0-9]{20,}/,
    /AKIA[0-9A-Z]{16}/,
    /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----/,
    /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, // JWT-like
    /gho_[A-Za-z0-9]{20,}/,
    /glpat-[A-Za-z0-9_-]{20,}/,
  ];
  return patterns.some(p => p.test(code));
}

function countSeverities(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    const sev = f.severity || 'INFO';
    counts[sev] = (counts[sev] || 0) + 1;
  }
  return counts;
}

function normalizeReport(parsed, code, mode) {
  return {
    tool: 'ViabilityScan',
    version: '1.0.0',
    scanned_at: new Date().toISOString(),
    mode: mode || 'mvp',
    driver: 'IBM Watsonx Granite',
    scores: parsed.scores || { security: 0, deployment: 0, reliability: 0, viability: 0 },
    gate: parsed.gate || 'FAIL',
    gate_reasons: parsed.gate_reasons || [],
    layers: {
      security_mvp: {
        layer: 'security_mvp',
        score: parsed.scores?.security || 0,
        findings: (parsed.findings || []).filter(f => f.layer === 'security_mvp'),
        finding_count: (parsed.findings || []).filter(f => f.layer === 'security_mvp').length,
        severity_counts: countSeverities((parsed.findings || []).filter(f => f.layer === 'security_mvp')),
        checks: {},
        remediations: [],
      },
      deployment: {
        layer: 'deployment',
        score: parsed.scores?.deployment || 0,
        findings: (parsed.findings || []).filter(f => f.layer === 'deployment'),
        finding_count: (parsed.findings || []).filter(f => f.layer === 'deployment').length,
        severity_counts: countSeverities((parsed.findings || []).filter(f => f.layer === 'deployment')),
        checks: {},
        remediations: [],
      },
      reliability: {
        layer: 'reliability',
        score: parsed.scores?.reliability || 0,
        findings: (parsed.findings || []).filter(f => f.layer === 'reliability'),
        finding_count: (parsed.findings || []).filter(f => f.layer === 'reliability').length,
        severity_counts: countSeverities((parsed.findings || []).filter(f => f.layer === 'reliability')),
        checks: {},
        remediations: [],
      },
      django_migrations: {
        layer: 'django_migrations',
        score: 100,
        findings: [],
        finding_count: 0,
        severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        checks: {},
        remediations: [],
      },
    },
    next_frame_prediction: parsed.next_frame_prediction || '',
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
  });
}