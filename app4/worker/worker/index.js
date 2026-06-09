/**
 * sdv1 Worker — IBM Watsonx + Cloudflare Edge
 * Dashboard + API + GitHub OAuth repo ingestion.
 */

import dashboardHTML from './dashboard.js';
import { deepScan } from './scanner.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Health check endpoints
    if (url.pathname === '/healthz' || url.pathname === '/readyz' || url.pathname === '/api/health') {
      return json({ status: 'ok', service: 'sdv1', version: '2.0.0', driver: env.DRIVER || 'IBM Watsonx Granite', timestamp: new Date().toISOString() });
    }

    // ── GitHub OAuth routes ──────────────────────────────────────────
    if (url.pathname === '/auth/login') {
      return handleAuthLogin(env);
    }
    if (url.pathname === '/auth/callback') {
      return handleAuthCallback(request, env);
    }

    // ── API routes ───────────────────────────────────────────────────
    if (url.pathname.startsWith('/api/')) {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders() });
      }
      if (url.pathname === '/api/scan' && request.method === 'POST') {
        return handleScan(request, env);
      }
      if (url.pathname === '/api/fetch' && request.method === 'POST') {
        return handleFetch(request, env);
      }
      if (url.pathname === '/api/repos') {
        return handleRepos(request, env);
      }
      if (url.pathname === '/api/repo-files' && request.method === 'POST') {
        return handleRepoFiles(request, env);
      }
      if (url.pathname === '/api/user') {
        return handleUser(request, env);
      }
      if (url.pathname === '/api/health') {
        return json({ status: 'ok', service: 'sdv1', version: '2.0.0', driver: env.DRIVER || 'IBM Watsonx Granite', timestamp: new Date().toISOString() });
      }
    }

    // Serve dashboard for everything else
    return new Response(dashboardHTML, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// GITHUB OAUTH
// ═══════════════════════════════════════════════════════════════════════════

// Cached secrets (lives for Worker instance lifetime)
let cachedSecrets = null;

async function getGithubClientSecret(env) {
  if (cachedSecrets?.github_client_secret) return cachedSecrets.github_client_secret;
  
  // Try env var first (fallback for direct wrangler secret)
  if (env.GITHUB_CLIENT_SECRET) return env.GITHUB_CLIENT_SECRET;
  
  // Fetch from IBM Secrets Manager
  const smId = env.IBM_SM_INSTANCE_ID || '77a74a8e-30d4-440a-b4da-7eb56ff43425';
  const ibmKey = env.IBM_CLOUD_API_KEY;
  
  if (!ibmKey) return null;
  
  try {
    const token = await getIBMToken(ibmKey);
    const resp = await fetch(
      `https://us-south.secrets-manager.appdomain.cloud/api/v2/secrets?search=GITHUB_CLIENT_SECRET&groups=github-bootstrap`,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/json',
        },
      }
    );
    
    if (resp.ok) {
      const data = await resp.json();
      const secret = data.resources?.[0];
      if (secret?.payload) {
        const value = atob(secret.payload);
        cachedSecrets = { ...cachedSecrets, github_client_secret: value };
        return value;
      }
    }
  } catch(e) {
    console.error('Failed to fetch GitHub secret from IBM SM:', e.message);
  }
  
  return null;
}

function handleAuthLogin(env) {
  const clientId = env.GITHUB_CLIENT_ID;
  const redirectUri = 'https://app4.nextaura.fit/auth/callback';
  const scope = 'read:user,public_repo';
  const state = crypto.randomUUID();
  
  const githubUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${scope}&state=${state}`;
  
  return Response.redirect(githubUrl, 302);
}

async function handleAuthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const base = `${url.protocol}//${url.host}`;

  if (!code) {
    return Response.redirect(`${base}/?error=no_code`, 302);
  }

  const clientSecret = await getGithubClientSecret(env);
  if (!clientSecret) {
    return Response.redirect(`${base}/?error=secret_config`, 302);
  }

  // Exchange code for access token
  const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: clientSecret,
      code,
      redirect_uri: 'https://app4.nextaura.fit/auth/callback',
    }),
  });

  const tokenData = await tokenResp.json();
  const accessToken = tokenData.access_token;

  if (!accessToken) {
    return Response.redirect(`${base}/?error=token_exchange_failed`, 302);
  }

  // Get user info
  const userResp = await fetch('https://api.github.com/user', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'sdv1/2.0',
    },
  });

  const userData = await userResp.json();

  // Create session token
  const sessionId = crypto.randomUUID();
  const sessionData = JSON.stringify({
    access_token: accessToken,
    login: userData.login,
    avatar: userData.avatar_url,
    name: userData.name,
    created: Date.now(),
  });

  // Store in KV with 24h expiry (if KV binding exists)
  if (env.SESSIONS) {
    await env.SESSIONS.put(sessionId, sessionData, { expirationTtl: 86400 });
  }

  // Set cookie and redirect to dashboard
  return new Response(null, {
    status: 302,
    headers: {
      'Location': base + '/',
      'Set-Cookie': `vs_session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`,
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// API: REPOS & FILES
// ═══════════════════════════════════════════════════════════════════════════

async function getSession(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/vs_session=([^;]+)/);
  if (!match) return null;

  const sessionId = match[1];
  
  // Try KV first
  if (env.SESSIONS) {
    const data = await env.SESSIONS.get(sessionId);
    if (data) return JSON.parse(data);
  }
  
  // Fallback: decode from cookie (for when KV isn't set up)
  // In production, always use KV
  return null;
}

async function handleUser(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ authenticated: false }, 401);
  return json({ authenticated: true, login: session.login, avatar: session.avatar, name: session.name });
}

async function handleRepos(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);

  const url = new URL(request.url);
  const page = url.searchParams.get('page') || '1';
  const sort = url.searchParams.get('sort') || 'updated';

  const resp = await fetch(`https://api.github.com/user/repos?sort=${sort}&per_page=30&page=${page}&type=owner`, {
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'sdv1/2.0',
    },
  });

  if (!resp.ok) {
    return json({ error: `GitHub API error: ${resp.status}` }, resp.status);
  }

  const repos = await resp.json();
  // Return simplified repo list
  const simplified = repos.map(r => ({
    id: r.id,
    name: r.name,
    full_name: r.full_name,
    description: r.description,
    private: r.private,
    language: r.language,
    stargazers_count: r.stargazers_count,
    updated_at: r.updated_at,
    default_branch: r.default_branch,
    clone_url: r.clone_url,
  }));

  return json(simplified);
}

async function handleRepoFiles(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);

  const { owner, repo, path } = await request.json();
  if (!owner || !repo) return json({ error: 'owner and repo required' }, 400);

  const apiPath = path 
    ? `https://api.github.com/repos/${owner}/${repo}/contents/${path}`
    : `https://api.github.com/repos/${owner}/${repo}/contents`;

  const resp = await fetch(apiPath, {
    headers: {
      'Authorization': `Bearer ${session.access_token}`,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'sdv1/2.0',
    },
  });

  if (!resp.ok) {
    return json({ error: `GitHub API error: ${resp.status}` }, resp.status);
  }

  const data = await resp.json();
  return json(data);
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/scan
// ═══════════════════════════════════════════════════════════════════════════

async function handleScan(request, env) {
  try {
    const { code, url, mode } = await request.json();
    const input = code || url;
    if (!input) return json({ error: 'No code or URL' }, 400);

    const ibmKey = env.IBM_CLOUD_API_KEY;
    const wxProjectId = env.WATSONX_PROJECT_ID;

    let result;
    if (ibmKey && wxProjectId && wxProjectId !== 'placeholder-setup-needed') {
      try {
        result = await scanWithWatsonx(input, mode, ibmKey, wxProjectId);
      } catch (wxErr) {
        result = deepScan(input, mode);
        result.driver = 'IBM Watsonx (unavailable, used heuristic)';
      }
    } else {
      result = deepScan(input, mode);
    }
    return json(result);
  } catch (e) {
    return json({ error: e.message || 'Scan failed' }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /api/fetch
// ═══════════════════════════════════════════════════════════════════════════

async function handleFetch(request, env) {
  try {
    const { url } = await request.json();
    if (!url) return json({ error: 'No URL' }, 400);

    let content = '', files = 0, lines = 0;
    try {
      const resp = await fetch(url, {
        headers: { 'User-Agent': 'sdv1/2.0', 'Accept': 'text/plain,text/html,*/*' },
        redirect: 'follow', signal: AbortSignal.timeout(10000),
      });
      if (resp.ok) {
        const text = await resp.text();
        content = text.slice(0, 50000);
        lines = content.split('\n').length;
        files = 1;
      }
    } catch (e) {
      content = `# Repository: ${url}\n# Unable to fetch. Paste code below.`;
    }
    return json({ content, files, lines, summary: `Fetched ${files} file(s), ~${lines} lines` });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// IBM WATSONX
// ═══════════════════════════════════════════════════════════════════════════

async function scanWithWatsonx(code, mode, apiKey, projectId) {
  const token = await getIBMToken(apiKey);
  const prompt = buildScanPrompt(code, mode);
  const resp = await fetch('https://us-south.ml.cloud.ibm.com/ml/v1/text/generation?version=2023-05-29', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' },
    body: JSON.stringify({ model_id: 'ibm/granite-13b-chat-v2', project_id: projectId, input: prompt, parameters: { max_new_tokens: 2000, temperature: 0.2, stop_sequences: ['```'] } }),
  });
  if (!resp.ok) throw new Error(`IBM Watsonx returned ${resp.status}`);
  return parseAIResponse((await resp.json()).results?.[0]?.generated_text || '', code, mode);
}

async function getIBMToken(apiKey) {
  const resp = await fetch('https://iam.cloud.ibm.com/identity/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body: `grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=${encodeURIComponent(apiKey)}`,
  });
  if (!resp.ok) throw new Error(`IBM IAM failed: ${resp.status}`);
  return (await resp.json()).access_token;
}

function buildScanPrompt(code, mode) {
  return `You are sdv1. Analyze this code for production viability. ${mode === 'full' ? 'Deep' : 'Standard'} analysis:
1. SECURITY (40%): secrets, input validation, unsafe deps, debug mode, auth
2. DEPLOYMENT (30%): Dockerfile, CI/CD, health checks, monitoring
3. RELIABILITY (30%): tests, error handling, logging, config, type safety
Return ONLY JSON: {"scores":{"security":0-100,"deployment":0-100,"reliability":0-100,"viability":0-100},"gate":"PASS"|"FAIL","gate_reasons":[],"findings":[{"title":"","severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO","file":"","line":null,"layer":"security_mvp|deployment|reliability","remediation":""}],"next_frame_prediction":"summary"}
Gate: PASS if viability>=75 AND security>=70 AND deployment>=60 AND reliability>=60.
Code:\n\`\`\`\n${code.slice(0, 8000)}\n\`\`\``;
}

function parseAIResponse(text, code, mode) {
  try { const m = text.match(/\{[\s\S]*\}/); if (m) return normalizeReport(JSON.parse(m[0]), code, mode); } catch (e) {}
  return deepScan(code, mode);
}

function normalizeReport(p, code, mode) {
  return {
    tool: 'sdv1', version: '2.0.0', scanned_at: new Date().toISOString(),
    mode: mode || 'mvp', driver: 'IBM Watsonx Granite',
    scores: p.scores || { security: 0, deployment: 0, reliability: 0, viability: 0 },
    gate: p.gate || 'FAIL', gate_reasons: p.gate_reasons || [],
    layers: {
      security_mvp: makeLayer('security_mvp', p.scores?.security || 0, p.findings || []),
      deployment: makeLayer('deployment', p.scores?.deployment || 0, p.findings || []),
      reliability: makeLayer('reliability', p.scores?.reliability || 0, p.findings || []),
      django_migrations: { layer: 'django_migrations', score: 100, findings: [], finding_count: 0, severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, checks: {}, remediations: [] },
    },
    next_frame_prediction: p.next_frame_prediction || '',
  };
}

function makeLayer(name, score, findings) {
  const f = findings.filter(x => x.layer === name);
  return { layer: name, score, findings: f, finding_count: f.length, severity_counts: countSeverities(f), checks: {}, remediations: f.filter(x => x.severity === 'CRITICAL' || x.severity === 'HIGH').map(x => `[${x.severity}] ${x.title}: ${x.remediation}`).slice(0, 5) };
}

function countSeverities(fs) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  fs.forEach(f => { c[f.severity || 'INFO']++; });
  return c;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', ...corsHeaders() },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}