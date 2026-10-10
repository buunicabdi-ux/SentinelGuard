const test = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/src/app');
const { loadConfig } = require('../src/src/config');

async function withServer(t, configOverrides = {}, options = {}) {
  const config = {
    ...loadConfig({ NODE_ENV: 'test' }),
    ...configOverrides
  };
  const server = createApp({ config, ...options }).listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  return `http://127.0.0.1:${server.address().port}`;
}

async function post(url, path, body, headers = {}) {
  return fetch(`${url}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body)
  });
}

test('health route preserves its response contract and security headers', async (t) => {
  const base = await withServer(t);
  const response = await fetch(`${base}/health`);
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.status, 'online');
  assert.equal(body.system, 'SentinelGuard Core AI Engine');
  assert.ok(body.timestamp);
  assert.ok(response.headers.get('x-request-id'));
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
});

test('serves the same-origin demo UI and static assets with security policy', async (t) => {
  const base = await withServer(t);
  const response = await fetch(`${base}/`);
  const html = await response.text();
  assert.equal(response.status, 200);
  assert.match(html, /SentinelGuard AI/);
  assert.match(html, /inspection-input/);
  assert.match(html, /id="ai-consent" type="checkbox"/);
  assert.doesNotMatch(html, /id="ai-consent" type="checkbox" checked/);
  assert.match(html, /redacted, bounded excerpt of this input to Featherless/);
  assert.match(response.headers.get('content-security-policy'), /default-src 'self'/);

  const script = await fetch(`${base}/app.js`);
  assert.equal(script.status, 200);
  assert.match(await script.text(), /localStorage/);
});

test('rejects unsupported inspection content types without exposing parser details', async (t) => {
  const base = await withServer(t);
  const response = await fetch(`${base}/api/v1/inspect`, {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: 'hello'
  });
  const body = await response.json();
  assert.equal(response.status, 415);
  assert.equal(body.error.code, 'UNSUPPORTED_MEDIA_TYPE');
  assert.equal(body.error.message, 'Content-Type must be application/json');
  assert.equal(JSON.stringify(body).includes('text/plain'), false);
});

test('bounds request IDs and logs only recognized methods and routes', async (t) => {
  const entries = [];
  const logger = {
    info(event, fields) { entries.push({ event, ...fields }); },
    warn() {},
    error() {}
  };
  const base = await withServer(t, {}, { logger });
  const marker = 'SgAuditCredentialValue947';
  const invalidId = `token=${marker}`;
  const unknown = await fetch(`${base}/private/${marker}?token=${marker}`, {
    headers: { 'x-request-id': invalidId }
  });
  const accepted = await fetch(`${base}/health`, {
    headers: { 'x-request-id': 'e13763e9-1c6f-4e34-9f0e-bd526b617d6f' }
  });
  await post(base, '/api/v1/inspect', { user_input: 'safe example' });

  assert.equal(unknown.status, 404);
  assert.match(unknown.headers.get('x-request-id'), /^[0-9a-f-]{36}$/i);
  assert.equal(accepted.headers.get('x-request-id'), 'e13763e9-1c6f-4e34-9f0e-bd526b617d6f');
  assert.deepEqual(entries.map((entry) => entry.route), ['other', '/health', '/api/v1/inspect']);
  assert.equal(JSON.stringify(entries).includes(marker), false);
  assert.equal(JSON.stringify(entries).includes('/private/'), false);
});

test('text inspection endpoint detects a known malicious pattern and has disabled AI fallback', async (t) => {
  const base = await withServer(t);
  const response = await post(base, '/api/v1/inspect', { user_input: "' OR '1'='1" });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.success, true);
  assert.equal(body.data.classification, 'sql_injection');
  assert.equal(body.data.riskScore, 70);
  assert.equal(body.data.ai.status, 'not_requested');
});

test('redacts common credential-shaped values from bounded finding evidence', async (t) => {
  const base = await withServer(t);
  const marker = 'SgAuditCredentialValue947';
  const response = await post(base, '/api/v1/inspect', {
    user_input: `' OR '1'='1 password=${marker} authorization: Bearer ${marker}`
  });
  const body = await response.json();
  const evidence = body.data.findings.map((finding) => finding.evidence).join(' ');
  assert.equal(response.status, 200);
  assert.equal(evidence.includes(marker), false);
  assert.match(evidence, /\[REDACTED\]/);
});

test('structured payload endpoint inspects nested values', async (t) => {
  const base = await withServer(t);
  const response = await post(base, '/api/v1/inspect/payload', {
    payload: { profile: { comment: '<script>alert(1)</script>' } }
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.data.classification, 'xss');
  assert.ok(body.data.findings.some((finding) => finding.ruleId === 'XSS-001'));
});

test('AI adapter failure cannot remove deterministic findings', async (t) => {
  const base = await withServer(t, {}, {
    analyzer: async () => { throw new Error('provider implementation details'); }
  });
  const response = await post(base, '/api/v1/inspect', {
    user_input: '<script>alert(1)</script>',
    ai_consent: true
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.data.classification, 'xss');
  assert.ok(body.data.findings.some((finding) => finding.ruleId === 'XSS-001'));
  assert.deepEqual(body.data.ai, { enabled: true, status: 'unavailable' });
});

test('requires per-inspection consent and skips AI for detected secrets', async (t) => {
  let analyzerCalls = 0;
  const base = await withServer(t, {}, {
    analyzer: async () => {
      analyzerCalls += 1;
      return { summary: 'Supplementary analysis.' };
    }
  });

  const notConsented = await post(base, '/api/v1/inspect', {
    user_input: '<script>alert(1)</script>'
  });
  const deterministicOnly = await notConsented.json();
  assert.equal(deterministicOnly.data.ai.status, 'not_requested');
  assert.equal(analyzerCalls, 0);
  assert.equal(deterministicOnly.data.classification, 'xss');
  assert.equal(deterministicOnly.data.riskScore, 70);

  const sensitive = await post(base, '/api/v1/inspect', {
    user_input: 'password="local-example-secret" <script>alert(1)</script>',
    ai_consent: true
  });
  const skipped = await sensitive.json();
  assert.equal(skipped.data.ai.status, 'skipped_sensitive');
  assert.equal(analyzerCalls, 0);
  assert.equal(skipped.data.classification, 'xss');
  assert.equal(skipped.data.riskScore, 70);
});

test('consented AI enrichment does not override deterministic inspection results', async (t) => {
  const base = await withServer(t, {}, {
    analyzer: async () => ({
      summary: 'Supplementary context only.',
      explanation: 'Additional context.',
      confidence: 0.5
    })
  });
  const response = await post(base, '/api/v1/inspect', {
    user_input: '<script>alert(1)</script>',
    ai_consent: true
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.data.ai.status, 'available');
  assert.equal(body.data.classification, 'xss');
  assert.equal(body.data.riskScore, 70);
  assert.ok(body.data.findings.some((finding) => finding.ruleId === 'XSS-001'));
});

test('propagates explicit consent for JSON payload inspection', async (t) => {
  let analyzerCalls = 0;
  const base = await withServer(t, {}, {
    analyzer: async () => {
      analyzerCalls += 1;
      return { summary: 'Supplementary payload analysis.' };
    }
  });
  const response = await post(base, '/api/v1/inspect/payload', {
    payload: { comment: '<script>alert(1)</script>' },
    ai_consent: true
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(analyzerCalls, 1);
  assert.equal(body.data.ai.status, 'available');
  assert.equal(body.data.classification, 'xss');
  assert.equal(body.data.riskScore, 70);
});

test('AI failure reporting errors do not interrupt deterministic inspection', async (t) => {
  const base = await withServer(t, {}, {
    analyzer: async () => { throw new Error('provider failure'); },
    onAiFailure: () => { throw new Error('reporting callback failure'); }
  });
  const response = await post(base, '/api/v1/inspect', {
    user_input: '<script>alert(1)</script>',
    ai_consent: true
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.ok(body.data.findings.some((finding) => finding.ruleId === 'XSS-001'));
  assert.deepEqual(body.data.ai, { enabled: true, status: 'unavailable' });
});

test('returns safe validation, malformed JSON, 404, and body-limit errors', async (t) => {
  const base = await withServer(t, { jsonBodyLimit: '1kb', maxInputChars: 500 });
  const missing = await post(base, '/api/v1/inspect', {});
  assert.equal(missing.status, 400);
  assert.equal((await missing.json()).error.code, 'VALIDATION_ERROR');

  const malformed = await fetch(`${base}/api/v1/inspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"user_input":'
  });
  assert.equal(malformed.status, 400);
  assert.equal((await malformed.json()).error.code, 'MALFORMED_JSON');

  const tooLarge = await post(base, '/api/v1/inspect', { user_input: 'x'.repeat(1200) });
  assert.equal(tooLarge.status, 413);
  assert.equal((await tooLarge.json()).error.code, 'REQUEST_TOO_LARGE');

  const missingRoute = await fetch(`${base}/private`);
  assert.equal(missingRoute.status, 404);
});

test('rejects disallowed browser origins and applies inspection rate limiting', async (t) => {
  const base = await withServer(t, {
    corsOrigins: ['http://allowed.example'],
    rateLimitMax: 1,
    rateLimitWindowMs: 60000
  });
  const denied = await post(base, '/api/v1/inspect', { user_input: 'hello' }, {
    origin: 'http://attacker.example'
  });
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error.code, 'CORS_ORIGIN_DENIED');

  const first = await post(base, '/api/v1/inspect', { user_input: 'hello' });
  const second = await post(base, '/api/v1/inspect', { user_input: 'hello' });
  assert.equal(first.status, 200);
  assert.equal(second.status, 429);
  assert.equal((await second.json()).error.code, 'RATE_LIMITED');
  assert.equal((await fetch(`${base}/health`)).status, 200);
});

test('validates environment configuration and requires production CORS origins', () => {
  assert.throws(() => loadConfig({ NODE_ENV: 'production' }), /CORS_ORIGINS/);
  assert.throws(() => loadConfig({ JSON_BODY_LIMIT: '100mb' }), /must not exceed/);
  assert.equal(loadConfig({
    NODE_ENV: 'production',
    CORS_ORIGINS: 'https://example.com'
  }).corsOrigins[0], 'https://example.com');
});
