const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeDeterministically } = require('../src/src/detection/engine');

const cases = [
  ["' OR '1'='1", 'sql_injection', 'SQLI-001'],
  ['UNION SELECT username FROM users', 'sql_injection', 'SQLI-002'],
  ['<script>alert(1)</script>', 'xss', 'XSS-001'],
  ['<img src=x onerror=alert(1)>', 'xss', 'XSS-002'],
  ['javascript:alert(1)', 'xss', 'XSS-003'],
  ['; cat /etc/passwd', 'command_injection', 'CMD-002'],
  ['$(whoami)', 'command_injection', 'CMD-001'],
  ['../../etc/passwd', 'path_traversal', 'PATH-001'],
  ['%2e%2e%2fetc/passwd', 'path_traversal', 'PATH-002'],
  ['Your account will be suspended today. Verify your password immediately.', 'phishing', 'PHISH-001']
];

for (const [input, category, ruleId] of cases) {
  test(`detects ${ruleId}`, () => {
    const result = analyzeDeterministically(input);
    assert.equal(result.classification, category);
    assert.ok(result.findings.some((finding) => finding.ruleId === ruleId));
  });
}

for (const input of [
  'I love SQL databases.',
  'We teach developers about XSS prevention.',
  'The command injection vulnerability was fixed.',
  'Never use ../../ paths from untrusted input.',
  'Verify a domain through its official website before signing in.',
  'The security team reviewed the account today.'
]) {
  test(`does not flag benign security discussion: ${input}`, () => {
    assert.equal(analyzeDeterministically(input).classification, 'clean');
  });
}

test('produces stable, bounded evidence and actionable recommendations', () => {
  const result = analyzeDeterministically("SELECT ' OR '1'='1'; password=supersecret");
  assert.equal(result.riskScore, analyzeDeterministically("SELECT ' OR '1'='1'; password=supersecret").riskScore);
  assert.ok(result.riskScore >= 0 && result.riskScore <= 100);
  assert.ok(result.findings.every((finding) => finding.evidence.length <= 160));
  assert.ok(result.findings.every((finding) => !finding.evidence.includes('supersecret')));
  assert.ok(result.recommendations.length > 0);
});
