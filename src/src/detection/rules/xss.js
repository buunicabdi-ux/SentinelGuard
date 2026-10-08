const { regexRule } = require('./shared');

module.exports = [
  regexRule({
    ruleId: 'XSS-001',
    category: 'xss',
    severity: 'critical',
    description: 'An executable script element was detected.',
    recommendation: 'Encode untrusted output for its context and apply a restrictive Content Security Policy.',
    pattern: /<\s*script\b[^>]*>/i
  }),
  regexRule({
    ruleId: 'XSS-002',
    category: 'xss',
    severity: 'high',
    description: 'An HTML event-handler attribute was detected.',
    recommendation: 'Do not render untrusted HTML; use contextual output encoding and safe DOM APIs.',
    pattern: /\bon[a-z]{3,32}\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/i
  }),
  regexRule({
    ruleId: 'XSS-003',
    category: 'xss',
    severity: 'high',
    description: 'A JavaScript URL scheme was detected.',
    recommendation: 'Reject executable URL schemes and allowlist safe protocols such as HTTPS.',
    pattern: /javascript\s*:/i
  }),
  regexRule({
    ruleId: 'XSS-004',
    category: 'xss',
    severity: 'medium',
    description: 'Encoded markup resembles an executable script element.',
    recommendation: 'Decode and validate input safely before rendering; apply contextual output encoding.',
    pattern: /&lt;\s*script\b/i
  })
];
