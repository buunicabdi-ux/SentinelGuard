const { regexRule } = require('./shared');

module.exports = [
  regexRule({
    ruleId: 'SQLI-001',
    category: 'sql_injection',
    severity: 'critical',
    description: 'Possible SQL tautology or authentication-bypass pattern detected.',
    recommendation: 'Use parameterized queries or prepared statements and never concatenate untrusted input into SQL.',
    pattern: /['"]\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i
  }),
  regexRule({
    ruleId: 'SQLI-002',
    category: 'sql_injection',
    severity: 'high',
    description: 'A UNION SELECT query-composition pattern was detected.',
    recommendation: 'Use parameterized queries and restrict database operations to expected query structures.',
    pattern: /\bunion\s+(?:all\s+)?select\b/i
  }),
  regexRule({
    ruleId: 'SQLI-003',
    category: 'sql_injection',
    severity: 'high',
    description: 'SQL comment syntax appears to follow query-control text.',
    recommendation: 'Use parameterized queries and reject unexpected SQL control syntax in user input.',
    pattern: /\b(?:select|where|or|and|union)\b.{0,80}(?:--|#|\/\*)/i
  })
];
