const SECRET_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /\b(authorization)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\r\n,;]+)/gi,
  /\b(password|passwd|token|api[\s_-]?key|secret)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi
];

function safeEvidence(input, match) {
  const index = Math.max(0, match.index || 0);
  const start = Math.max(0, index - 48);
  const end = Math.min(input.length, index + match[0].length + 48);
  let evidence = input.slice(start, end).replace(/\s+/g, ' ').trim();
  for (const pattern of SECRET_PATTERNS) {
    evidence = evidence.replace(pattern, '[REDACTED]');
  }
  if (start > 0) evidence = `…${evidence}`;
  if (end < input.length) evidence = `${evidence}…`;
  return evidence.slice(0, 160);
}

function finding(rule, input, match) {
  return {
    ruleId: rule.ruleId,
    category: rule.category,
    severity: rule.severity,
    description: rule.description,
    evidence: safeEvidence(input, match),
    recommendation: rule.recommendation
  };
}

function regexRule(rule) {
  return {
    ...rule,
    detect(input) {
      const match = rule.pattern.exec(input);
      return match ? finding(rule, input, match) : null;
    }
  };
}

module.exports = { finding, regexRule };
