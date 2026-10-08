const { calculateRiskScore, severityFor, SEVERITY_ORDER } = require('./riskScore');
const ruleGroups = [
  require('./rules/sqli'),
  require('./rules/xss'),
  require('./rules/commandInjection'),
  require('./rules/pathTraversal'),
  require('./rules/phishing')
];

const CATEGORY_ORDER = [
  'sql_injection',
  'xss',
  'command_injection',
  'path_traversal',
  'phishing'
];

function detectFindings(input) {
  return ruleGroups.flatMap((rules) => rules
    .map((rule) => rule.detect(input))
    .filter(Boolean))
    .sort((left, right) =>
      SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity] ||
      left.ruleId.localeCompare(right.ruleId));
}

function classify(findings) {
  if (findings.length === 0) return 'clean';
  const highestSeverity = Math.max(...findings.map((finding) => SEVERITY_ORDER[finding.severity]));
  const highest = findings.filter((finding) => SEVERITY_ORDER[finding.severity] === highestSeverity);
  const category = CATEGORY_ORDER.find((candidate) =>
    highest.some((finding) => finding.category === candidate));
  return category || 'suspicious';
}

function analyzeDeterministically(input) {
  const findings = detectFindings(input);
  const riskScore = calculateRiskScore(findings);
  const recommendations = [...new Set(findings.map((finding) => finding.recommendation))];
  return {
    riskScore,
    classification: classify(findings),
    severity: severityFor(findings, riskScore),
    findings,
    recommendations
  };
}

module.exports = { analyzeDeterministically, detectFindings, classify };
