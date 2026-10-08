const CONTRIBUTION = Object.freeze({
  informational: 5,
  low: 15,
  medium: 30,
  high: 50,
  critical: 70
});

const SEVERITY_ORDER = Object.freeze({
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
});

function calculateRiskScore(findings) {
  let remaining = 1;
  for (const finding of findings) {
    const contribution = CONTRIBUTION[finding.severity];
    if (contribution === undefined) {
      throw new TypeError(`Unsupported finding severity: ${finding.severity}`);
    }
    remaining *= 1 - contribution / 100;
  }
  return Math.min(100, Math.max(0, Math.round((1 - remaining) * 100)));
}

function severityFor(findings, riskScore) {
  if (findings.length === 0) return 'informational';
  const findingSeverity = findings.reduce(
    (highest, item) => Math.max(highest, SEVERITY_ORDER[item.severity]),
    0
  );
  const scoreSeverity = riskScore >= 90 ? SEVERITY_ORDER.critical
    : riskScore >= 70 ? SEVERITY_ORDER.high
      : riskScore >= 30 ? SEVERITY_ORDER.medium
        : SEVERITY_ORDER.low;
  const result = Math.max(findingSeverity, scoreSeverity);
  return Object.keys(SEVERITY_ORDER).find((severity) => SEVERITY_ORDER[severity] === result);
}

module.exports = { calculateRiskScore, severityFor, SEVERITY_ORDER };
