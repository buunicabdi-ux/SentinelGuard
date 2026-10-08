const test = require('node:test');
const assert = require('node:assert/strict');
const { calculateRiskScore, severityFor } = require('../src/src/detection/riskScore');

test('scores no findings as zero', () => {
  assert.equal(calculateRiskScore([]), 0);
});

test('uses the documented bounded aggregation formula', () => {
  assert.equal(calculateRiskScore([{ severity: 'critical' }]), 70);
  assert.equal(calculateRiskScore([{ severity: 'high' }, { severity: 'medium' }]), 65);
  assert.equal(calculateRiskScore([{ severity: 'critical' }, { severity: 'critical' }]), 91);
});

test('keeps risk score bounded and maps overall severity', () => {
  assert.equal(calculateRiskScore(Array.from({ length: 20 }, () => ({ severity: 'critical' }))), 100);
  assert.equal(severityFor([], 0), 'informational');
  assert.equal(severityFor([{ severity: 'critical' }], 70), 'critical');
});

test('rejects unknown severities rather than silently scoring them', () => {
  assert.throws(() => calculateRiskScore([{ severity: 'unknown' }]), /Unsupported finding severity/);
});
