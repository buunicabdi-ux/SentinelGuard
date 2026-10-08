const { finding } = require('./shared');

function makeRule(ruleId, severity, description, recommendation, pattern) {
  return {
    ruleId,
    category: 'phishing',
    severity,
    description,
    recommendation,
    detect(input) {
      const match = pattern.exec(input);
      return match ? finding(this, input, match) : null;
    }
  };
}

module.exports = [
  makeRule(
    'PHISH-001',
    'medium',
    'Urgent account language is combined with a request for credentials or verification.',
    'Verify the request through a trusted channel and never submit credentials through an unsolicited link.',
    /\b(?:account|mailbox|access)\b.{0,100}\b(?:suspend(?:ed)?|locked|expire[sd]?|verify|confirm)\b.{0,100}\b(?:password|credential|login|sign[ -]?in|verify)\b|\b(?:suspend(?:ed)?|locked|expire[sd]?)\b.{0,100}\b(?:password|credential|login|sign[ -]?in)\b/i
  ),
  makeRule(
    'PHISH-002',
    'medium',
    'Urgent payment language is combined with a payment demand.',
    'Verify payment requests independently using known contact details before transferring funds.',
    /\b(?:urgent|immediately|today|final notice)\b.{0,100}\b(?:payment|wire|transfer|invoice|gift card)\b|\b(?:payment|wire|transfer|invoice|gift card)\b.{0,100}\b(?:urgent|immediately|today|final notice)\b/i
  ),
  makeRule(
    'PHISH-003',
    'medium',
    'A URL contains user-info syntax that can visually obscure its destination host.',
    'Inspect the actual destination domain and use a trusted bookmark instead of following an unsolicited link.',
    /https?:\/\/[^/\s@]+@[^/\s]+/i
  ),
  makeRule(
    'PHISH-004',
    'low',
    'A URL uses a punycode hostname, which can be used in visually deceptive domains.',
    'Confirm the domain spelling and ownership through a trusted source; this indicator alone does not establish maliciousness.',
    /https?:\/\/(?:[^/\s.]+\.)?xn--[a-z0-9-]+/i
  ),
  makeRule(
    'PHISH-005',
    'medium',
    'A credential request is paired with language discouraging normal security checks.',
    'Do not bypass security controls or share credentials; verify the request independently.',
    /\b(?:password|credentials|login)\b.{0,100}\b(?:ignore|bypass|disable)\b.{0,60}\b(?:security|warning|verification|mfa|2fa)\b|\b(?:ignore|bypass|disable)\b.{0,60}\b(?:security|warning|verification|mfa|2fa)\b.{0,100}\b(?:password|credentials|login)\b/i
  )
];
