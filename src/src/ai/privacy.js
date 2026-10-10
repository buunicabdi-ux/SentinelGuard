const MAX_AI_CONTENT_CHARS = 1200;

const sensitivePatterns = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/i,
  /\bauthorization["']?\s*[:=]\s*(?:bearer\s+)?(?:"[^"]*"|'[^']*'|[^\s,;]+)/i,
  /\bbearer\s+[^\s,;]+/i,
  /\b(?:password|passwd|token|api[\s_-]?key|secret|access[\s_-]?token|refresh[\s_-]?token|client[\s_-]?secret)\b["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;}\]]+)/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/
];

const redactionPatterns = [
  {
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gi,
    replacement: '[REDACTED PRIVATE KEY]'
  },
  {
    pattern: /\bauthorization["']?\s*[:=]\s*(?:bearer\s+)?(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,
    replacement: 'authorization: [REDACTED CREDENTIAL]'
  },
  {
    pattern: /\bbearer\s+[^\s,;]+/gi,
    replacement: '[REDACTED CREDENTIAL]'
  },
  {
    pattern: /\b(password|passwd|token|api[\s_-]?key|secret|access[\s_-]?token|refresh[\s_-]?token|client[\s_-]?secret)\b["']?(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}\]]+)/gi,
    replacement: '$1$2[REDACTED]'
  },
  {
    pattern: /\bAKIA[0-9A-Z]{16}\b/gi,
    replacement: '[REDACTED CREDENTIAL]'
  },
  {
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})\b/gi,
    replacement: '[REDACTED CREDENTIAL]'
  },
  {
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    replacement: '[REDACTED TOKEN]'
  }
];

function normalizeInspectionInput(input) {
  if (typeof input === 'string') return input;
  if (input === undefined || input === null) return '';
  if (typeof input === 'number' || typeof input === 'boolean') return String(input);
  try {
    return JSON.stringify(input);
  } catch {
    return String(input);
  }
}

function containsSensitiveInput(input) {
  const content = normalizeInspectionInput(input);
  return sensitivePatterns.some((pattern) => pattern.test(content));
}

function prepareAiContent(input) {
  let content = normalizeInspectionInput(input).replace(/\s+/g, ' ').trim();
  for (const { pattern, replacement } of redactionPatterns) {
    content = content.replace(pattern, replacement);
  }
  return content.slice(0, MAX_AI_CONTENT_CHARS);
}

module.exports = { containsSensitiveInput, prepareAiContent, MAX_AI_CONTENT_CHARS };
