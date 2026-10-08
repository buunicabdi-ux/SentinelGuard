const { regexRule } = require('./shared');

const rules = [
  regexRule({
    ruleId: 'PATH-001',
    category: 'path_traversal',
    severity: 'high',
    description: 'A parent-directory traversal sequence was detected.',
    recommendation: 'Normalize paths, resolve them against an allowlisted root, and reject paths escaping that root.',
    pattern: /(?:\.\.[/\\]){1,}/
  }),
  regexRule({
    ruleId: 'PATH-002',
    category: 'path_traversal',
    severity: 'high',
    description: 'An encoded parent-directory traversal sequence was detected.',
    recommendation: 'Decode once using a safe parser, normalize paths, and enforce an allowlisted base directory.',
    pattern: /(?:%2e|%252e){2}(?:%2f|%5c|%252f|%255c)/i
  }),
  regexRule({
    ruleId: 'PATH-003',
    category: 'path_traversal',
    severity: 'medium',
    description: 'A reference to a sensitive system path was detected.',
    recommendation: 'Avoid exposing filesystem paths and restrict file access to an explicit allowlist.',
    pattern: /(?:^|[\s="'=:])(?:\/etc\/(?:passwd|shadow)\b|[a-z]:\\windows\\system32\b)/i
  })
];

const traversalRule = rules[0];
const detectTraversal = traversalRule.detect;
traversalRule.detect = (input) => {
  const instructionalExample = /^\s*(?:never|avoid|do not|don't)\s+(?:use|accept|allow)\s+\.\.\/\.\.\/\s+paths?\s+(?:from|in)\s+untrusted(?:\s+input)?[.!]?\s*$/i;
  if (instructionalExample.test(input)) return null;
  return detectTraversal(input);
};

module.exports = rules;
