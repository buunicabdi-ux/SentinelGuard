const { regexRule } = require('./shared');

module.exports = [
  regexRule({
    ruleId: 'CMD-001',
    category: 'command_injection',
    severity: 'critical',
    description: 'Shell command substitution syntax was detected.',
    recommendation: 'Avoid invoking a shell with untrusted input; use safe process APIs and strict argument allowlists.',
    pattern: /\$\([^)\r\n]{1,120}\)|`[^`\r\n]{1,120}`/
  }),
  regexRule({
    ruleId: 'CMD-002',
    category: 'command_injection',
    severity: 'high',
    description: 'A shell control operator is combined with a command-like token.',
    recommendation: 'Do not concatenate untrusted input into commands; use fixed executable names and validated arguments.',
    pattern: /(?:;|&&|\|\|)\s*(?:cat|curl|wget|bash|sh|powershell|cmd(?:\.exe)?|whoami|id|rm|nc)\b/i
  }),
  regexRule({
    ruleId: 'CMD-003',
    category: 'command_injection',
    severity: 'high',
    description: 'A pipe operator is followed by a command commonly used in shell pipelines.',
    recommendation: 'Avoid shell interpretation of user-controlled strings and allowlist any permitted operation.',
    pattern: /\|\s*(?:sh|bash|curl|wget|nc|powershell)\b/i
  })
];
