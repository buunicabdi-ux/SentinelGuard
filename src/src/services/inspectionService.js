const { analyzeDeterministically } = require('../detection/engine');
const { createAiBoundary } = require('../ai/analyzer');
const { containsSensitiveInput } = require('../ai/privacy');

function createInspectionService({ analyzer, onAiFailure, logger } = {}) {
  const reportAiFailure = (error) => {
    logger.warn('ai_analysis_unavailable');
    if (onAiFailure) {
      try {
        onAiFailure(error);
      } catch {
        logger.error('ai_failure_reporter_failed');
      }
    }
  };
  const aiBoundary = createAiBoundary({ analyzer, onFailure: reportAiFailure });

  return {
    async inspect(input, { aiConsent = false } = {}) {
      const deterministic = analyzeDeterministically(input);
      let ai;
      if (!aiConsent) {
        ai = { enabled: false, status: 'not_requested' };
      } else if (containsSensitiveInput(input)) {
        ai = { enabled: false, status: 'skipped_sensitive' };
      } else {
        ai = await aiBoundary.analyze(input, deterministic);
      }
      return { ...deterministic, ai };
    }
  };
}

module.exports = { createInspectionService };
