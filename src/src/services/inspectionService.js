const { analyzeDeterministically } = require('../detection/engine');
const { createAiBoundary } = require('../ai/analyzer');

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
    async inspect(input) {
      const deterministic = analyzeDeterministically(input);
      const ai = await aiBoundary.analyze(input, deterministic);
      return { ...deterministic, ai };
    }
  };
}

module.exports = { createInspectionService };
