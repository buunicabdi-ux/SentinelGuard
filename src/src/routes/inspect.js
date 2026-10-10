const express = require('express');
const { createInspectSchemas, validateBody, normalizePayload } = require('../middleware/validateRequest');

function createInspectRouter({ inspectionService, maxInputChars }) {
  const router = express.Router();
  const { inputSchema, payloadSchema } = createInspectSchemas(maxInputChars);

  router.post('/inspect', validateBody(inputSchema), async (req, res) => {
    const { user_input: input, ai_consent: aiConsent } = req.validatedBody;
    const data = await inspectionService.inspect(input, { aiConsent: aiConsent === true });
    res.locals.inspection = {
      riskScore: data.riskScore,
      classification: data.classification
    };
    res.status(200).json({ success: true, data });
  });

  router.post('/inspect/payload', validateBody(payloadSchema), async (req, res) => {
    const { payload, ai_consent: aiConsent } = req.validatedBody;
    const normalized = normalizePayload(payload, { maxChars: maxInputChars });
    const data = await inspectionService.inspect(normalized, { aiConsent: aiConsent === true });
    res.locals.inspection = {
      riskScore: data.riskScore,
      classification: data.classification
    };
    res.status(200).json({ success: true, data });
  });

  return router;
}

module.exports = { createInspectRouter };
