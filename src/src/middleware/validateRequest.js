const { z } = require('zod');
const { AppError } = require('../errors');

function createInspectSchemas(maxInputChars) {
  const inputSchema = z.object({
    user_input: z.string().min(1).max(maxInputChars).refine(
      (value) => value.trim().length > 0,
      'Input must not be empty'
    ),
    ai_consent: z.boolean().optional()
  }).strict();
  const payloadSchema = z.object({
    payload: z.union([z.record(z.string(), z.unknown()), z.array(z.unknown())]),
    ai_consent: z.boolean().optional()
  }).strict();

  return { inputSchema, payloadSchema };
}

function validateBody(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      next(new AppError('Request body is invalid', 400, 'VALIDATION_ERROR'));
      return;
    }
    req.validatedBody = result.data;
    next();
  };
}

function normalizePayload(payload, { maxDepth = 8, maxNodes = 2000, maxChars = 32000 } = {}) {
  let nodes = 0;
  let chars = 0;
  const chunks = [];

  function add(text) {
    chars += text.length;
    if (chars > maxChars) {
      throw new AppError('Payload exceeds the inspection size limit', 413, 'PAYLOAD_TOO_LARGE');
    }
    chunks.push(text);
  }

  function walk(value, path, depth) {
    nodes += 1;
    if (nodes > maxNodes) {
      throw new AppError('Payload contains too many values', 400, 'PAYLOAD_TOO_COMPLEX');
    }
    if (depth > maxDepth) {
      throw new AppError('Payload nesting is too deep', 400, 'PAYLOAD_TOO_DEEP');
    }

    if (value === null || typeof value === 'boolean' || typeof value === 'number') {
      add(`${path}=${String(value)}\n`);
      return;
    }
    if (typeof value === 'string') {
      add(`${path}=${value}\n`);
      return;
    }
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        walk(value[index], `${path}[${index}]`, depth + 1);
      }
      return;
    }
    if (value && typeof value === 'object') {
      const entries = Object.entries(value);
      for (const [key, child] of entries) {
        add(`${path}.${key}:`);
        walk(child, `${path}.${key}`, depth + 1);
      }
      return;
    }
    throw new AppError('Payload contains an unsupported value', 400, 'INVALID_PAYLOAD_VALUE');
  }

  walk(payload, 'payload', 0);
  return chunks.join('');
}

module.exports = { createInspectSchemas, normalizePayload, validateBody };
