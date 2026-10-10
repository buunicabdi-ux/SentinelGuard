const test = require('node:test');
const assert = require('node:assert/strict');
const { createInspectSchemas, normalizePayload } = require('../src/src/middleware/validateRequest');

const { inputSchema, payloadSchema } = createInspectSchemas(32);

test('validates required non-empty string input and maximum size', () => {
  assert.equal(inputSchema.safeParse({ user_input: 'hello' }).success, true);
  assert.equal(inputSchema.safeParse({}).success, false);
  assert.equal(inputSchema.safeParse({ user_input: '' }).success, false);
  assert.equal(inputSchema.safeParse({ user_input: 123 }).success, false);
  assert.equal(inputSchema.safeParse({ user_input: 'x'.repeat(33) }).success, false);
});

test('accepts optional boolean AI consent and rejects other consent values', () => {
  assert.equal(inputSchema.safeParse({ user_input: 'hello', ai_consent: true }).success, true);
  assert.equal(inputSchema.safeParse({ user_input: 'hello', ai_consent: false }).success, true);
  assert.equal(inputSchema.safeParse({ user_input: 'hello', ai_consent: 'yes' }).success, false);
  assert.equal(payloadSchema.safeParse({ payload: {}, ai_consent: true }).success, true);
  assert.equal(payloadSchema.safeParse({ payload: {}, ai_consent: 1 }).success, false);
});

test('rejects unknown request fields', () => {
  assert.equal(inputSchema.safeParse({ user_input: 'hello', extra: true }).success, false);
  assert.equal(payloadSchema.safeParse({ payload: {}, extra: true }).success, false);
});

test('normalizes nested structures while preserving property names and values', () => {
  assert.match(normalizePayload({ user: { name: 'admin' }, items: [1, true] }), /payload\.user\.name=admin/);
  assert.match(normalizePayload({ items: [1, true] }), /payload\.items\[1\]=true/);
});

test('bounds payload depth, values, and serialized size', () => {
  assert.throws(() => normalizePayload({ a: { b: { c: 1 } } }, { maxDepth: 1 }), /nesting is too deep/);
  assert.throws(() => normalizePayload([1, 2, 3], { maxNodes: 2 }), /too many values/);
  assert.throws(() => normalizePayload({ value: 'x'.repeat(20) }, { maxChars: 10 }), /size limit/);
});

test('requires payload to be an object or array', () => {
  assert.equal(payloadSchema.safeParse({ payload: null }).success, false);
  assert.equal(payloadSchema.safeParse({ payload: 'text' }).success, false);
});
