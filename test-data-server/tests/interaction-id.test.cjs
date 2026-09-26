const assert = require('node:assert/strict');
const { test } = require('node:test');
const { cdrHeaderValidator } = require('@cds-au/holder-sdk/dist/src/cdr-header-validator');

function validateHeader(interactionId) {
  const headers = { 'x-v': '1' };
  if (interactionId !== undefined) headers['x-fapi-interaction-id'] = interactionId;
  const result = { headers: {}, continued: false };
  const response = {
    setHeader(name, value) { result.headers[name] = value; },
    status(code) { result.status = code; return this; },
    json(body) { result.body = body; return this; },
  };
  cdrHeaderValidator()(
    { url: '/cds-au/v1/banking/products', method: 'GET', headers },
    response,
    () => { result.continued = true; },
  );
  return result;
}

test('the holder SDK generates a v4 interaction ID when none is supplied', () => {
  const result = validateHeader();
  assert.equal(result.continued, true);
  assert.match(result.headers['x-fapi-interaction-id'], /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
});

test('the holder SDK preserves a valid supplied interaction ID', () => {
  const id = '12345678-1234-4123-8123-123456789abc';
  const result = validateHeader(id);
  assert.equal(result.continued, true);
  assert.equal(result.headers['x-fapi-interaction-id'], id);
});

test('the holder SDK rejects an invalid interaction ID', () => {
  const result = validateHeader('invalid-interaction-id');
  assert.equal(result.continued, false);
  assert.equal(result.status, 400);
  assert.ok(result.body.errors.some(error => error.detail === 'x-fapi-interaction-id'));
});
