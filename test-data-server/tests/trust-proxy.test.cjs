const { test } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

function request(trust, peer) {
  const app = express();
  app.set('trust proxy', trust);
  const req = Object.create(app.request);
  req.app = app;
  req.socket = { remoteAddress: peer };
  req.headers = { 'x-forwarded-for': '198.51.100.8' };
  return req;
}

for (const trust of ['::ffff:10.0.0.0/8', '::/1']) {
  test(`an IPv6 trust subnet ${trust} must not trust an arbitrary IPv4 peer`, () => {
    const req = request(trust, '203.0.113.7');
    assert.equal(req.ip, '203.0.113.7');
    assert.deepEqual(req.ips, []);
  });
}

for (const [trust, peer] of [
  ['::ffff:10.0.0.0/104', '10.1.2.3'],
  ['10.0.0.0/8', '10.1.2.3'],
  ['2001:db8::/32', '2001:db8::1'],
]) {
  test(`legitimate forwarding through ${trust} remains supported`, () => {
    const req = request(trust, peer);
    assert.equal(req.ip, '198.51.100.8');
    assert.deepEqual(req.ips, ['198.51.100.8']);
  });
}
