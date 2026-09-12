const assert = require('assert');
const { normalizeTarget, normalizeApprovedTargets, isApprovedTarget } = require('./src/scope');

assert.strictEqual(normalizeTarget('https://APP.Example.com/path'), 'app.example.com');
assert.strictEqual(normalizeTarget('203.0.113.10'), '203.0.113.10');
assert.strictEqual(normalizeTarget('2001:db8::10'), '2001:db8::10');
assert.strictEqual(normalizeTarget('example.com:443'), null);
assert.strictEqual(normalizeTarget('not a host'), null);
assert.deepStrictEqual(normalizeApprovedTargets(['APP.example.com', 'app.example.com']).targets, ['app.example.com']);
assert.strictEqual(isApprovedTarget('app.example.com', ['app.example.com']), true);
assert.strictEqual(isApprovedTarget('other.example.com', ['app.example.com']), false);
console.log('scope tests passed');
