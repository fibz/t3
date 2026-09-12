const assert = require('assert');
const { createAssessmentSummary, riskRating } = require('./src/report-summary');

assert.strictEqual(riskRating({ critical: 1, high: 0, medium: 0, low: 0 }), 'Critical');
assert.strictEqual(riskRating({ critical: 0, high: 1, medium: 4, low: 0 }), 'High');
const summary = createAssessmentSummary({ authorizationConfirmedAt: '2026-08-28T00:00:00.000Z', scopeTarget: 'app.example.com', results: { modules: { cve: { totalVulnerabilities: 2, bySeverity: { HIGH: 1, LOW: 1 } }, ssl: { error: 'unavailable' } } } });
assert.deepStrictEqual(summary.counts, { critical: 0, high: 1, medium: 0, low: 1, unknown: 0 });
assert.strictEqual(summary.risk, 'High');
assert.strictEqual(summary.authorizationRecorded, true);
assert.deepStrictEqual(summary.unavailableChecks, ['ssl']);
console.log('report summary tests passed');
