const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

test('env-guard-api has command modules', () => {
  assert.equal(fs.existsSync('src/index.js'), true);
  assert.equal(fs.existsSync('src/commands/init.js'), true);
});
