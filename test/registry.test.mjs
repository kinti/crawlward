import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const registry = JSON.parse(readFileSync(new URL('../registry/crawlers.json', import.meta.url), 'utf8'));

test('registry structure is coherent', () => {
  assert.ok(Array.isArray(registry.crawlers));
  assert.ok(Array.isArray(registry.controlTokens));
  assert.ok(registry.crawlers.length >= 20);
  for (const c of registry.crawlers) {
    assert.equal(typeof c.token, 'string');
    assert.ok(c.token.length > 0);
    assert.equal(typeof c.vendor, 'string');
    assert.equal(typeof c.purpose, 'string');
    assert.ok(typeof c.verified === 'boolean', `verified flag missing on ${c.token}`);
    if (c.ranges !== undefined) {
      assert.ok(c.ranges.startsWith('https://'), `ranges must be https: ${c.token}`);
    }
  }
});

test('control tokens are documented, never matchable as crawlers', () => {
  const controlTokens = registry.controlTokens.map((t) => t.token);
  assert.ok(controlTokens.includes('Google-Extended'));
  assert.ok(controlTokens.includes('Applebot-Extended'));
  // No crawler entry may collide with a control token: a UA containing a
  // control token in logs is by definition not the vendor.
  for (const t of controlTokens) {
    const clash = registry.crawlers.find((c) => c.token === t);
    assert.equal(clash, undefined, `${t} must live in controlTokens, not crawlers`);
  }
});

test('crawler tokens are unique', () => {
  const tokens = registry.crawlers.map((c) => c.token.toLowerCase());
  assert.equal(new Set(tokens).size, tokens.length);
});

test('every verified crawler cites an official doc URL', () => {
  for (const c of registry.crawlers) {
    if (c.verified) {
      assert.ok(c.doc && c.doc.startsWith('https://'), `verified entry needs doc: ${c.token}`);
    }
  }
});
