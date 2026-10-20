// Text-only regression: never imports the composition or executes Remotion.
// Run from the repository root: node --test video/tests/showcase-copy.test.mjs
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

const root = new URL('../../', import.meta.url);
const read = (path) => readFileSync(new URL(path, root), 'utf8');
const source = read('video/src/HeroCryptShowcase.tsx');
const readiness = read('PRODUCTION_READINESS.md').replace(/\s+/g, ' ');

test('showcase license agrees with the project LICENSE and README', () => {
  assert.match(read('LICENSE'), /Apache License\s+Version 2\.0/);
  assert.match(read('README.md'), /License: Apache-2\.0/);
  assert.match(source, /"Apache-2\.0 licensed"/);
  assert.doesNotMatch(source, /MIT licensed/i);
});

test('showcase qualifies deployment readiness rather than certifying all APIs', () => {
  assert.match(readiness, /qualified by API and deployment profile/);
  assert.match(source, /Qualify your API and deployment profile/);
  assert.match(source, /PRODUCTION_READINESS\.md/);
  assert.doesNotMatch(source, /production-ready API/i);
});

test('messaging card describes the documented profile and interoperability limits', () => {
  assert.match(readiness, /in-memory profiles/);
  assert.match(readiness, /no independent professional audit, persistent-state support or Signal wire interoperability/);
  assert.match(readiness, /not qualified production messaging protocols/);
  const card = source.match(/title: "Protocols",\s+items: \[([\s\S]*?)\]/)?.[1];
  assert.ok(card, 'Protocols card must be present');
  assert.match(card, /X3DH \/ Double Ratchet: in-memory/);
  assert.match(card, /No Signal wire interoperability/);
  assert.match(card, /Not production messaging protocols/);
  assert.doesNotMatch(source, /Noise, Signal, TLS 1\.3/);
});
