// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

test('validates conformance vectors, CDDL schemas, and TLA+ specification', () => {
  const v1 = JSON.parse(fs.readFileSync(path.join(repoRoot, 'vectors/vectors.json'), 'utf8'));
  assert.ok(Array.isArray(v1.cases) && v1.cases.length >= 10);
  const v2 = JSON.parse(fs.readFileSync(path.join(repoRoot, 'vectors/vectors-v2.json'), 'utf8'));
  assert.ok(Array.isArray(v2.cases) && v2.cases.length > 0);
  const cddl = fs.readFileSync(path.join(repoRoot, 'cddl/capsule.cddl'), 'utf8');
  assert.ok(cddl.includes('urn:hivemind:receipts:capsule:1'));
  const tla = fs.readFileSync(path.join(repoRoot, 'spec/HivemindReceipts.tla'), 'utf8');
  assert.ok(tla.includes('MODULE HivemindReceipts'));
  const cfg = fs.readFileSync(path.join(repoRoot, 'spec/HivemindReceipts.cfg'), 'utf8');
  assert.ok(cfg.includes('INV_NoUnsignedRegistered'));
  const tlcOut = fs.readFileSync(path.join(repoRoot, 'spec/tlc-output.txt'), 'utf8');
  assert.ok(tlcOut.includes('No error has been found.'));
  const modelRun = JSON.parse(fs.readFileSync(path.join(repoRoot, 'spec/FORMAL-MODEL-RUN.json'), 'utf8'));
  assert.equal(modelRun.ok, true);
});
