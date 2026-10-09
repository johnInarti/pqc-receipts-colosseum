/**
 * Spec 2.1 §12 (latam-stablecoin-receipt): unit tests for behaviour that is not a corpus vector — amount rendering,
 * strict ABI decoding, registry overrides, and the offline (verifySync) rule for the `onchain` level.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  verify, verifySync, parseJsonStrict, CODES, EXIT, formatUnits, abiDecodeString, abiDecodeUint8, checkRegistry, BAKED_STABLECOIN_REGISTRY,
} from '../src/index.mjs';

const P30 = parseJsonStrict(readFileSync(new URL('../../corpus/vectors/P30-stablecoin-copm-polygon-two-rpcs.json', import.meta.url), 'utf8'));
const RECEIPT = JSON.stringify(P30.input.receipt);
const KEYS = [P30.input.receipt.public_key];

test('formatUnits renders canonically (no trailing zeros, no exponent, uint256-sized)', () => {
  assert.equal(formatUnits('667703000000000000000000', 18), '667703');
  assert.equal(formatUnits('135000000', 6), '135');
  assert.equal(formatUnits('18139674', 6), '18.139674');
  assert.equal(formatUnits('1', 18), '0.000000000000000001');
  assert.equal(formatUnits('627114637588570086999', 18), '627.114637588570086999');
  const max = ((1n << 256n) - 1n).toString();
  assert.equal(formatUnits(max, 0), max);
});

test('strict ABI decoding of symbol() / decimals()', () => {
  const str = (s, extra = '') => '0x' + '20'.padStart(64, '0') + s.length.toString(16).padStart(64, '0') + Buffer.from(s).toString('hex').padEnd(64, '0') + extra;
  assert.equal(abiDecodeString(str('COPM')), 'COPM');
  const bad = [
    str('COPM', '00'.repeat(32)),                                            // trailing word
    '0x' + '40'.padStart(64, '0') + '4'.padStart(64, '0') + '00'.repeat(32), // wrong offset
    str('COPM').slice(0, -2) + '01',                                         // non-zero padding
    '0x434f504d',                                                            // bytes4, not ABI
    '0x' + '20'.padStart(64, '0') + '2'.padStart(64, '0') + 'c328'.padEnd(64, '0'), // invalid UTF-8
  ];
  for (const b of bad) assert.throws(() => abiDecodeString(b), (e) => e.code === CODES.PAYMENT_TOKEN_METADATA, b.slice(0, 20));
  assert.equal(abiDecodeUint8('0x' + '12'.padStart(64, '0')), 18);
  assert.throws(() => abiDecodeUint8('0x' + '100'.padStart(64, '0')), (e) => e.code === CODES.PAYMENT_TOKEN_METADATA);
});

test('baked registry is well-formed; a malformed override is REGISTRY_INVALID; overrides are reported', async () => {
  assert.equal(checkRegistry(BAKED_STABLECOIN_REGISTRY).id, 'fractalai.latam-stablecoins/1');
  const dup = { ...BAKED_STABLECOIN_REGISTRY, tokens: [...BAKED_STABLECOIN_REGISTRY.tokens, BAKED_STABLECOIN_REGISTRY.tokens[0]] };
  const v1 = await verify(RECEIPT, { kind: 'latam-stablecoin-receipt', trustedKeys: KEYS, tokenRegistry: JSON.stringify(dup), now: P30.context.now });
  assert.equal(v1.levels.integrity, false);
  assert.equal(v1.reasons[0].code, CODES.REGISTRY_INVALID);
  const without = { ...BAKED_STABLECOIN_REGISTRY, tokens: BAKED_STABLECOIN_REGISTRY.tokens.filter((t) => t.symbol !== 'COPM') };
  const v2 = await verify(RECEIPT, { kind: 'latam-stablecoin-receipt', trustedKeys: KEYS, tokenRegistry: JSON.stringify(without), now: P30.context.now });
  assert.equal(v2.reasons[0].code, CODES.TOKEN_NOT_PINNED);
  assert.ok(v2.overrides.includes('tokenRegistry'));
});

test('verifySync never reaches the network: onchain required → ONCHAIN_NOT_CHECKED, exit 15', () => {
  const v = verifySync(RECEIPT, { kind: 'latam-stablecoin-receipt', trustedKeys: KEYS, now: P30.context.now, policy: { require: ['integrity', 'authentic', 'trusted', 'onchain'] } });
  assert.deepEqual(v.levels, { integrity: true, authentic: true, trusted: true, time_anchored: null, finalized: null, onchain: false });
  assert.equal(v.reasons[0].code, CODES.ONCHAIN_NOT_CHECKED);
  assert.equal(v.exit_code, EXIT.onchain);
});

test('domain separation: the stablecoin signature never verifies as any other kind', async () => {
  for (const kind of ['midas-alert', 'x402-seal', 'served-proof', 'acp-verdict', 'self-attest-seal']) {
    const v = await verify(RECEIPT, { kind, trustedKeys: KEYS, now: P30.context.now });
    assert.equal(v.valid, false, kind);
  }
});
