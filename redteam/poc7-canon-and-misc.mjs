// PoC 7 — canonicalisation + parsing + domain-pinning sweep (mostly NEGATIVE results, documented).
import { jcs as jcsW } from '../verifier/src/canon.mjs';
import { jcs as jcsP, verifyProfile } from '../conformance/src/profiles.mjs';
import { verifySeal, signSeal, NOTARY_DOMAIN, contentId } from '../verifier/src/witness-core.mjs';
import { ml_dsa65, issuer, keyFromByte, b64, utf8, verdict } from './_common.mjs';

const same = (a, b) => jcsW(a) === jcsW(b);
console.log('-- JCS (expected: deterministic, injective on the JSON value space) --');
console.log('  -0 vs 0 canon equal:', same(-0, 0), '(RFC 8785: both "0" — same as signer, fine)');
console.log('  1e21 →', jcsW(1e21), '| 1E400 parse →', (() => { try { return jcsW(JSON.parse('1E400')); } catch (e) { return 'THROWS ' + e.message; } })());
console.log('  0.1+0.2 →', jcsW(0.1 + 0.2), '| 2**53+1 →', jcsW(JSON.parse('9007199254740993')), '(precision loss is shared by signer & verifier)');
console.log('  NFC vs NFD "café" equal:', same('café', 'café'), '(no normalisation → distinct hashes: fail-closed)');
console.log('  lone surrogate →', jcsW('\ud800'), '| key order UTF-16:', jcsW({ '\u{1F600}': 1, '￿': 2 }));
const dup = JSON.parse('{"amount":"1","amount":"999"}');
console.log('  duplicate keys: JSON.parse keeps last →', jcsW(dup), '(parser-differential with first-wins tools; see report)');
const proto = JSON.parse('{"__proto__":{"isAdmin":true},"a":1}');
console.log('  __proto__ own key kept in canon:', jcsW(proto), '| Object.prototype polluted:', ({}).isAdmin === true);
const { a, ...rest } = proto; console.log('  rest-spread keeps own __proto__:', Object.keys(rest));
try { jcsW(JSON.parse('['.repeat(5000) + ']'.repeat(5000))); } catch (e) { console.log('  deep (5000) witness-core jcs →', e.message.slice(0, 50)); }
const deep = JSON.parse('['.repeat(200000) + ']'.repeat(200000));
const vp = verifyProfile('a2a-receipt-ml-dsa-65', { receipt: { schema: 'a2a.signed-receipt/0.1', content_id: 'x', x: deep, signature: { alg: 'ML-DSA-65', sig: b64(new Uint8Array(3309)), signer_public_key: b64(issuer.publicKey) } } }, { trustedKeys: [b64(issuer.publicKey)] });
console.log('  deep (200000) profiles jcs → valid:', vp.valid, '|', vp.reason.slice(0, 60));

console.log('-- domain pinning --');
// x402-served profile accepts ANY domain string; only route 'x402-attest-decision' is reserved.
const sm = `SOME-OTHER-PROTOCOL-v9\nverify-agent\n${'00'.repeat(32)}`;
const e = { domain: 'SOME-OTHER-PROTOCOL-v9', route_id: 'verify-agent', digest: '00'.repeat(32), signed_message: sm, signature: b64(ml_dsa65.sign(utf8(sm), issuer.secretKey)), public_key: b64(issuer.publicKey) };
let vuln = verdict(verifyProfile('x402-served', e, { trustedKeys: [b64(issuer.publicKey)] }).valid, 'x402-served profile: trusted-key signature under a NON-FractalAI domain is accepted as an x402 served-proof');
const e2 = { ...e, domain: 'FRACTALAI-x402-served-v1', route_id: 'x', digest: 'not-hex\u0000', signed_message: 'FRACTALAI-x402-served-v1\nx\nnot-hex\u0000' };
e2.signature = b64(ml_dsa65.sign(utf8(e2.signed_message), issuer.secretKey));
vuln = verdict(verifyProfile('x402-served', e2, { trustedKeys: [b64(issuer.publicKey)] }).valid, 'x402-served profile: digest not validated as 64-hex (accepts arbitrary bytes)') || vuln;

console.log('-- verifySeal without a key pin --');
const atk = keyFromByte(66);
const fake = signSeal({ schema: 'fractalai.x402-settlement-seal/0.1', amount: '999999999', payer: '0xVictim' }, { domain: NOTARY_DOMAIN, secretKey: atk.secretKey, publicKey: atk.publicKey });
const s = verifySeal(fake);
vuln = verdict(s.valid === true, `attacker-key seal claiming mode="${s.mode}" with NO pin → valid=${s.valid} keyTrusted=${s.keyTrusted} (documented as integrity-only, but the field is named "valid")`) || vuln;
process.exit(vuln ? 1 : 0);
