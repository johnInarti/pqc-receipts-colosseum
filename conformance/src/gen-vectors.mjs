/**
 * Generate golden vectors — DETERMINISTIC (ML-DSA-65 with extraEntropy:false, per W3C
 * vc-di-quantum-resistant#39) so regeneration is byte-reproducible. Each profile ships THREE cases so
 * the checker proves real authenticity, not just a signature check (red-team C1):
 *   - valid   : genuine receipt, signed by the ISSUER (trusted) key.
 *   - tampered : issuer key, but the signature bytes are flipped → signature INVALID.
 *   - forged  : a self-consistent ATTACKER keypair signs its own malicious content → the signature
 *               VERIFIES over the bytes, but the key is NOT the trusted issuer → must be REJECTED.
 * The trusted issuer public key is emitted as `trusted_public_key` so the checker can pin it.
 *   node src/gen-vectors.mjs   → writes vectors/*.json
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { jcs } from './profiles.mjs';

const utf8 = (s) => new TextEncoder().encode(s);
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const b64 = (u) => Buffer.from(u).toString('base64');
const b64url = (u) => Buffer.from(u).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const DET = { extraEntropy: false }; // deterministic FIPS-204 signing (reproducible vectors)

// ISSUER (trusted) key + ATTACKER key — both deterministic from fixed seeds (vectors only).
const issuer = ml_dsa65.keygen(new Uint8Array(32).map((_, i) => (i * 5 + 1) & 0xff));
const attacker = ml_dsa65.keygen(new Uint8Array(32).map((_, i) => (i * 11 + 3) & 0xff));
const PK = b64(issuer.publicKey);
const APK = b64(attacker.publicKey);
const signI = (msg) => b64(ml_dsa65.sign(utf8(msg), issuer.secretKey, DET));
const signA = (msg) => b64(ml_dsa65.sign(utf8(msg), attacker.secretKey, DET));
const flip = (sigB64) => { const b = Buffer.from(sigB64, 'base64'); b[9] ^= 0xff; return b.toString('base64'); };

const out = new URL('../vectors/', import.meta.url);
mkdirSync(out, { recursive: true });
const write = (name, obj) => writeFileSync(new URL(name, out), JSON.stringify(obj, null, 2) + '\n');

// ── x402-served ──────────────────────────────────────────────────────────────
{
  const domain = 'FRACTALAI-x402-served-v1', route_id = 'verify-agent';
  const digest = sha256hex(JSON.stringify({ req: 'verify', agent: '0xabc' }));
  const sm = `${domain}\n${route_id}\n${digest}`;
  // forged: attacker's own served proof (a paid proof FractalAI never issued)
  const fDigest = sha256hex(JSON.stringify({ req: 'verify', agent: '0xATTACKER' }));
  const fSm = `${domain}\n${route_id}\n${fDigest}`;
  write('x402-served.json', {
    profile: 'x402-served', algorithm: 'ML-DSA-65 (FIPS-204)', trusted_public_key: PK,
    valid: { profile: 'x402-served', domain, route_id, digest, signed_message: sm, signature: signI(sm), public_key: PK },
    tampered: { profile: 'x402-served', domain, route_id, digest, signed_message: sm, signature: flip(signI(sm)), public_key: PK, _why: 'signature byte flipped → signatureValid=false' },
    forged: { profile: 'x402-served', domain, route_id, digest: fDigest, signed_message: fSm, signature: signA(fSm), public_key: APK, _why: 'ATTACKER key + own content: signature verifies but key is not the trusted issuer → valid=false' },
  });
}

// ── sar ──────────────────────────────────────────────────────────────────────
{
  const mk = (txHash) => ({ x402Version: 1, type: 'settlement-attestation-receipt', payment: { txHash, network: 'base' }, resource: { contentHash: 'sha256:' + sha256hex('response body') }, terms: { offerDigest: 'sha256:' + sha256hex('signed offer') }, deliveredAt: 1756000000 });
  const sar = mk('0x0c8785...fed5f'); const sm = `x402-sar-pqc-v1\n${sha256hex(jcs(sar))}`;
  const fSar = mk('0xFORGED_never_mined'); const fSm = `x402-sar-pqc-v1\n${sha256hex(jcs(fSar))}`;
  write('sar.json', {
    profile: 'sar', algorithm: 'ML-DSA-65 (FIPS-204)', trusted_public_key: PK,
    valid: { profile: 'sar', sar, signed_message: sm, signature: signI(sm), public_key: PK },
    tampered: { profile: 'sar', sar, signed_message: sm, signature: flip(signI(sm)), public_key: PK, _why: 'signature byte flipped → signatureValid=false' },
    forged: { profile: 'sar', sar: fSar, signed_message: fSm, signature: signA(fSm), public_key: APK, _why: 'ATTACKER key signs a settlement for a tx never mined → verifies but untrusted key → valid=false' },
  });
}

// ── acp-verdict ────────────────────────────────────────────────────────────────
{
  const mk = (outcome) => ({ agent_id: 'a1', input: 'verdict', output: `{"outcome":"${outcome}"}`, model_id: 'm', model_version: '1' });
  const dec = mk('accept'); const sm = `FRACTALAI-x402-served-v1\nx402-attest-decision\n${sha256hex(jcs(dec))}`;
  const fDec = mk('accept'); const fSm = `FRACTALAI-x402-served-v1\nx402-attest-decision\n${sha256hex(jcs(fDec))}`;
  write('acp-verdict.json', {
    profile: 'acp-verdict', algorithm: 'ML-DSA-65 (FIPS-204)', trusted_public_key: PK,
    valid: { profile: 'acp-verdict', decision: dec, signed_message: sm, signature: signI(sm), public_key: PK },
    tampered: { profile: 'acp-verdict', decision: mk('reject'), signed_message: sm, signature: signI(sm), public_key: PK, _why: 'decision outcome changed after signing → signed_message mismatch → signatureValid=false' },
    forged: { profile: 'acp-verdict', decision: fDec, signed_message: fSm, signature: signA(fSm), public_key: APK, _why: 'ATTACKER signs an authoritative "accept" nobody authorized → verifies but untrusted key → valid=false' },
  });
}

// ── jose-ml-dsa-65 (RFC 9964 JOSE / JWS compact) ────────────────────────────────
{
  const mk = (settled, kp, det) => { const header = { alg: 'ML-DSA-65', typ: 'JWT' }; const payload = { iss: 'fractalai', sub: 'agent-receipt', settled, tx: '0x0c8785...fed5f' }; const h = b64url(utf8(JSON.stringify(header))), p = b64url(utf8(JSON.stringify(payload))); const s = b64url(ml_dsa65.sign(utf8(`${h}.${p}`), kp.secretKey, DET)); return { jws: `${h}.${p}.${s}`, h, p }; };
  const good = mk(true, issuer); const forged = mk(true, attacker);
  write('jose-ml-dsa-65.json', {
    profile: 'jose-ml-dsa-65', algorithm: 'ML-DSA-65 (FIPS-204)', spec: 'RFC 9964 (JOSE)', trusted_public_key: PK,
    valid: { profile: 'jose-ml-dsa-65', jws: good.jws, public_key: PK },
    tampered: { profile: 'jose-ml-dsa-65', jws: `${good.h}.${b64url(utf8(JSON.stringify({ iss: 'fractalai', sub: 'agent-receipt', settled: false, tx: '0x0c8785...fed5f' })))}.${good.jws.split('.')[2]}`, public_key: PK, _why: 'JWS payload changed after signing → signatureValid=false' },
    forged: { profile: 'jose-ml-dsa-65', jws: forged.jws, public_key: APK, _why: 'ATTACKER key signs a JWS claiming iss:fractalai → verifies but untrusted key → valid=false' },
  });
}

// ── vc-di-ml-dsa-65 (W3C Data Integrity, mldsa65-jcs-2024) ───────────────────────
{
  const proofConfig = { type: 'DataIntegrityProof', cryptosuite: 'mldsa65-jcs-2024', created: '2026-08-24T00:00:00Z', verificationMethod: 'did:web:fractalai.example#key-1', proofPurpose: 'assertionMethod' };
  const mk = (role, kp) => { const unsecured = { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential'], issuer: 'did:web:fractalai.example', credentialSubject: { id: 'did:example:agent-1', role, pqc: 'ML-DSA-65' } }; const hashData = Buffer.concat([createHash('sha256').update(jcs(proofConfig)).digest(), createHash('sha256').update(jcs(unsecured)).digest()]); const proofValue = 'u' + b64url(ml_dsa65.sign(new Uint8Array(hashData), kp.secretKey, DET)); return { ...unsecured, proof: { ...proofConfig, proofValue } }; };
  const secured = mk('validator', issuer);
  write('vc-di-ml-dsa-65.json', {
    profile: 'vc-di-ml-dsa-65', algorithm: 'ML-DSA-65 (FIPS-204)', spec: 'W3C VC Data Integrity — mldsa65-jcs-2024', trusted_public_key: PK,
    valid: { profile: 'vc-di-ml-dsa-65', securedDocument: secured, public_key: PK },
    tampered: { profile: 'vc-di-ml-dsa-65', securedDocument: { ...secured, credentialSubject: { id: 'did:example:agent-1', role: 'admin', pqc: 'ML-DSA-65' } }, public_key: PK, _why: 'credentialSubject.role changed after signing → hashData mismatch → signatureValid=false' },
    forged: { profile: 'vc-di-ml-dsa-65', securedDocument: mk('admin', attacker), public_key: APK, _why: 'ATTACKER key mints role:admin under did:web:fractalai → verifies but untrusted key → valid=false' },
  });
}

// ── hai-ml-dsa-65 (Corrente Labs Hardware-Attested Agent Identity, PQC extension) ──
// x402-foundation/wg-identity#27 §3.1 defines `identity` = {format, hardwareQuote, publicKey,
// timestamp, nonce}. This profile is the software-only PQC path: format opts into
// "eat+cwt+ml-dsa-65" and identity.pqc carries an ML-DSA-65 signature over publicKey/timestamp/nonce
// — the same fields the TEE-attested path binds, so a verifier can trust either without the schema
// forking. hardwareQuote is untouched/irrelevant here (this profile does not check it).
{
  const mk = (nonce, kp) => {
    const core = { publicKey: '0xAgentIdentityKey000000000000000000000001', timestamp: 1787747200, nonce };
    const signed_message = `FRACTALAI-hai-pqc-v1\n${sha256hex(jcs(core))}`;
    const sig = kp === issuer ? signI(signed_message) : signA(signed_message);
    const signingPk = kp === issuer ? PK : APK;
    return { identity: { format: 'eat+cwt+ml-dsa-65', ...core, pqc: { algorithm: 'ml-dsa-65', signed_message, signature: sig, public_key: signingPk } } };
  };
  const good = mk('0xnonce0001', issuer);
  const forged = mk('0xnonce0001', attacker);
  write('hai-ml-dsa-65.json', {
    profile: 'hai-ml-dsa-65', algorithm: 'ML-DSA-65 (FIPS-204)', spec: 'x402-foundation/wg-identity#27 (Corrente Labs HAI, PQC extension)', trusted_public_key: PK,
    valid: { profile: 'hai-ml-dsa-65', identity: good.identity, public_key: PK },
    tampered: { profile: 'hai-ml-dsa-65', identity: { ...good.identity, nonce: '0xnonce0002' }, public_key: PK, _why: 'nonce changed after signing → signed_message mismatch → signatureValid=false' },
    forged: { profile: 'hai-ml-dsa-65', identity: forged.identity, public_key: APK, _why: 'ATTACKER key signs a hardware-identity claim for the same publicKey/nonce → verifies but untrusted key → valid=false' },
  });
}

// ── a2a-receipt-ml-dsa-65 (CSOAI's signed-receipts/v1 A2A extension, PQC option) ──
// a2aproject/A2A#2150 (spec+ref impl: github.com/CSOAI-ORG/a2a-signed-receipts). Their reference
// signs Ed25519 over the RFC-8785-canonical receipt object (content_id included in the signed
// bytes, itself the sha256 of the same object minus content_id/signature). Same wire shape, same
// procedure, alg swapped to ML-DSA-65 with base64 sig/key (their example uses hex; encoding is an
// implementation choice per algorithm, not part of the normative field set).
{
  const mk = (taskId, kp) => {
    const body0 = {
      schema: 'a2a.signed-receipt/0.1',
      issuer: 'did:web:fractalai.example',
      subject_card: 'https://fractalai.example/.well-known/agent-card.json',
      task_id: taskId,
      claims: [{ type: 'measurement', detail: 'x402 settlement', evidence_sha256: sha256hex('demo-evidence') }],
      register: 'Evidence of what was claimed and when by the issuer. Not a certification, endorsement, or conformity mark.',
      issued_at: '2026-09-03T00:00:00Z',
    };
    const content_id = sha256hex(jcs(body0));
    const body = { ...body0, content_id };
    const sig = kp === issuer ? signI(jcs(body)) : signA(jcs(body));
    const signingPk = kp === issuer ? PK : APK;
    return { receipt: { ...body, signature: { alg: 'ML-DSA-65', kid: 'did:web:fractalai.example#receipt-1', signer_public_key: signingPk, sig } } };
  };
  const good = mk('task-001', issuer);
  const forged = mk('task-001', attacker);
  write('a2a-receipt-ml-dsa-65.json', {
    profile: 'a2a-receipt-ml-dsa-65', algorithm: 'ML-DSA-65 (FIPS-204)', spec: 'a2aproject/A2A#2150 (CSOAI signed-receipts/v1, PQC option)', trusted_public_key: PK,
    valid: { profile: 'a2a-receipt-ml-dsa-65', receipt: good.receipt, public_key: PK },
    tampered: { profile: 'a2a-receipt-ml-dsa-65', receipt: { ...good.receipt, task_id: 'task-002' }, public_key: PK, _why: 'task_id changed after signing without recomputing content_id → content_id mismatch → signatureValid=false' },
    forged: { profile: 'a2a-receipt-ml-dsa-65', receipt: forged.receipt, public_key: APK, _why: 'ATTACKER key signs a self-consistent receipt claiming issuer did:web:fractalai.example → verifies but untrusted key → valid=false' },
  });
}

console.log('wrote deterministic vectors (valid/tampered/forged) for 7 profiles. trusted issuer pk:', PK.slice(0, 16) + '…  attacker pk:', APK.slice(0, 16) + '…');
