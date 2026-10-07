/**
 * END-TO-END red-team of Trust Kernel v2 against a REAL in-process EVM (Hardhat, chainId 31337) running the
 * real PQCReceiptAnchor bytecode (runtime code hash must equal the mainnet pin 0xe4733ce5…) and the
 * LookalikeAnchor fixture. Chain 31337 is pinned through an explicit roots OVERRIDE (as any test chain must be).
 * Run from a Hardhat project that contains contracts/PQCReceiptAnchor.sol + contracts/redteam/LookalikeAnchor.sol:
 *   KERNEL_DIR=<repo>/kernel/src npx hardhat test <this file>
 */
const { expect } = require("chai");
const { ethers, network } = require("hardhat");
const path = require("path");
const KERNEL_DIR = process.env.KERNEL_DIR || path.join(__dirname, "..", "..", "kernel", "src");

const bridge = async (_url, init) => {
  const { id, method, params } = JSON.parse(init.body);
  try { const result = await network.provider.request({ method, params }); return { ok: true, status: 200, headers: { get: () => "application/json" }, text: async () => JSON.stringify({ jsonrpc: "2.0", id, result }) }; }
  catch (e) { return { ok: true, status: 200, headers: { get: () => "application/json" }, text: async () => JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32000, message: e.message } }) }; }
};

describe("Trust Kernel v2 — end-to-end on a real EVM", function () {
  let K, v1, fake, issuer, attacker, roots, kp, pk, sign;
  before(async function () {
    K = await import(path.join(KERNEL_DIR, "index.mjs"));
    const { ml_dsa65 } = await import(require.resolve("@noble/post-quantum/ml-dsa.js", { paths: [KERNEL_DIR] }));
    kp = ml_dsa65.keygen(new Uint8Array(32).fill(9));
    pk = Buffer.from(kp.publicKey).toString("base64");
    sign = (msg) => Buffer.from(ml_dsa65.sign(new TextEncoder().encode(msg), kp.secretKey)).toString("base64");
  });
  beforeEach(async function () {
    [issuer, attacker] = await ethers.getSigners();
    v1 = await (await ethers.getContractFactory("PQCReceiptAnchor")).deploy();
    fake = await (await ethers.getContractFactory("LookalikeAnchor")).deploy();
    roots = JSON.parse(JSON.stringify(K.BAKED_ROOTS));
    roots.anchors.evm["31337"] = { name: "hardhat", network_class: "test", contract: (await v1.getAddress()).toLowerCase(), runtime_codehash: K.BAKED_ROOTS.anchors.evm["42161"].runtime_codehash, from_block: 0, default_rpc: "hardhat://" };
  });
  async function makeSeal() {
    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const body = { schema: K.SEAL_SCHEMA, amount: "20000", sealed_at: new Date(now * 1000).toISOString() };
    const cid = K.sha256hex(K.jcsSigned(body));
    const domain = K.KINDS["x402-seal"].domain;
    const seal = { algorithm: "ml-dsa-65", domain, content_id: cid, public_key: pk, signature: sign(`${domain}\n${cid}`), body };
    const ids = K.anchorIds(K.parseReceipt(seal, "x402-seal"));
    return { seal, ids, t: Math.floor(Date.parse(body.sealed_at) / 1000), rid: "0x" + ids.receipt_id, ph: "0x" + ids.payload_hash, kid: "0x" + ids.kid16 + "0".repeat(48) };
  }
  const run = (seal, anchors, extra = {}) => K.verify(JSON.stringify(seal), { kind: "x402-seal", trustedKeys: JSON.stringify([pk]), roots, checkAnchors: true, anchors: JSON.stringify(anchors), rpc: { "eip155:31337": ["hardhat://"] }, fetchImpl: bridge, policy: { require: ["integrity", "authentic", "trusted", "time_anchored"], allowTestnetAnchors: true, ...extra } });

  it("genuine anchor on the REAL bytecode (code hash == mainnet pin) → time_anchored", async function () {
    const s = await makeSeal();
    const tx = await v1.connect(issuer).anchor(s.rid, s.ph, s.kid, s.t);
    await tx.wait();
    const v = await run(s.seal, [{ chain_id: 31337, tx_hash: tx.hash }]);
    expect(v.valid, JSON.stringify(v.reasons)).to.equal(true);
    expect(v.levels.time_anchored).to.equal(true);
    expect(v.anchors[0].facts.network_class).to.equal("test");
  });
  it("RT-E2 look-alike contract with a back-dated anchoredAt → refused (not the pinned contract)", async function () {
    const s = await makeSeal();
    const tx = await fake.forge(s.rid, s.ph, s.kid, 1690000000, issuer.address, 1690000000);
    await tx.wait();
    const v = await run(s.seal, [{ chain_id: 31337, contract: await fake.getAddress(), tx_hash: tx.hash }]);
    expect(v.levels.time_anchored).to.equal(false);
    expect(v.reasons.map((r) => r.code)).to.include("ANCHOR_CONTRACT_NOT_PINNED");
  });
  it("RT-E2b look-alike PINNED by a careless override → refused by the runtime code hash", async function () {
    const s = await makeSeal();
    roots.anchors.evm["31337"].contract = (await fake.getAddress()).toLowerCase();
    const tx = await fake.forge(s.rid, s.ph, s.kid, s.t, issuer.address, 1690000000);
    await tx.wait();
    const v = await run(s.seal, [{ chain_id: 31337, tx_hash: tx.hash }]);
    expect(v.reasons.map((r) => r.code)).to.include("ANCHOR_CODEHASH_MISMATCH");
  });
  it("RT-E3 squatted receiptId (garbage payloadHash) → ANCHOR_SQUATTED naming the squatter", async function () {
    const s = await makeSeal();
    await (await v1.connect(attacker).anchor(s.rid, "0x" + "ee".repeat(32), s.kid, 1)).wait();
    const v = await run(s.seal, [{ chain_id: 31337 }]);
    const r = v.reasons.find((x) => x.code === "ANCHOR_SQUATTED");
    expect(r, JSON.stringify(v.reasons)).to.not.equal(undefined);
    expect(r.detail.toLowerCase()).to.contain(attacker.address.toLowerCase());
  });
  it("RT-E5 stranger front-runs with the correct bytes but observedAt=1 → ANCHOR_OBSERVED_AT_MISMATCH", async function () {
    const s = await makeSeal();
    await (await v1.connect(attacker).anchor(s.rid, s.ph, s.kid, 1)).wait();
    const v = await run(s.seal, [{ chain_id: 31337 }]);
    expect(v.reasons.map((r) => r.code)).to.include("ANCHOR_OBSERVED_AT_MISMATCH");
  });
});
