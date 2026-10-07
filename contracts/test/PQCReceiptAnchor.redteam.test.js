const { expect } = require("chai");
const { ethers, network } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const crypto = require("crypto");
const path = require("path");

/**
 * RED-TEAM (2026-10-06) — PQCReceiptAnchor v1 (deployed, immutable) vs the proposed V2, plus an END-TO-END check of
 * the offline verifier against a real in-process EVM (Hardhat network; nothing leaves this process).
 *
 *   VERIFIER_DIR       path to verifier/src (default: ../../verifier/src relative to this file)
 *   ORIG_VERIFIER_DIR  optional path to the PRE-PATCH verifier/src, to show the attacks it accepted
 */
const VERIFIER_DIR = process.env.VERIFIER_DIR || path.join(__dirname, "..", "..", "verifier", "src");
const ORIG_VERIFIER_DIR = process.env.ORIG_VERIFIER_DIR;
const sha256 = (s) => "0x" + crypto.createHash("sha256").update(s).digest("hex");
const KID = "0x86c139c960bb274c" + "0".repeat(48);

// JSON-RPC bridge: lets the verifier (which only speaks fetch/JSON-RPC) talk to the in-process Hardhat node.
const bridge = async (_url, init) => {
  const { method, params } = JSON.parse(init.body);
  try {
    const result = await network.provider.request({ method, params });
    return { ok: true, json: async () => ({ jsonrpc: "2.0", id: 1, result }) };
  } catch (e) {
    return { ok: true, json: async () => ({ jsonrpc: "2.0", id: 1, error: { message: e.message } }) };
  }
};

describe("PQCReceiptAnchor — red-team", function () {
  let v1, v2, fake, issuer, attacker;

  beforeEach(async function () {
    [issuer, attacker] = await ethers.getSigners();
    v1 = await (await ethers.getContractFactory("PQCReceiptAnchor")).deploy();
    v2 = await (await ethers.getContractFactory("PQCReceiptAnchorV2")).deploy();
    fake = await (await ethers.getContractFactory("LookalikeAnchor")).deploy();
  });

  describe("v1 (deployed): squatting / griefing", function () {
    it("RT-E3 PoC: attacker anchors a public receiptId FIRST with a garbage payloadHash → the genuine anchor is impossible forever", async function () {
      const rid = sha256("public-receipt-signature");
      const now = BigInt(await time.latest());
      await v1.connect(attacker).anchor(rid, sha256("garbage"), KID, 1n);
      await expect(v1.connect(issuer).anchor(rid, sha256("genuine-signed-bytes"), KID, now))
        .to.be.revertedWithCustomError(v1, "AlreadyAnchored");
      const rec = await v1.getAnchor(rid);
      expect(rec.anchoredBy).to.equal(attacker.address);
      expect(rec.payloadHash).to.equal(sha256("garbage"));
    });

    it("RT-E11 PoC: one squatted id makes the issuer's WHOLE anchorBatch revert (all-or-nothing griefing)", async function () {
      const now = BigInt(await time.latest());
      const ids = [...Array(20)].map((_, i) => sha256(`sig-${i}`));
      await v1.connect(attacker).anchor(ids[13], sha256("x"), KID, 1n);
      await expect(v1.connect(issuer).anchorBatch(ids, ids.map((i) => sha256(i)), ids.map(() => KID), ids.map(() => now)))
        .to.be.revertedWithCustomError(v1, "AlreadyAnchored").withArgs(ids[13]);
      expect(await v1.totalAnchored()).to.equal(1n);
    });

    it("observedAt: future beyond 15 min reverts, but ANY past value (even 0) is accepted — it is only a claim", async function () {
      const now = BigInt(await time.latest());
      await expect(v1.anchor(sha256("a"), sha256("p"), KID, now + 3600n)).to.be.revertedWithCustomError(v1, "ObservedAtInFuture");
      await v1.anchor(sha256("b"), sha256("p"), KID, 0n);
      expect((await v1.getAnchor(sha256("b"))).observedAt).to.equal(0n);
    });

    it("no value path, no external call: payable send reverts; gas is linear (~94k/entry): a 100-entry batch stays under the 2^24 per-tx gas cap (EIP-7825)", async function () {
      await expect(issuer.sendTransaction({ to: await v1.getAddress(), value: 1n })).to.be.reverted;
      await expect(v1.anchor(sha256("c"), sha256("p"), KID, 0n, { value: 1n })).to.be.reverted;
      const now = BigInt(await time.latest());
      const ids = [...Array(100)].map((_, i) => sha256(`big-${i}`));
      const tx = await v1.anchorBatch(ids, ids.map((i) => sha256(i)), ids.map(() => KID), ids.map(() => now));
      const r = await tx.wait();
      expect(r.gasUsed).to.be.lessThan(16_777_216n);
      console.log(`      gas: 100-entry anchorBatch = ${r.gasUsed} (${r.gasUsed / 100n}/entry)`);
    });
  });

  describe("V2 proposal: namespaced by anchorer", function () {
    it("squatting is impossible: the attacker writes into HIS namespace; the issuer's slot stays free", async function () {
      const rid = sha256("public-receipt-signature");
      const now = BigInt(await time.latest());
      await v2.connect(attacker).anchor(rid, sha256("garbage"), KID, 1n);
      await v2.connect(issuer).anchor(rid, sha256("genuine"), KID, now);
      expect((await v2.getAnchor(issuer.address, rid)).payloadHash).to.equal(sha256("genuine"));
      expect((await v2.getAnchor(attacker.address, rid)).payloadHash).to.equal(sha256("garbage"));
      await expect(v2.connect(issuer).anchor(rid, sha256("other"), KID, now))
        .to.be.revertedWithCustomError(v2, "AlreadyAnchored").withArgs(issuer.address, rid);
    });

    it("batch is idempotent within the caller's namespace and immune to foreign squats", async function () {
      const now = BigInt(await time.latest());
      const ids = [...Array(5)].map((_, i) => sha256(`s-${i}`));
      await v2.connect(attacker).anchor(ids[2], sha256("x"), KID, 1n);
      await v2.connect(issuer).anchor(ids[0], sha256(ids[0]), KID, now);
      const args = [ids, ids.map((i) => sha256(i)), ids.map(() => KID), ids.map(() => now)];
      expect(await v2.connect(issuer).anchorBatch.staticCall(...args)).to.equal(4n);
      await v2.connect(issuer).anchorBatch(...args);
      for (const id of ids) expect(await v2.isAnchored(issuer.address, id)).to.equal(true);
      await expect(v2.connect(issuer).anchorBatch([], [], [], [])).to.be.revertedWithCustomError(v2, "EmptyBatch");
      await expect(v2.connect(issuer).anchorBatch(ids, ids, ids, [now])).to.be.revertedWithCustomError(v2, "LengthMismatch");
    });

    it("event is filterable by (receiptId, anchoredBy) topics", async function () {
      const rid = sha256("r");
      await v2.connect(issuer).anchor(rid, sha256("p"), KID, 0n);
      const logs = await v2.queryFilter(v2.filters.ReceiptAnchored(rid, issuer.address));
      expect(logs.length).to.equal(1);
      expect(await v2.queryFilter(v2.filters.ReceiptAnchored(rid, attacker.address))).to.have.length(0);
    });
  });

  describe("END-TO-END: offline verifier against a live (in-process) EVM", function () {
    async function makeSeal(sealedAtSec) {
      const { generateKeypair } = await import(path.join(VERIFIER_DIR, "self-attest.mjs"));
      const { signSeal, NOTARY_DOMAIN } = await import(path.join(VERIFIER_DIR, "witness-core.mjs"));
      const kp = generateKeypair();
      const body = { schema: "fractalai.x402-settlement-seal/0.1", amount: "20000", sealed_at: new Date(Number(sealedAtSec) * 1000).toISOString() };
      const seal = signSeal(body, { domain: NOTARY_DOMAIN, secretKey: kp.secretKey, publicKey: kp.publicKey });
      return { seal, pk: Buffer.from(kp.publicKey).toString("base64") };
    }

    it("genuine anchor on the real bytecode → VALID (code hash matches the mainnet deployments)", async function () {
      const { verifyAnchoredSeal, deriveAnchorIds } = await import(path.join(VERIFIER_DIR, "verify-anchor.mjs"));
      const now = BigInt(await time.latest());
      const { seal, pk } = await makeSeal(now);
      const ids = deriveAnchorIds(seal);
      const tx = await v1.connect(issuer).anchor(ids.receipt_id, ids.payload_hash, ids.kid, now);
      await tx.wait();
      const anchor = { chain_id: 31337, contract: await v1.getAddress(), tx_hash: tx.hash };
      const r = await verifyAnchoredSeal({ ...seal, anchor }, { trustedPublicKeysB64: [pk], rpcUrl: "hardhat", fetchImpl: bridge, expectedAnchoredBy: issuer.address });
      expect(r.valid, r.reason).to.equal(true);
      expect(r.codehash_ok).to.equal(true);
      expect(r.network_class).to.equal("test");
    });

    it("RT-E2 PoC: look-alike contract emits a BACK-DATED anchor (2023) → pre-patch verifier says VALID, patched refuses", async function () {
      const now = BigInt(await time.latest());
      const { seal, pk } = await makeSeal(now);
      const { verifyAnchoredSeal, deriveAnchorIds } = await import(path.join(VERIFIER_DIR, "verify-anchor.mjs"));
      const ids = deriveAnchorIds(seal);
      const backdated = 1690000000n; // 2023-07-22
      const tx = await fake.forge(ids.receipt_id, ids.payload_hash, ids.kid, backdated, issuer.address, backdated);
      await tx.wait();
      // The seal carries the address — so the ATTACKER chooses it.
      const anchor = { chain_id: 31337, contract: await fake.getAddress(), tx_hash: tx.hash };
      if (ORIG_VERIFIER_DIR) {
        const orig = await import(path.join(ORIG_VERIFIER_DIR, "verify-anchor.mjs"));
        const o = await orig.verifyAnchoredSeal({ ...seal, anchor }, { trustedPublicKeysB64: [pk], rpcUrl: "hardhat", fetchImpl: bridge, expectedAnchoredBy: issuer.address });
        expect(o.valid, o.reason).to.equal(true);            // ← the bug
        expect(o.anchored_at).to.equal(Number(backdated));    // ← forged time reported as proven
      }
      const r = await verifyAnchoredSeal({ ...seal, anchor }, { trustedPublicKeysB64: [pk], rpcUrl: "hardhat", fetchImpl: bridge, expectedAnchoredBy: issuer.address, observedAtToleranceSec: 1e12 });
      expect(r.valid).to.equal(false);
      expect(r.reason).to.match(/is not PQCReceiptAnchor/);
    });

    it("RT-E3 PoC end-to-end: squatted receiptId → patched verifier names the squatter", async function () {
      const now = BigInt(await time.latest());
      const { seal, pk } = await makeSeal(now);
      const { verifyAnchoredSeal, deriveAnchorIds } = await import(path.join(VERIFIER_DIR, "verify-anchor.mjs"));
      const ids = deriveAnchorIds(seal);
      await (await v1.connect(attacker).anchor(ids.receipt_id, sha256("garbage"), ids.kid, 1n)).wait();
      await expect(v1.connect(issuer).anchor(ids.receipt_id, ids.payload_hash, ids.kid, now)).to.be.revertedWithCustomError(v1, "AlreadyAnchored");
      const r = await verifyAnchoredSeal({ ...seal, anchor: { chain_id: 31337, contract: await v1.getAddress() } }, { trustedPublicKeysB64: [pk], rpcUrl: "hardhat", fetchImpl: bridge });
      expect(r.valid).to.equal(false);
      expect(r.reason.toLowerCase()).to.contain(`squatted by ${attacker.address.toLowerCase()}`);
    });

    it("RT-E5 PoC: stranger front-runs with the CORRECT bytes but a fake observedAt → pre-patch VALID, patched refuses", async function () {
      const now = BigInt(await time.latest());
      const { seal, pk } = await makeSeal(now);
      const { verifyAnchoredSeal, deriveAnchorIds } = await import(path.join(VERIFIER_DIR, "verify-anchor.mjs"));
      const ids = deriveAnchorIds(seal);
      await (await v1.connect(attacker).anchor(ids.receipt_id, ids.payload_hash, ids.kid, 1n)).wait(); // observedAt = 1970
      const anchor = { chain_id: 31337, contract: await v1.getAddress() };
      if (ORIG_VERIFIER_DIR) {
        const orig = await import(path.join(ORIG_VERIFIER_DIR, "verify-anchor.mjs"));
        const o = await orig.verifyAnchoredSeal({ ...seal, anchor }, { trustedPublicKeysB64: [pk], rpcUrl: "hardhat", fetchImpl: bridge });
        expect(o.valid, o.reason).to.equal(true);
      }
      const r = await verifyAnchoredSeal({ ...seal, anchor }, { trustedPublicKeysB64: [pk], rpcUrl: "hardhat", fetchImpl: bridge });
      expect(r.valid).to.equal(false);
      expect(r.reason).to.match(/observedAt 1 != signed time/);
    });
  });
});
