const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const crypto = require("crypto");

/**
 * PQCReceiptAnchor — write-once, ownerless, fundless anchor for ML-DSA-65-signed x402 receipts.
 * Nothing here touches post-quantum crypto: the signature is verified OFF-chain (see
 * integrations/x402-pqc-witness/src/verify-anchor.mjs). These tests pin the on-chain contract:
 * write-once semantics, event shape, batch atomicity, zero-value rejection, no owner/no funds.
 */
describe("PQCReceiptAnchor", function () {
  let anchorC;
  let alice, bob;

  const sha256 = (s) => "0x" + crypto.createHash("sha256").update(s).digest("hex");
  // Left-aligned 8-byte key-directory kid (sha256(pubkey_b64)[:16] hex) in a bytes32.
  const kidBytes32 = (kidHex16) => "0x" + kidHex16.padEnd(64, "0");
  const KID = kidBytes32("86c139c960bb274c"); // epoch-2 FractalAI receipt key id (public info)

  function sample(i = 0) {
    return {
      receiptId: sha256(`signature-${i}`),
      payloadHash: sha256(`FRACTALAI-x402-served-v1\nx402-witness\n${sha256(`cid-${i}`).slice(2)}`),
      kid: KID,
      observedAt: 0, // filled per-test from the chain clock
    };
  }

  beforeEach(async function () {
    [alice, bob] = await ethers.getSigners();
    const F = await ethers.getContractFactory("PQCReceiptAnchor");
    anchorC = await F.deploy();
    await anchorC.waitForDeployment();
  });

  async function nowTs() {
    return BigInt(await time.latest());
  }

  // ═══════════════════════════════════════════════════════════
  //  Deployment / shape
  // ═══════════════════════════════════════════════════════════
  describe("deployment", function () {
    it("1. starts empty: totalAnchored == 0 and an unknown id is not anchored", async function () {
      expect(await anchorC.totalAnchored()).to.equal(0n);
      const s = sample();
      expect(await anchorC.anchoredAt(s.receiptId)).to.equal(0n);
      expect(await anchorC.isAnchored(s.receiptId)).to.equal(false);
      const rec = await anchorC.getAnchor(s.receiptId);
      expect(rec.payloadHash).to.equal(ethers.ZeroHash);
      expect(rec.anchoredAt).to.equal(0n);
      expect(rec.anchoredBy).to.equal(ethers.ZeroAddress);
    });

    it("2. has no owner, no admin and no upgrade surface in its ABI", async function () {
      const names = anchorC.interface.fragments.filter((f) => f.type === "function").map((f) => f.name);
      for (const forbidden of ["owner", "transferOwnership", "upgradeTo", "upgradeToAndCall", "pause", "unpause", "withdraw", "setAdmin", "grantRole"]) {
        expect(names, `must not expose ${forbidden}`).to.not.include(forbidden);
      }
      expect(names.sort()).to.deep.equal(["MAX_FUTURE_SKEW", "anchor", "anchorBatch", "anchoredAt", "getAnchor", "isAnchored", "totalAnchored"].sort());
    });

    it("3. refuses ETH: no receive/fallback, a plain value transfer reverts", async function () {
      await expect(alice.sendTransaction({ to: await anchorC.getAddress(), value: 1n })).to.be.reverted;
      expect(await ethers.provider.getBalance(await anchorC.getAddress())).to.equal(0n);
    });
  });

  // ═══════════════════════════════════════════════════════════
  //  anchor()
  // ═══════════════════════════════════════════════════════════
  describe("anchor", function () {
    it("4. anchors once and emits ReceiptAnchored(receiptId, payloadHash, kid, observedAt, msg.sender, block.timestamp)", async function () {
      const s = sample(1);
      s.observedAt = await nowTs();
      const tx = await anchorC.connect(alice).anchor(s.receiptId, s.payloadHash, s.kid, s.observedAt);
      const rcpt = await tx.wait();
      const block = await ethers.provider.getBlock(rcpt.blockNumber);
      await expect(tx)
        .to.emit(anchorC, "ReceiptAnchored")
        .withArgs(s.receiptId, s.payloadHash, s.kid, s.observedAt, alice.address, BigInt(block.timestamp));
      expect(await anchorC.anchoredAt(s.receiptId)).to.equal(BigInt(block.timestamp));
      expect(await anchorC.isAnchored(s.receiptId)).to.equal(true);
      expect(await anchorC.totalAnchored()).to.equal(1n);
    });

    it("5. stores the full record (payloadHash, kid, observedAt, anchoredAt, anchoredBy)", async function () {
      const s = sample(2);
      s.observedAt = (await nowTs()) - 30n;
      const tx = await anchorC.connect(bob).anchor(s.receiptId, s.payloadHash, s.kid, s.observedAt);
      const rcpt = await tx.wait();
      const block = await ethers.provider.getBlock(rcpt.blockNumber);
      const rec = await anchorC.getAnchor(s.receiptId);
      expect(rec.payloadHash).to.equal(s.payloadHash);
      expect(rec.kid).to.equal(s.kid);
      expect(rec.observedAt).to.equal(s.observedAt);
      expect(rec.anchoredAt).to.equal(BigInt(block.timestamp));
      expect(rec.anchoredBy).to.equal(bob.address);
    });

    it("6. is write-once: a second anchor of the same receiptId reverts with AlreadyAnchored, even with different data or sender", async function () {
      const s = sample(3);
      s.observedAt = await nowTs();
      await anchorC.connect(alice).anchor(s.receiptId, s.payloadHash, s.kid, s.observedAt);
      const other = sample(99);
      await expect(anchorC.connect(bob).anchor(s.receiptId, other.payloadHash, other.kid, s.observedAt))
        .to.be.revertedWithCustomError(anchorC, "AlreadyAnchored")
        .withArgs(s.receiptId);
      // and the original record is untouched
      const rec = await anchorC.getAnchor(s.receiptId);
      expect(rec.payloadHash).to.equal(s.payloadHash);
      expect(rec.anchoredBy).to.equal(alice.address);
      expect(await anchorC.totalAnchored()).to.equal(1n);
    });

    it("7. rejects a zero receiptId", async function () {
      const s = sample(4);
      await expect(anchorC.anchor(ethers.ZeroHash, s.payloadHash, s.kid, await nowTs()))
        .to.be.revertedWithCustomError(anchorC, "ZeroReceiptId");
    });

    it("8. rejects a zero payloadHash", async function () {
      const s = sample(5);
      await expect(anchorC.anchor(s.receiptId, ethers.ZeroHash, s.kid, await nowTs()))
        .to.be.revertedWithCustomError(anchorC, "ZeroPayloadHash");
    });

    it("9. accepts a zero kid (issuers without a key directory) — kid is informational", async function () {
      const s = sample(6);
      await expect(anchorC.anchor(s.receiptId, s.payloadHash, ethers.ZeroHash, await nowTs()))
        .to.emit(anchorC, "ReceiptAnchored");
      expect((await anchorC.getAnchor(s.receiptId)).kid).to.equal(ethers.ZeroHash);
    });

    it("10. rejects observedAt further than MAX_FUTURE_SKEW in the future, accepts exactly at the bound", async function () {
      const s = sample(7);
      const skew = await anchorC.MAX_FUTURE_SKEW();
      expect(skew).to.equal(15n * 60n);
      const t = await nowTs();
      // Hardhat auto-mines; the next block's timestamp is >= t+1, so t + skew + 1 can still be exactly at
      // the bound when mined. Use a clearly-too-far value for the revert case.
      await expect(anchorC.anchor(s.receiptId, s.payloadHash, s.kid, t + skew + 3600n))
        .to.be.revertedWithCustomError(anchorC, "ObservedAtInFuture");
      // exactly at the bound relative to the NEXT block
      await time.setNextBlockTimestamp(Number(t + 10n));
      await expect(anchorC.anchor(s.receiptId, s.payloadHash, s.kid, t + 10n + skew))
        .to.emit(anchorC, "ReceiptAnchored");
    });

    it("11. observedAt may be far in the past (old receipts can be anchored late; anchoredAt still records the chain time)", async function () {
      const s = sample(8);
      const tx = await anchorC.anchor(s.receiptId, s.payloadHash, s.kid, 1_600_000_000n);
      const rcpt = await tx.wait();
      const block = await ethers.provider.getBlock(rcpt.blockNumber);
      const rec = await anchorC.getAnchor(s.receiptId);
      expect(rec.observedAt).to.equal(1_600_000_000n);
      expect(rec.anchoredAt).to.equal(BigInt(block.timestamp));
    });

    it("12. anyone can anchor (no allow-list): two different senders anchor two different receipts", async function () {
      const a = sample(9); const b = sample(10);
      const t = await nowTs();
      await anchorC.connect(alice).anchor(a.receiptId, a.payloadHash, a.kid, t);
      await anchorC.connect(bob).anchor(b.receiptId, b.payloadHash, b.kid, t);
      expect((await anchorC.getAnchor(a.receiptId)).anchoredBy).to.equal(alice.address);
      expect((await anchorC.getAnchor(b.receiptId)).anchoredBy).to.equal(bob.address);
      expect(await anchorC.totalAnchored()).to.equal(2n);
    });

    it("13. the event is discoverable by eth_getLogs filtered on topic1 = receiptId (what the offline verifier does)", async function () {
      const s = sample(11);
      const t = await nowTs();
      const tx = await anchorC.anchor(s.receiptId, s.payloadHash, s.kid, t);
      const rcpt = await tx.wait();
      const logs = await ethers.provider.getLogs({
        address: await anchorC.getAddress(),
        topics: [anchorC.interface.getEvent("ReceiptAnchored").topicHash, s.receiptId],
        fromBlock: rcpt.blockNumber, toBlock: rcpt.blockNumber,
      });
      expect(logs.length).to.equal(1);
      expect(logs[0].topics[2]).to.equal(s.payloadHash);
      expect(logs[0].topics[3]).to.equal(s.kid);
      expect(logs[0].transactionHash).to.equal(tx.hash);
      const decoded = anchorC.interface.parseLog(logs[0]);
      expect(decoded.args.observedAt).to.equal(t);
      expect(decoded.args.anchoredBy).to.equal(alice.address);
    });
  });

  // ═══════════════════════════════════════════════════════════
  //  anchorBatch()
  // ═══════════════════════════════════════════════════════════
  describe("anchorBatch", function () {
    it("14. anchors N receipts in one tx, emitting one event each, in order", async function () {
      const items = [sample(20), sample(21), sample(22)];
      const t = await nowTs();
      const tx = await anchorC.connect(alice).anchorBatch(
        items.map((i) => i.receiptId), items.map((i) => i.payloadHash), items.map((i) => i.kid), items.map(() => t),
      );
      const rcpt = await tx.wait();
      const events = rcpt.logs.map((l) => anchorC.interface.parseLog(l)).filter((e) => e && e.name === "ReceiptAnchored");
      expect(events.length).to.equal(3);
      events.forEach((e, idx) => {
        expect(e.args.receiptId).to.equal(items[idx].receiptId);
        expect(e.args.payloadHash).to.equal(items[idx].payloadHash);
        expect(e.args.anchoredBy).to.equal(alice.address);
      });
      expect(await anchorC.totalAnchored()).to.equal(3n);
      for (const i of items) expect(await anchorC.isAnchored(i.receiptId)).to.equal(true);
    });

    it("15. is atomic: one already-anchored id reverts the WHOLE batch and nothing is written", async function () {
      const dup = sample(30);
      const t = await nowTs();
      await anchorC.anchor(dup.receiptId, dup.payloadHash, dup.kid, t);
      const fresh = [sample(31), sample(32)];
      const items = [fresh[0], dup, fresh[1]];
      await expect(anchorC.anchorBatch(
        items.map((i) => i.receiptId), items.map((i) => i.payloadHash), items.map((i) => i.kid), items.map(() => t),
      )).to.be.revertedWithCustomError(anchorC, "AlreadyAnchored").withArgs(dup.receiptId);
      expect(await anchorC.isAnchored(fresh[0].receiptId)).to.equal(false);
      expect(await anchorC.isAnchored(fresh[1].receiptId)).to.equal(false);
      expect(await anchorC.totalAnchored()).to.equal(1n);
    });

    it("16. rejects an empty batch", async function () {
      await expect(anchorC.anchorBatch([], [], [], [])).to.be.revertedWithCustomError(anchorC, "EmptyBatch");
    });

    it("17. rejects mismatched array lengths (each array checked)", async function () {
      const a = sample(40); const b = sample(41);
      const t = await nowTs();
      await expect(anchorC.anchorBatch([a.receiptId, b.receiptId], [a.payloadHash], [a.kid, b.kid], [t, t]))
        .to.be.revertedWithCustomError(anchorC, "LengthMismatch");
      await expect(anchorC.anchorBatch([a.receiptId, b.receiptId], [a.payloadHash, b.payloadHash], [a.kid], [t, t]))
        .to.be.revertedWithCustomError(anchorC, "LengthMismatch");
      await expect(anchorC.anchorBatch([a.receiptId, b.receiptId], [a.payloadHash, b.payloadHash], [a.kid, b.kid], [t]))
        .to.be.revertedWithCustomError(anchorC, "LengthMismatch");
    });

    it("18. a duplicate receiptId WITHIN the same batch reverts (second occurrence hits AlreadyAnchored)", async function () {
      const a = sample(50);
      const t = await nowTs();
      await expect(anchorC.anchorBatch([a.receiptId, a.receiptId], [a.payloadHash, a.payloadHash], [a.kid, a.kid], [t, t]))
        .to.be.revertedWithCustomError(anchorC, "AlreadyAnchored").withArgs(a.receiptId);
      expect(await anchorC.isAnchored(a.receiptId)).to.equal(false);
    });

    it("19. a zero payloadHash anywhere in the batch reverts the whole batch", async function () {
      const a = sample(60); const b = sample(61);
      const t = await nowTs();
      await expect(anchorC.anchorBatch([a.receiptId, b.receiptId], [a.payloadHash, ethers.ZeroHash], [a.kid, b.kid], [t, t]))
        .to.be.revertedWithCustomError(anchorC, "ZeroPayloadHash");
      expect(await anchorC.isAnchored(a.receiptId)).to.equal(false);
    });
  });

  // ═══════════════════════════════════════════════════════════
  //  Gas sanity (informational; keeps the per-receipt cost honest)
  // ═══════════════════════════════════════════════════════════
  describe("gas", function () {
    it("20. a single anchor costs well under 150k gas (cold storage write + event)", async function () {
      const s = sample(70);
      const tx = await anchorC.anchor(s.receiptId, s.payloadHash, s.kid, await nowTs());
      const rcpt = await tx.wait();
      expect(rcpt.gasUsed).to.be.lessThan(150_000n);
    });
  });
});
