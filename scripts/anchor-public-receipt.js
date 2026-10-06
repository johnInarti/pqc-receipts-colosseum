/**
 * anchor-public-receipt — anchor ONE public, ML-DSA-65-signed FractalAI receipt (a MIDAS signed
 * alert or a notary seal) on a deployed PQCReceiptAnchor, and write a verifier-ready fixture
 * `{ seal: { …, anchor } }` that `integrations/x402-pqc-witness/src/verify-anchor.mjs` consumes.
 *
 *   PRIVATE_KEY=$(cat /outside/repo/key) RECEIPT_ID=fe62b072… \
 *     npx hardhat run scripts/anchor-public-receipt.js --network arc
 *
 * Derivation is byte-for-byte the one in frontend/lib/x402-receipt-anchor.ts#deriveAnchorIds:
 *   receiptId   = sha256(ML-DSA-65 signature bytes)
 *   payloadHash = sha256(utf8(`${domain}\n${content_id}`))   — the exact bytes the signature covers
 *   kid         = sha256(public_key_b64)[:16] left-aligned in bytes32
 * For a MIDAS alert receipt: domain = served_domain ("FRACTALAI-x402-served-v1\nmidas-alert"),
 * content_id = receipt_id (= sha256(canonical)), so `${domain}\n${content_id}` === served_message.
 * The script re-verifies the ML-DSA-65 signature locally BEFORE spending gas.
 */
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const { createHash } = require("crypto");

const BASE_URL = process.env.FRACTALAI_BASE || "https://fractalai.net.co";
const RECEIPT_ID = process.env.RECEIPT_ID || "fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee";
const EXPLORERS = { 5042: "https://explorer.arc.io", 5042002: "https://explorer.testnet.arc.io", 421614: "https://sepolia.arbiscan.io", 42161: "https://arbiscan.io" };
const NATIVE = { 5042: "USDC", 5042002: "USDC" };
const RECEIPT_ANCHORED_TOPIC = "0x86069938b925599e2755e87e9b3242e8f6cbd24f2bc3d1ab52bc585d82646184";

const sha256hex = (d) => createHash("sha256").update(d).digest("hex");

function sealFromMidasReceipt(r) {
  if (r.algorithm !== "ml-dsa-65") throw new Error(`unsupported algorithm ${r.algorithm}`);
  if (sha256hex(Buffer.from(r.canonical, "utf8")) !== r.receipt_id) throw new Error("receipt_id != sha256(canonical)");
  const domain = r.served_domain;
  const content_id = r.receipt_id;
  if (`${domain}\n${content_id}` !== r.served_message) throw new Error("served_message != domain\\ncontent_id");
  return { algorithm: r.algorithm, domain, content_id, public_key: r.public_key, signature: r.signature, canonical: r.canonical, emitted_at: r.emitted_at };
}

function deriveAnchorIds(seal) {
  const sig = Buffer.from(seal.signature, "base64");
  if (sig.length !== 3309) throw new Error(`ML-DSA-65 signature must be 3309 bytes, got ${sig.length}`);
  const pk = Buffer.from(seal.public_key, "base64");
  if (pk.length !== 1952) throw new Error(`ML-DSA-65 public key must be 1952 bytes, got ${pk.length}`);
  const signedMessage = `${seal.domain}\n${seal.content_id}`;
  return {
    receipt_id: "0x" + sha256hex(sig),
    payload_hash: "0x" + sha256hex(Buffer.from(signedMessage, "utf8")),
    kid: "0x" + sha256hex(seal.public_key).slice(0, 16).padEnd(64, "0"),
    signed_message: signedMessage,
  };
}

async function verifyMlDsa65(seal) {
  // @noble/post-quantum lives in the witness package; resolve it from there (ESM).
  const mod = await import(path.join(__dirname, "..", "..", "integrations", "x402-pqc-witness", "node_modules", "@noble", "post-quantum", "ml-dsa.js"));
  return mod.ml_dsa65.verify(Buffer.from(seal.signature, "base64"), Buffer.from(`${seal.domain}\n${seal.content_id}`, "utf8"), Buffer.from(seal.public_key, "base64")) === true;
}

async function main() {
  const { ethers, network } = hre;
  const [signer] = await ethers.getSigners();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const sym = NATIVE[chainId] || "ETH";
  const depFile = path.join(__dirname, "..", "deployments", `PQCReceiptAnchor-${chainId}.json`);
  if (!fs.existsSync(depFile)) throw new Error(`no deployment for chainId ${chainId}: ${depFile}`);
  const dep = JSON.parse(fs.readFileSync(depFile, "utf8"));
  console.log(`network: ${network.name} (chainId ${chainId}) contract ${dep.address} signer ${signer.address}`);

  const url = `${BASE_URL}/api/midas/alerts/receipt/${RECEIPT_ID}`;
  const r = await (await fetch(url, { signal: AbortSignal.timeout(20000) })).json();
  const seal = sealFromMidasReceipt(r);
  if (!(await verifyMlDsa65(seal))) throw new Error("ML-DSA-65 signature does NOT verify — refusing to anchor");
  const dir = await (await fetch(`${BASE_URL}/.well-known/x402-receipt-keys`, { signal: AbortSignal.timeout(20000) })).json();
  const entry = (dir.keys || []).find((k) => k.public_key_b64 === seal.public_key);
  console.log(`signature verified locally; key in directory: ${entry ? `${entry.kid} (${entry.status})` : "NOT FOUND"}; directory epoch ${dir.epoch}`);

  const ids = deriveAnchorIds(seal);
  const observedAt = Number(seal.emitted_at);
  console.log(`receiptId   ${ids.receipt_id}\npayloadHash ${ids.payload_hash}\nkid         ${ids.kid}\nobservedAt  ${observedAt}`);
  if (entry && !ids.kid.startsWith("0x" + String(entry.kid).toLowerCase())) console.warn("warning: derived kid does not start with the directory kid");

  const c = await ethers.getContractAt("PQCReceiptAnchor", dep.address, signer);
  if (await c.isAnchored(ids.receipt_id)) throw new Error("already anchored on this contract (write-once)");
  const gas = await c.anchor.estimateGas(ids.receipt_id, ids.payload_hash, ids.kid, observedAt);
  const fee = await ethers.provider.getFeeData();
  const maxCost = gas * (fee.maxFeePerGas ?? fee.gasPrice ?? 0n);
  console.log(`estimated gas ${gas} (max cost ≈ ${ethers.formatEther(maxCost)} ${sym})`);
  if (sym === "USDC" && maxCost > ethers.parseEther(process.env.ARC_MAX_ANCHOR_USDC || "0.5")) throw new Error("refusing: anchor cost over budget");
  if (process.env.DRY_RUN) { console.log("DRY_RUN — not broadcasting"); return; }

  const tx = await c.anchor(ids.receipt_id, ids.payload_hash, ids.kid, observedAt);
  console.log(`anchor tx ${tx.hash}`);
  const rcpt = await tx.wait(1);
  if (rcpt.status !== 1) throw new Error("anchor tx reverted");
  const log = rcpt.logs.find((l) => l.address.toLowerCase() === dep.address.toLowerCase() && l.topics[0] === RECEIPT_ANCHORED_TOPIC && l.topics[1] === ids.receipt_id);
  if (!log) throw new Error("mined without ReceiptAnchored log");
  const block = await ethers.provider.getBlock(rcpt.blockNumber);
  const cost = rcpt.gasUsed * (rcpt.gasPrice ?? 0n);
  console.log(`anchored in block ${rcpt.blockNumber} (ts ${block.timestamp}) logIndex ${log.index} gasUsed ${rcpt.gasUsed} cost ${ethers.formatEther(cost)} ${sym}`);

  const anchor = {
    scheme: "fractalai.pqc-receipt-anchor/1", chain_id: chainId, contract: dep.address, tx_hash: tx.hash,
    log_index: log.index, block_number: rcpt.blockNumber, status: "confirmed",
    receipt_id: ids.receipt_id, payload_hash: ids.payload_hash, kid: ids.kid, observed_at: observedAt, anchored_by: signer.address,
    anchored_at: Number(block.timestamp), explorer_tx: EXPLORERS[chainId] ? `${EXPLORERS[chainId]}/tx/${tx.hash}` : null,
  };
  const out = { source_receipt_url: url, key_directory: `${BASE_URL}/.well-known/x402-receipt-keys`, seal: { ...seal, anchor } };
  const outDir = path.join(__dirname, "..", "deployments", "anchors");
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, `PQCReceiptAnchor-${chainId}-${RECEIPT_ID.slice(0, 8)}.json`);
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${outFile}`);
  // Record on the deployment file too (append-only list).
  dep.anchors = [...(dep.anchors || []), { receipt: RECEIPT_ID, ...anchor, gasUsed: rcpt.gasUsed.toString(), cost: `${ethers.formatEther(cost)} ${sym}` }];
  fs.writeFileSync(depFile, JSON.stringify(dep, null, 2) + "\n");
}

main().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
