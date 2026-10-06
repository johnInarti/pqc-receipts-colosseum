#!/usr/bin/env node
/**
 * cctp-bridge-base-to-arc.mjs — Base (CCTP domain 6) → Arc mainnet (CCTP domain 26) USDC bridge via CCTP v2 +
 * Circle Forwarding Service, with ethers v6.
 *
 * Why the Forwarding Service: Arc pays gas in USDC and the recipient has 0 USDC on Arc, so it cannot
 * send `receiveMessage` itself. With the `cctp-forward` hook Circle broadcasts the mint on Arc and
 * deducts its fee (≈0.0156 USDC quoted live) from the minted amount. Source of truth:
 *   https://developers.circle.com/cctp/concepts/forwarding-service.md
 *   https://developers.circle.com/cctp/howtos/transfer-usdc-with-forwarding-service.md
 *   https://developers.circle.com/cctp/evm-smart-contracts  (TokenMessengerV2 / MessageTransmitterV2)
 *   https://developers.circle.com/cctp/cctp-supported-blockchains (Arc = domain 26)
 *   https://docs.arc.io/arc/references/connect-to-arc (chainId 5042, rpc.mainnet.arc.io, explorer.arc.io)
 *
 * Safety rails: refuses to run if the key does not derive the expected treasury address; moves exactly
 * AMOUNT_USDC; caps Base gas spend; static-calls before broadcasting; never prints the key.
 *
 *   TK=$(cat /outside/repo/treasury.key) node scripts/cctp-bridge-base-to-arc.mjs           # full flow (run from smart-contracts/)
 *   TK=… node scripts/cctp-bridge-base-to-arc.mjs --resume <burnTxHash>                 # only wait for attestation/forward
 */
import { ethers } from 'ethers';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';

const EXPECTED = '0xC13789e82661635d9Cea38a53A0390CF9939ef4f';
const AMOUNT_USDC = '10';                 // exactly what the founder authorised
const MAX_BASE_GAS_ETH = '0.0002';        // hard cap on Base gas for the whole flow
const MAX_FEE_UNITS = 40_000n;            // 0.04 USDC: forwardFee(high)=15,824 + fast fee 0.325 bps ≈ 325 + margin
const MIN_FINALITY = 1000;                // Fast Transfer from Base (standard would wait ~15 min for L1 finality)

const BASE_RPC = 'https://mainnet.base.org';
const ARC_RPC = 'https://rpc.mainnet.arc.io';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const TOKEN_MESSENGER_V2 = '0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d'; // same address on Base and Arc
const ARC_DOMAIN = 26; const BASE_DOMAIN = 6;
const FORWARD_HOOK = '0x636374702d666f72776172640000000000000000000000000000000000000000'; // "cctp-forward" | v0 | len 0
const IRIS = 'https://iris-api.circle.com';
const STATE = process.env.BRIDGE_STATE || new URL('../deployments/cctp-bridge-base-to-arc.state.json', import.meta.url).pathname;

const ERC20 = ['function balanceOf(address) view returns (uint256)', 'function allowance(address,address) view returns (uint256)', 'function approve(address,uint256) returns (bool)'];
const TM_ABI = ['function depositForBurnWithHook(uint256 amount, uint32 destinationDomain, bytes32 mintRecipient, address burnToken, bytes32 destinationCaller, uint256 maxFee, uint32 minFinalityThreshold, bytes hookData)'];

const log = (...a) => console.log(new Date().toISOString(), ...a);
const saveState = (s) => writeFileSync(STATE, JSON.stringify(s, null, 2) + '\n');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const key = (process.env.TK || '').trim();
  if (!key) throw new Error('TK env missing');
  const base = new ethers.JsonRpcProvider(BASE_RPC, 8453, { staticNetwork: true });
  const arc = new ethers.JsonRpcProvider(ARC_RPC, 5042, { staticNetwork: true });
  const wallet = new ethers.Wallet(key.startsWith('0x') ? key : '0x' + key, base);
  if (wallet.address.toLowerCase() !== EXPECTED.toLowerCase()) throw new Error(`ABORT: key derives ${wallet.address}, expected ${EXPECTED}`);
  log('signer', wallet.address);

  const state = existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : {};
  const resumeIdx = process.argv.indexOf('--resume');
  let burnTx = resumeIdx >= 0 ? process.argv[resumeIdx + 1] : state.burnTxHash;

  const arcBefore = await arc.getBalance(wallet.address);
  log('Arc native USDC before:', ethers.formatEther(arcBefore));

  if (!burnTx) {
    const usdc = new ethers.Contract(BASE_USDC, ERC20, wallet);
    const tm = new ethers.Contract(TOKEN_MESSENGER_V2, TM_ABI, wallet);
    const amount = ethers.parseUnits(AMOUNT_USDC, 6);
    const [ethBal, usdcBal, fee] = await Promise.all([base.getBalance(wallet.address), usdc.balanceOf(wallet.address), base.getFeeData()]);
    log('Base ETH', ethers.formatEther(ethBal), 'USDC', ethers.formatUnits(usdcBal, 6), 'maxFeePerGas gwei', ethers.formatUnits(fee.maxFeePerGas, 'gwei'));
    if (usdcBal < amount) throw new Error('ABORT: insufficient USDC on Base');

    // Live fee quote (forwarding) — refuse if our MAX_FEE_UNITS would not cover it.
    const quote = await (await fetch(`${IRIS}/v2/burn/USDC/fees/${BASE_DOMAIN}/${ARC_DOMAIN}?forward=true`)).json();
    const q = quote.find((x) => x.finalityThreshold === MIN_FINALITY);
    if (!q) throw new Error(`ABORT: no fee quote for threshold ${MIN_FINALITY}: ${JSON.stringify(quote)}`);
    const protocolFee = (amount * BigInt(Math.round(q.minimumFee * 100))) / 1_000_000n; // bps*100 / 1e6
    const needed = BigInt(q.forwardFee.high) + protocolFee;
    log('fee quote', JSON.stringify(q), '→ needed ≤', needed.toString(), 'units; maxFee', MAX_FEE_UNITS.toString());
    if (needed > MAX_FEE_UNITS) throw new Error(`ABORT: quoted fee ${needed} > maxFee ${MAX_FEE_UNITS}`);

    // Gas cap: approve(~60k) + depositForBurnWithHook(~250k) at the live max fee must stay under the cap.
    const maxFeePerGas = fee.maxFeePerGas ?? fee.gasPrice;
    const worstGas = 60_000n + 300_000n;
    const worstEth = worstGas * maxFeePerGas;
    log('worst-case Base gas', ethers.formatEther(worstEth), 'ETH (cap', MAX_BASE_GAS_ETH, ')');
    if (worstEth > ethers.parseEther(MAX_BASE_GAS_ETH)) throw new Error('ABORT: Base gas cap exceeded');
    if (ethBal < worstEth) throw new Error('ABORT: insufficient ETH for gas');

    const mintRecipient = ethers.zeroPadValue(wallet.address, 32);
    const destinationCaller = ethers.ZeroHash;
    const burnArgs = [amount, ARC_DOMAIN, mintRecipient, BASE_USDC, destinationCaller, MAX_FEE_UNITS, MIN_FINALITY, FORWARD_HOOK];

    // 1) approve exactly the amount (idempotent).
    const allowance = await usdc.allowance(wallet.address, TOKEN_MESSENGER_V2);
    let approveHash = state.approveTxHash ?? null;
    if (allowance < amount) {
      const txa = await usdc.approve(TOKEN_MESSENGER_V2, amount, { gasLimit: 80_000n });
      log('approve tx', txa.hash); approveHash = txa.hash;
      const ra = await txa.wait(1); if (ra.status !== 1) throw new Error('approve reverted');
      log('approve mined block', ra.blockNumber, 'gasUsed', ra.gasUsed.toString());
    } else log('allowance already sufficient', ethers.formatUnits(allowance, 6));

    // 2) static-call first, then burn.
    await tm.depositForBurnWithHook.staticCall(...burnArgs);
    const gasEst = await tm.depositForBurnWithHook.estimateGas(...burnArgs);
    log('depositForBurnWithHook estimateGas', gasEst.toString());
    const txb = await tm.depositForBurnWithHook(...burnArgs, { gasLimit: (gasEst * 13n) / 10n });
    log('burn tx', txb.hash);
    burnTx = txb.hash;
    saveState({ ...state, approveTxHash: approveHash, burnTxHash: burnTx, amount: AMOUNT_USDC, maxFee: MAX_FEE_UNITS.toString(), minFinality: MIN_FINALITY, startedAt: new Date().toISOString() });
    const rb = await txb.wait(1); if (rb.status !== 1) throw new Error('burn reverted');
    const gasEth = rb.gasUsed * rb.gasPrice;
    log('burn mined block', rb.blockNumber, 'gasUsed', rb.gasUsed.toString(), 'cost ETH', ethers.formatEther(gasEth));
    saveState({ ...JSON.parse(readFileSync(STATE, 'utf8')), burnBlock: rb.blockNumber, burnGasEth: ethers.formatEther(gasEth) });
  } else log('resuming burn', burnTx);

  // 3) Poll Iris for attestation + forwarding (Circle submits receiveMessage on Arc).
  const url = `${IRIS}/v2/messages/${BASE_DOMAIN}?transactionHash=${burnTx}`;
  log('polling', url);
  const deadline = Date.now() + 45 * 60_000;
  let msg = null;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(20_000) });
      if (res.status === 404) { log('iris 404 (not indexed yet)'); }
      else {
        const j = await res.json();
        msg = j?.messages?.[0] ?? null;
        if (msg) {
          const { status, forwardTxHash, delayReason, eventNonce } = msg;
          log('iris status', status, 'nonce', eventNonce, 'forwardTxHash', forwardTxHash ?? '-', delayReason ? `delay: ${delayReason}` : '');
          if (status === 'complete' && forwardTxHash) break;
        }
      }
    } catch (e) { log('poll error', e.message); }
    await sleep(10_000);
  }
  const cur = JSON.parse(readFileSync(STATE, 'utf8'));
  saveState({ ...cur, attestationStatus: msg?.status ?? null, attestation: msg?.attestation ?? null, message: msg?.message ?? null, eventNonce: msg?.eventNonce ?? null, forwardTxHash: msg?.forwardTxHash ?? null, decodedMessage: msg?.decodedMessage ?? null });
  if (!msg || msg.status !== 'complete') throw new Error(`attestation not complete within budget (status=${msg?.status})`);
  if (!msg.forwardTxHash) throw new Error('attestation complete but no forwardTxHash — forwarding not performed; recipient has no USDC on Arc to call receiveMessage itself');

  // 4) Confirm the Arc mint.
  let rc = null;
  for (let i = 0; i < 30 && !rc; i++) { rc = await arc.getTransactionReceipt(msg.forwardTxHash); if (!rc) await sleep(3000); }
  if (!rc) throw new Error(`forward tx ${msg.forwardTxHash} not found on Arc`);
  log('Arc mint tx', msg.forwardTxHash, 'status', rc.status, 'block', rc.blockNumber);
  const arcAfter = await arc.getBalance(wallet.address);
  log('Arc native USDC after:', ethers.formatEther(arcAfter), '(delta', ethers.formatEther(arcAfter - arcBefore), ')');
  saveState({ ...JSON.parse(readFileSync(STATE, 'utf8')), arcMintBlock: rc.blockNumber, arcBalanceAfter: ethers.formatEther(arcAfter), finishedAt: new Date().toISOString() });
}

main().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
