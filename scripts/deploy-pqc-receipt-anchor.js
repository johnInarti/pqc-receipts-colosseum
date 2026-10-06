/**
 * Deploy PQCReceiptAnchor (ownerless, fundless, write-once receipt anchor) and record the result in
 * deployments/PQCReceiptAnchor-<chainId>.json.
 *
 *   npx hardhat run scripts/deploy-pqc-receipt-anchor.js --network arbitrumSepolia
 *   npx hardhat run scripts/deploy-pqc-receipt-anchor.js --network arbitrumOne
 *
 * Signer: PRIVATE_KEY from the environment (hardhat.config.js). For a testnet deploy use a
 * throwaway wallet; e.g. `PRIVATE_KEY=$(cat /path/outside/repo/deployer.key) npx hardhat run …`.
 * The key is never written anywhere by this script — only the deployer ADDRESS is recorded.
 */
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

const EXPLORERS = {
  421614: "https://sepolia.arbiscan.io",
  42161: "https://arbiscan.io",
  8453: "https://basescan.org",
  84532: "https://sepolia.basescan.org",
  5042: "https://explorer.arc.io",
  5042002: "https://explorer.testnet.arc.io",
  31337: null,
};
// Native gas token symbol per chain (Arc pays gas in USDC, 18 decimals natively).
const NATIVE = { 5042: "USDC", 5042002: "USDC" };
// Arc: refuse to deploy if the estimated max cost exceeds this many USDC (founder's budget).
const ARC_MAX_DEPLOY_USDC = process.env.ARC_MAX_DEPLOY_USDC || "2";

async function main() {
  const { ethers, network } = hre;
  const [deployer] = await ethers.getSigners();
  const net = await ethers.provider.getNetwork();
  const chainId = Number(net.chainId);
  const balance = await ethers.provider.getBalance(deployer.address);
  const sym = NATIVE[chainId] || "ETH";

  console.log(`network: ${network.name} (chainId ${chainId})`);
  console.log(`deployer: ${deployer.address}`);
  console.log(`balance: ${ethers.formatEther(balance)} ${sym}`);

  const Factory = await ethers.getContractFactory("PQCReceiptAnchor");
  // Estimate first so a dry run on an unfunded wallet fails loudly BEFORE broadcasting anything.
  const deployTx = await Factory.getDeployTransaction();
  const gas = await ethers.provider.estimateGas({ ...deployTx, from: deployer.address });
  const fee = await ethers.provider.getFeeData();
  const maxCost = gas * (fee.maxFeePerGas ?? fee.gasPrice ?? 0n);
  console.log(`estimated deploy gas: ${gas} (max cost ≈ ${ethers.formatEther(maxCost)} ${sym}; maxFeePerGas ${ethers.formatUnits(fee.maxFeePerGas ?? fee.gasPrice ?? 0n, "gwei")} gwei)`);
  if (balance < maxCost) {
    throw new Error(`insufficient funds: need ≈ ${ethers.formatEther(maxCost)} ${sym}, have ${ethers.formatEther(balance)} ${sym} on chainId ${chainId}`);
  }
  if (sym === "USDC" && maxCost > ethers.parseEther(ARC_MAX_DEPLOY_USDC)) {
    throw new Error(`refusing: estimated max cost ${ethers.formatEther(maxCost)} USDC > budget ${ARC_MAX_DEPLOY_USDC} USDC`);
  }
  if (process.env.DRY_RUN) { console.log("DRY_RUN set — not broadcasting."); return; }

  const contract = await Factory.deploy();
  const tx = contract.deploymentTransaction();
  console.log(`deploy tx: ${tx.hash}`);
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  const receipt = await tx.wait();
  console.log(`PQCReceiptAnchor deployed at ${address} (block ${receipt.blockNumber})`);

  // Post-deploy sanity: the contract answers and starts empty.
  const total = await contract.totalAnchored();
  if (total !== 0n) throw new Error(`unexpected totalAnchored=${total} right after deploy`);

  const artifact = await hre.artifacts.readArtifact("PQCReceiptAnchor");
  const out = {
    contract: "PQCReceiptAnchor",
    address,
    chainId,
    network: network.name,
    deployer: deployer.address,
    txHash: tx.hash,
    blockNumber: receipt.blockNumber,
    deployedAt: new Date().toISOString(),
    explorer: EXPLORERS[chainId] ? `${EXPLORERS[chainId]}/address/${address}` : null,
    gasUsed: receipt.gasUsed.toString(),
    effectiveGasPrice: (receipt.gasPrice ?? receipt.effectiveGasPrice ?? 0n).toString(),
    deployCostNative: ethers.formatEther(receipt.gasUsed * (receipt.gasPrice ?? receipt.effectiveGasPrice ?? 0n)) + ` ${sym}`,
    compiler: { solc: "0.8.24", optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: "cancun" },
    abi: artifact.abi,
  };
  const dir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `PQCReceiptAnchor-${chainId}.json`);
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + "\n");
  console.log(`wrote ${file}`);
  if (out.explorer) console.log(`explorer: ${out.explorer}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
