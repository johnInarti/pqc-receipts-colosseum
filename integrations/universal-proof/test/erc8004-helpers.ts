/**
 * Local chain harness for the ERC-8004 adapter: starts `anvil`, deploys the OFFICIAL Identity and Validation
 * registries (fixtures/erc8004/official-artifacts.json, compiled from erc-8004/erc-8004-contracts) behind ERC1967
 * proxies exactly as the official test suite does (HardhatMinimalUUPS → upgradeToAndCall). Anvil's default dev
 * accounts are public test keys (no real funds, local chain only).
 */
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createPublicClient, createWalletClient, http, encodeFunctionData, decodeEventLog } from 'viem';
import type { Address, Hex, PublicClient, WalletClient, Abi } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';

const ART = JSON.parse(readFileSync(new URL('../fixtures/erc8004/official-artifacts.json', import.meta.url), 'utf8'));
export const abiOf = (n: string): Abi => ART.contracts[n].abi;
const bytecodeOf = (n: string): Hex => ART.contracts[n].bytecode;

// anvil's well-known public dev keys (accounts 0..2)
export const DEV_KEYS: Hex[] = [
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
];

export interface Chain { anvil: ChildProcess; url: string; pub: PublicClient; wallets: WalletClient[]; identity: Address; validation: Address; stop: () => void }

async function waitRpc(url: string) {
  for (let i = 0; i < 100; i++) {
    try { const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }) }); if (r.ok) return; } catch { /* not up yet */ }
    await new Promise((res) => setTimeout(res, 100));
  }
  throw new Error('anvil did not start');
}

export async function startChain(port: number): Promise<Chain> {
  const anvil = spawn('anvil', ['--port', String(port), '--silent'], { stdio: 'ignore' });
  const url = `http://127.0.0.1:${port}`;
  await waitRpc(url);
  const pub = createPublicClient({ chain: foundry, transport: http(url) }) as PublicClient;
  const wallets = DEV_KEYS.map((k) => createWalletClient({ account: privateKeyToAccount(k), chain: foundry, transport: http(url) }));
  const [deployer] = wallets;
  const deploy = async (name: string, args: unknown[] = []) => {
    const hash = await deployer.deployContract({ abi: abiOf(name), bytecode: bytecodeOf(name), args, account: deployer.account!, chain: foundry });
    const rc = await pub.waitForTransactionReceipt({ hash });
    return rc.contractAddress!;
  };
  const send = async (to: Address, data: Hex, w = deployer) => {
    const hash = await w.sendTransaction({ to, data, account: w.account!, chain: foundry });
    const rc = await pub.waitForTransactionReceipt({ hash });
    if (rc.status !== 'success') throw new Error(`tx to ${to} reverted`);
    return rc;
  };
  const minimalInit = (addr: Address) => encodeFunctionData({ abi: abiOf('HardhatMinimalUUPS'), functionName: 'initialize', args: [addr] });
  const proxyFor = async (realName: string, initData: Hex, minimalArg: Address) => {
    const minimal = await deploy('HardhatMinimalUUPS');
    const proxy = await deploy('ERC1967Proxy', [minimal, minimalInit(minimalArg)]);
    const real = await deploy(realName);
    await send(proxy, encodeFunctionData({ abi: abiOf('HardhatMinimalUUPS'), functionName: 'upgradeToAndCall', args: [real, initData] }));
    return proxy;
  };
  const ZERO = '0x0000000000000000000000000000000000000000' as Address;
  const identity = await proxyFor('IdentityRegistryUpgradeable', encodeFunctionData({ abi: abiOf('IdentityRegistryUpgradeable'), functionName: 'initialize', args: [] }), ZERO);
  const validation = await proxyFor('ValidationRegistryUpgradeable', encodeFunctionData({ abi: abiOf('ValidationRegistryUpgradeable'), functionName: 'initialize', args: [identity] }), identity);
  return { anvil, url, pub, wallets, identity, validation, stop: () => anvil.kill('SIGTERM') };
}

/** Register an agent in the official IdentityRegistry; returns its agentId (from the Registered event). */
export async function registerAgent(c: Chain, w: WalletClient, tokenURI: string): Promise<bigint> {
  const hash = await w.writeContract({ address: c.identity, abi: abiOf('IdentityRegistryUpgradeable'), functionName: 'register', args: [tokenURI], account: w.account!, chain: foundry });
  const rc = await c.pub.waitForTransactionReceipt({ hash });
  for (const log of rc.logs) {
    try {
      const ev = decodeEventLog({ abi: abiOf('IdentityRegistryUpgradeable'), data: log.data, topics: log.topics });
      if (ev.eventName === 'Registered') return (ev.args as unknown as { agentId: bigint }).agentId;
    } catch { /* other event */ }
  }
  throw new Error('Registered event not found');
}

export const dataUri = (bytes: Uint8Array, mediaType = 'application/json') => `data:${mediaType};base64,${Buffer.from(bytes).toString('base64')}`;
export const fromDataUri = (uri: string): Uint8Array => Uint8Array.from(Buffer.from(uri.slice(uri.indexOf(',') + 1), 'base64'));
