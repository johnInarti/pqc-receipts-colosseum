/**
 * Copy the OFFICIAL ERC-8004 contracts' compiled artifacts (abi + bytecode) into fixtures/erc8004/, with provenance.
 * Source: a clone of https://github.com/erc-8004/erc-8004-contracts compiled with its own settings
 * (solc 0.8.24, evm shanghai, optimizer 200, viaIR) via `npx hardhat --config hardhat.local.config.ts compile`
 * (hardhat.local.config.ts = the repo's solidity block without the network section).
 *   node scripts/copy-erc8004-artifacts.ts <path-to-clone> <commit>
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const [clone, commit] = process.argv.slice(2);
if (!clone || !commit) throw new Error('usage: copy-erc8004-artifacts.ts <clone> <commit>');
const names = ['ERC1967Proxy', 'HardhatMinimalUUPS', 'IdentityRegistryUpgradeable', 'ValidationRegistryUpgradeable'];
const out: Record<string, unknown> = {
  source: 'https://github.com/erc-8004/erc-8004-contracts', commit,
  compiler: { solc: '0.8.24', evmVersion: 'shanghai', optimizer: { enabled: true, runs: 200 }, viaIR: true },
  note: 'Unmodified official sources; compiled locally. Used only to run the ERC-8004 adapter end-to-end on a local anvil chain.',
  contracts: {},
};
for (const n of names) {
  const a = JSON.parse(readFileSync(join(clone, 'artifacts', 'contracts', `${n}.sol`, `${n}.json`), 'utf8'));
  const src = readFileSync(join(clone, 'contracts', `${n}.sol`));
  (out.contracts as Record<string, unknown>)[n] = { abi: a.abi, bytecode: a.bytecode, source_sha256: createHash('sha256').update(src).digest('hex') };
}
mkdirSync(new URL('../fixtures/erc8004/', import.meta.url), { recursive: true });
writeFileSync(new URL('../fixtures/erc8004/official-artifacts.json', import.meta.url), JSON.stringify(out) + '\n');
console.log(`copied ${names.length} artifacts from ${commit}`);
