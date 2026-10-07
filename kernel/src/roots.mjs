/**
 * Baked trust roots (kernel/trust-roots.json): the pinned governance key, the pinned directory
 * checkpoint, the pinned anchor deployments (chainId → contract + runtime code hash), Solana cluster
 * genesis hashes and announced anchor signers. Anything else a caller supplies is an OVERRIDE and is
 * reported as such in the verdict (trust_basis: "override").
 */
import roots from '../trust-roots.json' with { type: 'json' };
import checkpointDirectory from '../checkpoint-directory.json' with { type: 'json' };

const deepFreeze = (o) => { if (o && typeof o === 'object') { Object.values(o).forEach(deepFreeze); Object.freeze(o); } return o; };
export const BAKED_ROOTS = deepFreeze(roots);

/** Full body of the pinned checkpoint epoch: lets the kernel check append-only (no key removed / rebound /
 * un-revoked) from the checkpoint to any later epoch. Accepted only if its root equals the pinned root. */
export const BAKED_CHECKPOINT_DIRECTORY = deepFreeze(checkpointDirectory.root === roots.directory_checkpoint.root ? checkpointDirectory : null);
