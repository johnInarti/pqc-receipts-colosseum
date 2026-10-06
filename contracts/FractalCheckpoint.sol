// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * FractalCheckpoint — public, append-only ACCOUNTABILITY anchor on Base (chainId 8453).
 *
 * WHAT THIS IS (honest scope, per adversarial review): FractalAI publishes here, on a chain it
 * does NOT control, an append-only, publicly-timestamped, non-repudiable sequence of the roots of
 * its own state (state / FOCI / forecast-ledger / identity / FractalPay app-level Postgres).
 * Reading ONLY Base (+ the durable DA
 * the `cid` points to), anyone can check:
 *   1. NON-EQUIVOCATION — we cannot show different roots to different observers.
 *   2. ORDER + public lower-bound TIME of every commitment.
 *   3. That the published SEQUENCE of forecast-ledger AND identity heads is CHAINED head-to-head
 *      (each epoch references the previous head), so a discontinuity is detectable + non-repudiable.
 *
 * WHAT THIS IS **NOT** (never market beyond this — doing so is verifiable fraud): NOT "trustless",
 * NOT a validity proof, and it does NOT by itself solve prover==verifier. FractalAI still controls
 * the node (the ML-DSA-65 key), the leaves (DA) and this anchor wallet, so a committed root could
 * in principle map to a chosen/falsified state. The head-to-head chaining below makes any
 * DISCONTINUITY in the published sequence detectable and permanent — it does NOT prevent the
 * operator from committing a chosen root (that regression, if it ever happens, is simply recorded
 * publicly and non-repudiably: accountability, not validity). Real trustlessness needs independent
 * re-executing validators or ZK validity proofs — this anchor is a necessary prerequisite, never a
 * substitute. Honest limits the chain does NOT close on-chain (verify off-chain against the DA):
 *   - a SKIP inside the ledger range (heads chain, but 101..102 can be omitted between two heads);
 *   - the operator going SILENT (simply stops publishing) — mitigate with an off-chain watchtower;
 *   - DA WITHHOLDING (cid points to an unavailable blob) — a verifier MUST treat "root on Base but
 *     DA not recomputable" as FAIL, never PASS. (Leaf swaps ARE detectable: the roots cover them.)
 *   - the id<->seq bound is only between CONSECUTIVE epochs (imposing global uniqueness would need
 *     an id->seq mapping's storage). A head id can reappear NON-consecutively under a larger seq;
 *     a watchtower must flag any ledgerHeadId that shows up with two different ledgerHeadSeq.
 *
 * Zero governance surface by design: no owner, no pause, no upgrade, no setAnchor. `anchor` and the
 * canonical MIDAS ML-DSA-65 `midasPubkeyHash` are immutable. Operational requirement (NOT enforced
 * on-chain, it is your deploy choice): run `anchor` as a Safe multisig with the key in KMS/HSM —
 * a bare EOA makes a single-key compromise a permanent authorized writer, and key LOSS freezes the
 * sequence forever (there is deliberately no recovery path — adding one would break zero-governance).
 */
contract FractalCheckpoint {
    struct Checkpoint {
        bytes32 stateRoot;        // the node state_root all other roots were read at (atomicity)
        bytes32 fociRoot;         // root-of-roots over ALL retained/persisted FOCI batches
        uint64  ledgerHeadSeq;    // forecast-ledger enumeration head sequence
        bytes32 ledgerHeadId;     // forecast-ledger enumeration head id
        bytes32 prevLedgerHeadId; // previous checkpoint's ledgerHeadId (ledger chaining)
        bytes32 identityRoot;     // IdentityRegistry root (labeled-domain Merkle)
        bytes32 prevIdentityRoot; // previous checkpoint's identityRoot (identity chaining)
        // (2026-09-21, Fase 2 PLAN_MAESTRO_FRACTALPAY_VACA_MORADA.md §5) extends this from
        // "the NODE's own state" to "the whole system, not just the node" — a hash-chain HEAD
        // over FractalPay's app-level Postgres event log (payments/merchants/recurring plans),
        // same chaining shape as ledgerHead above (append-only tip, not a full Merkle root —
        // matches this contract's already-declared honest scope: accountability/non-equivocation
        // over the SEQUENCE, not a membership-proof system). Computed + chained OFF this L1
        // node entirely (lib/state-event-log.ts, in the Next.js app's own Postgres) — this
        // contract and the relayer don't care WHERE a head comes from, only that it chains.
        uint64  appStateHeadSeq;     // FractalPay Postgres event-log head sequence (row count anchored so far)
        bytes32 appStateHeadId;      // FractalPay Postgres event-log head hash (the chain tip)
        bytes32 prevAppStateHeadId;  // previous checkpoint's appStateHeadId (app-state chaining)
        uint64  sealedAtHeight;   // node block height the bundle was sealed at
        uint64  timestamp;        // Base block.timestamp (public lower-bound time)
        string  cid;              // durable DA content id (Arweave) of the leaves + PQC sig + pubkey
    }

    /// The only address allowed to write. Immutable — rotation is a redeploy (or future continuity log).
    address public immutable anchor;
    /// sha3-256 of the canonical MIDAS ML-DSA-65 public key. Immutable, so the PQC signature over
    /// each bundle binds to ONE canonical key — not a per-epoch key the operator swaps at will.
    bytes32 public immutable midasPubkeyHash;

    uint64 public latestEpoch;
    mapping(uint64 => Checkpoint) public checkpoints;

    event CheckpointAnchored(
        uint64 indexed epoch,
        bytes32 stateRoot,
        bytes32 fociRoot,
        uint64  ledgerHeadSeq,
        bytes32 ledgerHeadId,
        bytes32 prevLedgerHeadId, // in the event too, so a log-only watchtower verifies the
        bytes32 identityRoot,
        bytes32 prevIdentityRoot, // chaining without an extra checkpoints(epoch) storage read
        uint64  appStateHeadSeq,
        bytes32 appStateHeadId,
        bytes32 prevAppStateHeadId,
        uint64  sealedAtHeight,
        string  cid,
        uint64  timestamp
    );

    constructor(address _anchor, bytes32 _midasPubkeyHash) {
        require(_anchor != address(0), "anchor=0");
        require(_midasPubkeyHash != bytes32(0), "midasHash=0"); // footgun: an immutable 0 = binding to nothing
        anchor = _anchor;
        midasPubkeyHash = _midasPubkeyHash;
    }

    /**
     * Append checkpoint `epoch`. Invariants (make rewrite/reorder/silent-jump detectable):
     *  - only the immutable anchor may write;
     *  - epoch is strictly monotonic +1 (no gaps, no rewrites — a written slot is immutable);
     *  - ledger head CHAINS (prevLedgerHeadId == previous checkpoint's ledgerHeadId) and, when the
     *    head advances, seq STRICTLY increases; when the head is unchanged, seq must be unchanged too
     *    (id<->seq bound, so you cannot bump seq without a new head or freeze a head under a new seq);
     *  - identity head CHAINS (prevIdentityRoot == previous checkpoint's identityRoot);
     *  - sealedAtHeight does NOT regress (a later epoch cannot reference an older node height).
     */
    function submitCheckpoint(
        uint64 epoch,
        bytes32 stateRoot,
        bytes32 fociRoot,
        uint64 ledgerHeadSeq,
        bytes32 ledgerHeadId,
        bytes32 prevLedgerHeadId,
        bytes32 identityRoot,
        bytes32 prevIdentityRoot,
        uint64 appStateHeadSeq,
        bytes32 appStateHeadId,
        bytes32 prevAppStateHeadId,
        uint64 sealedAtHeight,
        string calldata cid
    ) external {
        require(msg.sender == anchor, "not anchor");
        require(epoch == latestEpoch + 1, "epoch not next");
        require(checkpoints[epoch].timestamp == 0, "epoch sealed");
        require(bytes(cid).length > 0 && bytes(cid).length <= 128, "bad cid len"); // Arweave 43 / IPFS CIDv1 ~59
        if (epoch > 1) {
            Checkpoint storage prev = checkpoints[epoch - 1];
            // Ledger chaining + id<->seq bound (closes the '>=' spec-vs-code gap).
            require(prevLedgerHeadId == prev.ledgerHeadId, "ledger chain broken");
            if (ledgerHeadId != prev.ledgerHeadId) {
                require(ledgerHeadSeq > prev.ledgerHeadSeq, "seq must advance with head");
            } else {
                require(ledgerHeadSeq == prev.ledgerHeadSeq, "seq moved but head frozen");
            }
            // Identity chaining (closes the silent identity de-revocation JUMP).
            require(prevIdentityRoot == prev.identityRoot, "identity chain broken");
            // App-state (FractalPay Postgres event log) chaining — same id<->seq bound as ledger.
            require(prevAppStateHeadId == prev.appStateHeadId, "app-state chain broken");
            if (appStateHeadId != prev.appStateHeadId) {
                require(appStateHeadSeq > prev.appStateHeadSeq, "app-state seq must advance with head");
            } else {
                require(appStateHeadSeq == prev.appStateHeadSeq, "app-state seq moved but head frozen");
            }
            // Referenced node height cannot regress.
            require(sealedAtHeight >= prev.sealedAtHeight, "height regressed");
        }
        checkpoints[epoch] = Checkpoint({
            stateRoot: stateRoot,
            fociRoot: fociRoot,
            ledgerHeadSeq: ledgerHeadSeq,
            ledgerHeadId: ledgerHeadId,
            prevLedgerHeadId: prevLedgerHeadId,
            identityRoot: identityRoot,
            prevIdentityRoot: prevIdentityRoot,
            appStateHeadSeq: appStateHeadSeq,
            appStateHeadId: appStateHeadId,
            prevAppStateHeadId: prevAppStateHeadId,
            sealedAtHeight: sealedAtHeight,
            timestamp: uint64(block.timestamp),
            cid: cid
        });
        latestEpoch = epoch;
        emit CheckpointAnchored(
            epoch, stateRoot, fociRoot, ledgerHeadSeq, ledgerHeadId, prevLedgerHeadId,
            identityRoot, prevIdentityRoot, appStateHeadSeq, appStateHeadId, prevAppStateHeadId,
            sealedAtHeight, cid, uint64(block.timestamp)
        );
    }

    /// Latest checkpoint (epoch 0 + zeroed struct if none yet).
    function latest() external view returns (uint64 epoch, Checkpoint memory cp) {
        return (latestEpoch, checkpoints[latestEpoch]);
    }
}
