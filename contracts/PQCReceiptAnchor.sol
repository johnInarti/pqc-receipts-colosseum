// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PQCReceiptAnchor
 * @notice Write-once, ownerless, fundless timestamp anchor for post-quantum-signed (ML-DSA-65 /
 *         FIPS 204) x402 receipts. The receipt itself — and its ML-DSA-65 signature — lives OFF-chain;
 *         this contract only records, immutably and publicly, that a receipt with a given identity,
 *         payload hash and signing-key id existed no later than the block that mined the anchor.
 *
 *         What an anchor PROVES: existence-by-time + integrity (the payloadHash can be recomputed
 *         from the off-chain receipt bytes) + which key id the issuer claims signed it.
 *         What an anchor does NOT prove: that the receipt's signature is valid (verify ML-DSA-65
 *         off-chain against the issuer's published key directory), that the payment it describes
 *         was correct, or that `msg.sender` is anyone in particular (anyone may anchor any receipt;
 *         `anchoredBy` is emitted so verifiers may pin a known anchorer if they want to).
 *
 *         Design constraints (deliberate): no owner, no roles, no ETH (no receive/fallback → any
 *         value transfer reverts), no upgradeability, no self-destruct, no external calls. The
 *         only state transition is "unanchored → anchored", and it can happen exactly once per
 *         `receiptId`. 256 bytes of calldata per anchor; cheap enough to run on every receipt.
 *
 * @dev Conventions used by FractalAI (not enforced on-chain; any issuer may choose its own):
 *        receiptId   = sha256(ML-DSA-65 signature bytes)            — unique per issued receipt
 *        payloadHash = sha256(exact bytes the signature covers)     — recomputable by anyone
 *        kid         = sha256(public_key_base64)[0..8] left-aligned in bytes32 (key-directory kid)
 *        observedAt  = issuer's own unix time when the receipt was signed (uint64)
 */
contract PQCReceiptAnchor {
    struct AnchorRecord {
        bytes32 payloadHash;
        bytes32 kid;
        uint64 observedAt;   // issuer-claimed signing time
        uint64 anchoredAt;   // block.timestamp of the anchoring block (0 = never anchored)
        address anchoredBy;  // msg.sender of the anchoring tx
    }

    /// @dev receiptId => record. `anchoredAt == 0` means "not anchored".
    mapping(bytes32 => AnchorRecord) private _anchors;

    /// @notice Total anchors ever written (monotonic; purely informational).
    uint256 public totalAnchored;

    /**
     * @notice Emitted exactly once per `receiptId`.
     * @dev `receiptId`, `payloadHash` and `kid` are indexed so an offline verifier can locate the
     *      anchor with a single `eth_getLogs` filtered by topic1 = receiptId, without any index.
     */
    event ReceiptAnchored(
        bytes32 indexed receiptId,
        bytes32 indexed payloadHash,
        bytes32 indexed kid,
        uint64 observedAt,
        address anchoredBy,
        uint256 anchoredAt
    );

    error AlreadyAnchored(bytes32 receiptId);
    error ZeroReceiptId();
    error ZeroPayloadHash();
    error EmptyBatch();
    error LengthMismatch();
    error ObservedAtInFuture(uint64 observedAt, uint256 blockTimestamp);

    /// @dev Maximum clock skew tolerated between the issuer's `observedAt` and the chain. An
    ///      anchor whose `observedAt` is in the future would let an issuer back-date nothing but
    ///      forward-date a receipt past its own anchor, which defeats "existed no later than".
    uint64 public constant MAX_FUTURE_SKEW = 15 minutes;

    /**
     * @notice Anchor one receipt. Reverts if `receiptId` was already anchored.
     * @param receiptId   Unique receipt identity (e.g. sha256 of the ML-DSA-65 signature). Non-zero.
     * @param payloadHash Hash of the exact signed bytes. Non-zero.
     * @param kid         Signing-key identifier (left-aligned 8-byte key-directory kid, or any scheme).
     * @param observedAt  Issuer's unix time of signing. Must not be more than MAX_FUTURE_SKEW ahead
     *                    of `block.timestamp`.
     */
    function anchor(bytes32 receiptId, bytes32 payloadHash, bytes32 kid, uint64 observedAt) external {
        _anchor(receiptId, payloadHash, kid, observedAt);
    }

    /**
     * @notice Anchor several receipts in one transaction. All-or-nothing: if any entry is invalid
     *         or already anchored, the whole batch reverts (so a verifier never sees a half batch).
     */
    function anchorBatch(
        bytes32[] calldata receiptIds,
        bytes32[] calldata payloadHashes,
        bytes32[] calldata kids,
        uint64[] calldata observedAts
    ) external {
        uint256 n = receiptIds.length;
        if (n == 0) revert EmptyBatch();
        if (payloadHashes.length != n || kids.length != n || observedAts.length != n) revert LengthMismatch();
        for (uint256 i = 0; i < n; ++i) {
            _anchor(receiptIds[i], payloadHashes[i], kids[i], observedAts[i]);
        }
    }

    /// @notice Block timestamp at which `receiptId` was anchored, or 0 if it never was.
    function anchoredAt(bytes32 receiptId) external view returns (uint64) {
        return _anchors[receiptId].anchoredAt;
    }

    /// @notice True iff `receiptId` has been anchored.
    function isAnchored(bytes32 receiptId) external view returns (bool) {
        return _anchors[receiptId].anchoredAt != 0;
    }

    /// @notice Full record for `receiptId` (all-zero if never anchored).
    function getAnchor(bytes32 receiptId) external view returns (AnchorRecord memory) {
        return _anchors[receiptId];
    }

    function _anchor(bytes32 receiptId, bytes32 payloadHash, bytes32 kid, uint64 observedAt) private {
        if (receiptId == bytes32(0)) revert ZeroReceiptId();
        if (payloadHash == bytes32(0)) revert ZeroPayloadHash();
        if (_anchors[receiptId].anchoredAt != 0) revert AlreadyAnchored(receiptId);
        if (uint256(observedAt) > block.timestamp + MAX_FUTURE_SKEW) {
            revert ObservedAtInFuture(observedAt, block.timestamp);
        }
        // block.timestamp fits in uint64 for the next ~5.8e11 years.
        uint64 nowTs = uint64(block.timestamp);
        _anchors[receiptId] = AnchorRecord({
            payloadHash: payloadHash,
            kid: kid,
            observedAt: observedAt,
            anchoredAt: nowTs,
            anchoredBy: msg.sender
        });
        unchecked { ++totalAnchored; }
        emit ReceiptAnchored(receiptId, payloadHash, kid, observedAt, msg.sender, block.timestamp);
    }
}
