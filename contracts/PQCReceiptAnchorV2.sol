// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PQCReceiptAnchorV2 (PROPOSAL — NOT DEPLOYED)
 * @notice Same purpose and same ids as PQCReceiptAnchor (v1, deployed and immutable on Arbitrum One and Arc), with the
 *         one change the 2026-10-06 red-team asked for: records are NAMESPACED BY ANCHORER.
 *
 *         v1 keys the write-once slot by `receiptId` alone, so anyone who sees a receipt before it is anchored can
 *         occupy its slot with a garbage payloadHash and the genuine anchor can never be written there (permanent,
 *         ~US$0.003 griefing; and one squatted id reverts a whole `anchorBatch`). In v2 the slot is
 *         (anchoredBy, receiptId): a stranger can only write into HIS namespace, so the issuer's slot cannot be
 *         squatted, and the verifier MUST pin the anchorer it trusts (it reads `getAnchor(anchorer, receiptId)` or
 *         filters the event on topic2 = anchorer). `anchoredAt` is block.timestamp as before.
 *
 *         Batch semantics change too: `anchorBatch` skips ids already present in the caller's namespace instead of
 *         reverting (idempotent retries), but still reverts on malformed input.
 */
contract PQCReceiptAnchorV2 {
    struct AnchorRecord {
        bytes32 payloadHash;
        bytes32 kid;
        uint64 observedAt;
        uint64 anchoredAt; // 0 = never anchored
    }

    mapping(address => mapping(bytes32 => AnchorRecord)) private _anchors;
    uint256 public totalAnchored;
    uint64 public constant MAX_FUTURE_SKEW = 15 minutes;

    event ReceiptAnchored(
        bytes32 indexed receiptId,
        address indexed anchoredBy,
        bytes32 indexed payloadHash,
        bytes32 kid,
        uint64 observedAt,
        uint256 anchoredAt
    );

    error AlreadyAnchored(address anchoredBy, bytes32 receiptId);
    error ZeroReceiptId();
    error ZeroPayloadHash();
    error EmptyBatch();
    error LengthMismatch();
    error ObservedAtInFuture(uint64 observedAt, uint256 blockTimestamp);

    function anchor(bytes32 receiptId, bytes32 payloadHash, bytes32 kid, uint64 observedAt) external {
        if (!_anchor(receiptId, payloadHash, kid, observedAt)) revert AlreadyAnchored(msg.sender, receiptId);
    }

    /// @return written number of NEW records (ids already in the caller's namespace are skipped, not reverted).
    function anchorBatch(
        bytes32[] calldata receiptIds,
        bytes32[] calldata payloadHashes,
        bytes32[] calldata kids,
        uint64[] calldata observedAts
    ) external returns (uint256 written) {
        uint256 n = receiptIds.length;
        if (n == 0) revert EmptyBatch();
        if (payloadHashes.length != n || kids.length != n || observedAts.length != n) revert LengthMismatch();
        for (uint256 i = 0; i < n; ++i) {
            if (_anchor(receiptIds[i], payloadHashes[i], kids[i], observedAts[i])) ++written;
        }
    }

    function getAnchor(address anchoredBy, bytes32 receiptId) external view returns (AnchorRecord memory) {
        return _anchors[anchoredBy][receiptId];
    }

    function isAnchored(address anchoredBy, bytes32 receiptId) external view returns (bool) {
        return _anchors[anchoredBy][receiptId].anchoredAt != 0;
    }

    function _anchor(bytes32 receiptId, bytes32 payloadHash, bytes32 kid, uint64 observedAt) private returns (bool) {
        if (receiptId == bytes32(0)) revert ZeroReceiptId();
        if (payloadHash == bytes32(0)) revert ZeroPayloadHash();
        if (uint256(observedAt) > block.timestamp + MAX_FUTURE_SKEW) revert ObservedAtInFuture(observedAt, block.timestamp);
        AnchorRecord storage r = _anchors[msg.sender][receiptId];
        if (r.anchoredAt != 0) return false;
        r.payloadHash = payloadHash;
        r.kid = kid;
        r.observedAt = observedAt;
        r.anchoredAt = uint64(block.timestamp);
        unchecked { ++totalAnchored; }
        emit ReceiptAnchored(receiptId, msg.sender, payloadHash, kid, observedAt, block.timestamp);
        return true;
    }
}
