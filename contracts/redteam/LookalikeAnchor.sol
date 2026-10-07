// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// RED-TEAM FIXTURE (never deploy): emits PQCReceiptAnchor's exact ReceiptAnchored topic with ANY anchoredAt.
/// Used to prove that a verifier which trusts `seal.anchor.contract` + event data can be fed a back-dated anchor.
contract LookalikeAnchor {
    event ReceiptAnchored(bytes32 indexed receiptId, bytes32 indexed payloadHash, bytes32 indexed kid, uint64 observedAt, address anchoredBy, uint256 anchoredAt);

    function forge(bytes32 receiptId, bytes32 payloadHash, bytes32 kid, uint64 observedAt, address anchoredBy, uint256 anchoredAt) external {
        emit ReceiptAnchored(receiptId, payloadHash, kid, observedAt, anchoredBy, anchoredAt);
    }
}
