// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  MessageIntegrity
/// @author DES-perate Team
/// @notice Stores keccak256 Merkle roots of message conversation batches on
///         the Ethereum Sepolia testnet, providing tamper-evident integrity
///         verification for an end-to-end encrypted messaging application.
contract MessageIntegrity {

    // =========================================================================
    // State variables
    // =========================================================================

    /// @notice The server wallet address authorised to submit Merkle roots.
    address public immutable owner;

    /// @notice Address nominated to become the new owner. Must call
    ///         {acceptOwnership} to complete the transfer.
    address public pendingOwner;

    /// @notice Maximum number of roots accepted in a single `storeBatchHashes`
    ///         call. Prevents unbounded calldata from hitting the block gas
    ///         limit and producing an opaque out-of-gas revert.
    uint256 public constant MAX_BATCH_SIZE = 100;


    // =========================================================================
    // Custom errors
    // =========================================================================

    /// @notice Thrown when {acceptOwnership} is called by any address other
    ///         than {pendingOwner}.
    error NotPendingOwner();

    /// @notice Thrown by {transferOwnership} when the nominated address is
    ///         the zero address.
    error ZeroPendingOwner();

    /// @notice Thrown by the constructor when the supplied owner address is
    ///         the zero address.
    error ZeroOwner();

    /// @notice Thrown by `storeBatchHashes` when the input array is empty.
    error EmptyBatch();

    /// @notice Thrown by `storeBatchHashes` when the input array exceeds
    ///         `MAX_BATCH_SIZE`. Prevents unbounded calldata from causing an
    ///         opaque out-of-gas revert at the block gas limit.
    /// @param length The number of roots supplied by the caller.
    error BatchTooLarge(uint256 length);

    /// @notice Thrown when a submitted root is bytes32(0).
    /// @param index Array position of the zero root.
    error ZeroRoot(uint256 index);

    /// @notice Thrown when a function is called by an address other than the owner.
    error Unauthorized();

    // =========================================================================
    // Events
    // =========================================================================

    /// @notice Emitted when a new owner is nominated.
    /// @param previousOwner The current owner who initiated the transfer.
    /// @param newOwner      The nominated address.
    event OwnershipTransferInitiated(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when the nominated address accepts ownership.
    /// @param previousOwner The outgoing owner.
    /// @param newOwner      The new owner.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted once for every root successfully stored.
    /// @param merkleRoot The stored Merkle root.
    /// @param timestamp  Block timestamp at the time the transaction was mined.
    event HashStored(
        bytes32 indexed merkleRoot,
        uint256         timestamp
    );

    // =========================================================================
    // Constructor
    // =========================================================================

    constructor(address _owner) {
        if (_owner == address(0)) revert ZeroOwner();
        owner = _owner;
    }


    // =========================================================================
    // Ownership functions
    // =========================================================================

    /// @notice Nominate `newOwner` as the pending owner.
    /// @dev    Does not transfer ownership immediately. The nominated address
    ///         must call {acceptOwnership} to complete the transfer.
    ///         Reverts with {Unauthorized} if called by any address other than {owner}.
    ///         Reverts with {ZeroPendingOwner} if `newOwner` is the zero address.
    /// @param newOwner The address to nominate.
    function transferOwnership(address newOwner) external {
        if (msg.sender != owner)    revert Unauthorized();
        if (newOwner == address(0)) revert ZeroPendingOwner();
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(owner, newOwner);
    }

    /// @notice Accept ownership of the contract.
    /// @dev    Must be called by {pendingOwner} to complete a transfer initiated
    ///         by {transferOwnership}.
    ///         Reverts with {NotPendingOwner} if called by any other address.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }


    // =========================================================================
    // Merkle Write functions
    // =========================================================================

    /// @notice Store a batch of Merkle roots in a single transaction.
    /// @param merkleRoots Array of roots to record. Must be non-empty, within
    ///                    MAX_BATCH_SIZE, and contain no zero roots.
    function storeBatchHashes(bytes32[] calldata merkleRoots) external {
        _storeBatch(merkleRoots);
    }

    /// @notice Validates and emits a {HashStored} event for each root in the batch.
    /// @dev    Reverts with {Unauthorized} if called by any address other than {owner}.
    ///         Reverts with {EmptyBatch} if `merkleRoots` is empty.
    ///         Reverts with {BatchTooLarge} if `merkleRoots` exceeds {MAX_BATCH_SIZE}.
    ///         Reverts with {ZeroRoot} if any element is bytes32(0).
    /// @param merkleRoots Array of roots to validate and emit.
    function _storeBatch(bytes32[] calldata merkleRoots) internal {
        if (msg.sender != owner) revert Unauthorized();
        if (merkleRoots.length == 0)             revert EmptyBatch();
        if (merkleRoots.length > MAX_BATCH_SIZE) revert BatchTooLarge(merkleRoots.length);

        uint256 ts = block.timestamp;

        uint256 len = merkleRoots.length;
        for (uint256 i = 0; i < len;) {
            bytes32 merkleRoot = merkleRoots[i];

            if (merkleRoot == bytes32(0)) revert ZeroRoot(i);
            emit HashStored(merkleRoot, ts);
            unchecked { ++i; }
        }
    }
}
