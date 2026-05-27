// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  MessagesContract
/// @author EPIC Team
/// @notice Stores keccak256 Merkle roots of message conversation batches on
///         the Ethereum Sepolia testnet, providing tamper-evident integrity
///         verification for an end-to-end encrypted messaging application.
contract MessageIntegrity {

    // =========================================================================
    // State variables
    // =========================================================================

    /// @notice The server wallet address authorised to submit Merkle roots.
    address public immutable owner;

    /// @notice Maximum number of roots accepted in a single `storeBatchHashes`
    ///         call. Prevents unbounded calldata from hitting the block gas
    ///         limit and producing an opaque out-of-gas revert.
    uint256 public constant MAX_BATCH_SIZE = 50;


    // =========================================================================
    // Custom errors
    // =========================================================================

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


    // =========================================================================
    // Events
    // =========================================================================

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

    /// @notice Deploy the contract and permanently assign the authorised owner.
    /// @param _owner Server wallet address authorised to call `storeHash` and
    ///               `storeBatchHashes`. Reverts with `ZeroOwner` if the zero
    ///               address is supplied.
    constructor(address _owner) {
        if (_owner == address(0)) revert ZeroOwner();
        owner = _owner;
    }

    // =========================================================================
    // Write functions
    // =========================================================================

    function storeHash(bytes32 merkleRoot) external {
        bytes32[] memory roots = new bytes32[](1);
        roots[0] = merkleRoot;
        _storeBatch(roots);
    }

    function storeBatchHashes(bytes32[] calldata merkleRoots) external {
        _storeBatch(merkleRoots);
    }

    function _storeBatch(bytes32[] memory merkleRoots) internal {
        require(msg.sender == owner, "Only owner can submit");
        if (merkleRoots.length == 0)             revert EmptyBatch();
        if (merkleRoots.length > MAX_BATCH_SIZE) revert BatchTooLarge(merkleRoots.length);

        uint256 ts = block.timestamp;

        for (uint256 i = 0; i < merkleRoots.length; i++) {
            bytes32 merkleRoot = merkleRoots[i];

            if (merkleRoot == bytes32(0)) revert ZeroRoot(i);
            emit HashStored(merkleRoot, ts);

        }
    }


}
