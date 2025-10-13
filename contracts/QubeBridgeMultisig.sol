// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./QubeBridge.sol";  // Import the bridge contract for type safety

contract QubeBridgeMultisig is Ownable, ReentrancyGuard {
    using ECDSA for bytes32;

    // --- State Variables ---
    QubeBridge public immutable bridge;  // Reference to the bridge contract
    address[] public signers;            // List of authorized signers
    uint256 public requiredSignatures;   // Threshold (e.g., 2 for 2-of-3)
    uint256 public nonce;                // Replay protection
    /// @notice Counter for multisig transaction IDs (replay protection).
    uint256 public transactionIdCounter;

    // Struct for pending transactions
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        bool executed;
    }
    mapping(address => bool) public isSigner;
    mapping(uint256 => Transaction) public transactions;
    mapping(uint256 => mapping(address => bool)) public signatures;

    // --- Events ---
    event TransactionSubmitted(
        uint256 indexed transactionId,
        address indexed to,
        uint256 value,
        bytes data
    );
    event TransactionExecuted(uint256 indexed transactionId);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event RequiredSignaturesUpdated(uint256 newThreshold);

    // --- Errors ---
    error Unauthorized();
    error TransactionAlreadyExecuted();
    error InsufficientSignatures();
    error InvalidSignature();
    error BridgeCallFailed();

    // --- Constructor ---
    constructor(
        address[] memory _signers,
        uint256 _requiredSignatures,
        address _bridge
    ) Ownable(msg.sender) {
        require(_signers.length > 0, "Multisig: no signers");
        require(_requiredSignatures <= _signers.length, "Multisig: invalid threshold");
        require(_bridge != address(0), "Multisig: invalid bridge");

        bridge = QubeBridge(payable(_bridge));
        requiredSignatures = _requiredSignatures;

        for (uint256 i = 0; i < _signers.length; i++) {
            address signer = _signers[i];
            require(signer != address(0), "Multisig: invalid signer");
            require(!isSigner[signer], "Multisig: duplicate signer");
            isSigner[signer] = true;
            signers.push(signer);
        }
    }

    // --- Core Functions ---

    /**
     * @dev Submit a new transaction to the multisig.
     * @param to Target contract (e.g., QubeBridge).
     * @param value ETH value (use 0 for token bridging).
     * @param data Calldata (e.g., encoded `sendToken` call).
     * @return transactionId Unique ID for the transaction.
     */
    function submitTransaction(
        address to,
        uint256 value,
        bytes memory data
    ) external nonReentrant returns (uint256 transactionId) {
        transactionId = nonce++;
        transactions[transactionId] = Transaction({
            to: to,
            value: value,
            data: data,
            executed: false
        });
        emit TransactionSubmitted(transactionId, to, value, data);
    }

    /**
     * @dev Sign a transaction (off-chain or on-chain).
     * @param transactionId ID of the transaction to sign.
     */
    function signTransaction(uint256 transactionId) external {
        require(isSigner[msg.sender], "Multisig: not a signer");
        require(!transactions[transactionId].executed, "Multisig: executed");
        signatures[transactionId][msg.sender] = true;
    }

    /**
     * @dev Execute a transaction if threshold is met.
     * @param transactionId ID of the transaction.
     */
    function executeTransaction(uint256 transactionId) external payable nonReentrant {
        Transaction storage transaction = transactions[transactionId];
        require(!transaction.executed, "Multisig: executed");

        // Count signatures
        uint256 signatureCount = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signatures[transactionId][signers[i]]) {
                signatureCount++;
            }
        }
        require(signatureCount >= requiredSignatures, "Multisig: insufficient signatures");

        // Execute
        transaction.executed = true;
        (bool success, ) = transaction.to.call{value: transaction.value}(
            transaction.data
        );
        require(success, "Multisig: execution failed");

        emit TransactionExecuted(transactionId);
    }

    // --- Admin Functions ---

    function addSigner(address newSigner) external onlyOwner {
        require(!isSigner[newSigner], "Multisig: already a signer");
        isSigner[newSigner] = true;
        signers.push(newSigner);
        emit SignerAdded(newSigner);
    }

    function removeSigner(address oldSigner) external onlyOwner {
        require(isSigner[oldSigner], "Multisig: not a signer");
        require(oldSigner != owner(), "Multisig: cannot remove owner");
        isSigner[oldSigner] = false;
        // Swap-and-pop for gas efficiency
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == oldSigner) {
                signers[i] = signers[signers.length - 1];
                signers.pop();
                break;
            }
        }
        emit SignerRemoved(oldSigner);
    }

    function updateRequiredSignatures(uint256 newThreshold) external onlyOwner {
        require(
            newThreshold <= signers.length && newThreshold > 0,
            "Multisig: invalid threshold"
        );
        requiredSignatures = newThreshold;
        emit RequiredSignaturesUpdated(newThreshold);
    }

    // --- Helper Functions ---

    /**
     * @dev Get the number of signatures for a transaction.
     */
    function getSignatureCount(uint256 transactionId) public view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signatures[transactionId][signers[i]]) {
                count++;
            }
        }
        return count;
    }

    /// @notice Encodes a bridge call with QubeBridge's nonce parameter.
    /**
    * @dev Encode a `sendToken` call for the bridge (helper for off-chain signing).
    * @param bridgeNonce The nonce used by QubeBridge (not the multisig's nonce).
    */
    function encodeTransferToken(
        address tokenAddress,
        address recipient,
        uint256 amount,
        uint256 fromChainId,
        bytes32 srcTxHash,
        uint256 bridgeNonce  // Renamed to avoid shadowing
    ) public pure returns (bytes memory) {
        return abi.encodeWithSelector(
            QubeBridge.transferToken.selector,
            tokenAddress,
            recipient,
            amount,
            fromChainId,
            srcTxHash,
            bridgeNonce
        );
    }
}