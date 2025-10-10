// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@chainlink/contracts/src/v0.8/automation/AutomationCompatible.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "./interfaces/IMintableERC20.sol";

/**
 * @title QubeBridge - v5.6
 * @author Mabble Protocol (@muroko)
 * @notice using OpenZellin Contracts v5
 * @notice QubeBridge is a cross-chain Bridge on supported chains
 * @notice QubeBridge is a Secure Custom Private Bridge operated by Mabble Protocol
 * used solely by QubeSwap Dex for its users to Bridge Assets and Trade.
 * The Bridge work flow relied on a Backend Processor Server off-chain
 * validation and a multisig for admin operations.
 * @custom:security-contact security@mabble.io
 * Website: qubeswap.com
*/
contract QubeBridge is ReentrancyGuard, Pausable, Ownable2Step, AutomationCompatible {
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;

    // TxDetails struct definition
    struct TxDetails {
        address token;
        address user;
        uint256 amount;
    }

    // --- State Variables ---
    address public controller;
    address public processor;
    address[] public supportedTokens;  // List of supported tokens
    uint256 public immutable srcChainId;  // Origin deploy chain ID
    address public multisig;  // Managed by Mabble Protocol for admin operations
    address public feeRecipient;  // Address to receive bridge fees
    uint256 public feePercent = 200; // Default bridge Fee in basis points (e.g., 2% = 200)
    uint256 public emergencyWithdrawLockUntil;
    uint256 public MAX_SUPPORTED_TOKENS = 100;
    uint256 public constant FEE_DIVISOR = 10_000;
    uint256 public unpauseDelay = 48 hours;
    uint256 private _maxPendingTransactions = 100;
    uint256 private _unpauseTime;

    // Constants for bitmask operations
    uint8 private constant FLAG_PAUSED    = 0x01;  // Binary: 00000001 (Bit 0)
    uint8 private constant FLAG_MINTABLE  = 0x02;  // Binary: 00000010 (Bit 1)
    
    // --- Chainlink Automation Support ---
    address public chainlinkOracle;               // Chainlink Automation registry address (address(0) if unsupported)
    bytes32 public chainlinkJobId;                 // Chainlink job ID (bytes32(0) if unsupported)
    uint256 public oracleTimeout = 15 minutes;        // Max time to wait for oracle validation
    uint256[] private _chainlinkEnabledChains;
    mapping(uint256 => bool) public chainlinkSupportedChains;  // Track per-chain Chainlink support
    mapping(bytes32 => bool) public oracleValidations;         // Track validated transactions
    mapping(bytes32 => uint256) public txHashToChainId;        // Map txHash to destChainId for Chainlink callbacks
    
    // Track pending transactions (for Chainlink oracle validation)
    bytes32[] private _pendingTransactions;

    // Track supported tokens
    EnumerableSet.AddressSet private _supportedTokens;
    // Track supported destination chains
    EnumerableSet.UintSet private _supportedChainIds;

    // Bitmask flags for token properties (1 byte = 8 bits)
    // Bit 0: isSupported (redundant with EnumerableSet, but kept for clarity)
    // Bit 1: isPaused
    // Bit 2: isMintable
    // Bits 3-7: Reserved for future use
    // Track paused tokens
    // Track which tokens are mintable (optional)
    mapping(address => uint8) private _tokenFlags;
    mapping(address => bool) private _pausedTokens;
    mapping(address => bool) private _mintableTokens;
    // Track paused chains
    mapping(uint256 => bool) private _pausedChains;
    // user => srcChain => destChain =>
    mapping(address => mapping(uint256 => mapping(uint256 => uint256))) public nonces;
    // Track locked Native Chain Token and ERC20 tokens per user
    mapping(address => uint256) private _lockedETH;
    mapping(address => mapping(address => uint256)) private _lockedTokens;
    // Track processed transactions to prevent replay attacks
    mapping(bytes32 => bool) private _processedTransactions;
    // chainId => [txHash1, txHash2]
    mapping(uint256 => bytes32[]) private _pendingTransactionsByChain;
    // Track pending transactions to prevent duplicate bridging attempts
    mapping(bytes32 => bool) private _isPendingTransaction;
    // Track pending transaction timestamps to enforce timeouts
    mapping(bytes32 => uint256) private _pendingTxTimestamps;
    // Track the minimum amount of tokens that can be bridged
    mapping(address => uint256) public minAmount;
    mapping(address => uint256) private _tokenIndices;
    mapping(address => uint256) private _recoveryTimelocks;
    // Track transaction details for pending transactions
    mapping(bytes32 => TxDetails) private _txHashDetails;
    // Track cancel timelocks for pending transactions
    mapping(bytes32 => uint256) private _cancelTimelocks;

    // --- Events ---
    event Bridge(
        address indexed tokenAddress,
        address indexed from,
        address indexed to,
        uint256 amount,
        uint256 feeAmount,
        uint256 fromChainId,
        uint256 toChainId,
        uint256 nonce,
        uint256 deadline
    );
    event BridgeCompleted(
        address indexed tokenAddress,
        address indexed executor,
        address indexed to,
        uint256 amount,
        uint256 fromChainId,
        uint256 toChainId,
        bytes32 srcTxHash,
        uint256 nonce
    );

    // --- New Event for Chainlink Automation ---
    event BridgeInitiated(
        address indexed tokenAddress,
        address indexed from,
        address indexed to,
        uint256 amount,
        uint256 feeAmount,
        uint256 fromChainId,
        uint256 toChainId,
        uint256 validationDeadline
    );
    event BridgeToUnsupportedChain(
        address indexed tokenAddress,
        address indexed from,
        address indexed to,
        uint256 amount,
        uint256 chainId,
        string warning
    );
    event BridgeFailed(
        address indexed tokenAddress,
        address indexed from,
        uint256 amount,
        string reason
    );
    event TokenSupportUpdated(address indexed token, bool isSupported);
    event ChainSupportUpdated(uint256 indexed chainId, bool isSupported);
    event FeePercentUpdated(uint256 newFeePercent);
    event FeeRecipientUpdated(address newRecipient);
    event ControllerUpdated(address newController);
    event ProcessorUpdated(address newProcessor);
    event MultisigUpdated(address newMultisig);
    event TokensWithdrawn(address indexed token, address indexed to, uint256 amount);
    event ETHWithdrawn(address indexed to, uint256 amount);
    event MintableTokenUpdated(address indexed token, bool isMintable);
    event MinAmountChanged(address indexed token, uint256 newMinAmount);
    event TokenPauseUpdated(address indexed token, bool isPaused);
    event ChainPauseUpdated(uint256 indexed chainId, bool isPaused);
    event OracleValidationCompleted(bytes32 indexed txHash, uint256 indexed chainId);
    event ChainlinkSupportUpdated(uint256 indexed chainId, bool isSupported);
    event ChainlinkConfigUpdated(address indexed oracle, bytes32 indexed jobId);
    event OracleValidationOverridden(bytes32 indexed txHash);
    event OracleTimeoutUpdated(uint256 newTimeout);
    event MaxSupportedTokensUpdated(uint256 newMaxSupportedTokens);
    event EmergencyWithdrawal(address indexed user, address indexed token, uint256 amount);
    event TransactionCancelled(bytes32 indexed txHash, address indexed user);
    event TransactionCancelledByController(bytes32 indexed txHash, address indexed user, address indexed controller);
    event UnpauseDelayUpdated(uint256 oldDelay, uint256 newDelay);

    // --- Modifiers ---
    
    modifier onlyBridge() {
        require(msg.sender == address(this), "Not bridge");
        _;
    }

    modifier whenChainNotPaused(uint256 destChainId) {
        require(!_pausedChains[destChainId], "Pausable: chain paused");
        _;
    }

    // Add new modifier for token-specific checks
    modifier whenTokenNotPaused(address token) {
        require(!_isTokenPaused(token), "Pausable: token paused");
        _;
    }

    // --- Custom Error ---
    error Bridge__Unauthorized(address caller);

    // --- Constructor ---
    constructor(
        uint256 _srcChainId,
        address _controller,
        address _processor,
        address _multisig,
        address _feeRecipient,
        address _chainlinkOracle,       // Optional: address(0) if unsupported
        bytes32 _chainlinkJobId          // Optional: bytes32(0) if unsupported
    ) Ownable(msg.sender) {
        require(_controller != address(0), "Bridge: invalid controller");
        require(_multisig != address(0), "Bridge: invalid multisig");
        require(_srcChainId != 0, "Bridge: invalid chain ID");

        srcChainId = _srcChainId;
        controller = _controller;
        processor = _processor;
        multisig = _multisig;
        feeRecipient = _feeRecipient;

        // Initialize Chainlink (if supported)
        chainlinkOracle = _chainlinkOracle;
        chainlinkJobId = _chainlinkJobId;
        if (_chainlinkOracle != address(0) && _chainlinkJobId != bytes32(0)) {
            chainlinkSupportedChains[_srcChainId] = true;
        } else {
            chainlinkSupportedChains[_srcChainId] = false;
        }

        // Automatically support the source chain
        _addSupportedChain(_srcChainId);
    }

    // --- Check Functions ---

    function isSupportedToken(address token) public view returns (bool) {
        return _supportedTokens.contains(token);
    }

    function isSupportedChain(uint256 chainId) public view returns (bool) {
        return _supportedChainIds.contains(chainId);
    }

    // --- Token Flags ---

    /// @dev Check if a token is paused
    function _isTokenPaused(address token) internal view returns (bool) {
        return (_tokenFlags[token] & FLAG_PAUSED) != 0;
    }

    /// @dev Check if a token is mintable
    function _isTokenMintable(address token) internal view returns (bool) {
        return (_tokenFlags[token] & FLAG_MINTABLE) != 0;
    }

    /// @dev Sets the pause status of a token.
    /// @param token Address of the token.
    /// @param paused Whether to pause the token.
    function _setTokenPaused(address token, bool paused) internal {
        if (paused) {
            _tokenFlags[token] |= FLAG_PAUSED;
        } else {
            _tokenFlags[token] &= ~FLAG_PAUSED;
        }
    }

    /// @dev Set mintable status for a token
    function _setTokenMintable(address token, bool mintable) internal {
        require(
            mintable ? IMintableERC20(token).supportsInterface(type(IMintableERC20).interfaceId) : true,
            "Token does not support IMintableERC20"
        );
        if (mintable) {
            _tokenFlags[token] |= FLAG_MINTABLE;
        } else {
            _tokenFlags[token] &= ~FLAG_MINTABLE;
        }
    }

    // --- Core Functions ---

    /// @notice Bridge tokens from the source chain to the destination chain.
    /// @param tokenAddress The address of the token to bridge.
    /// @param destinationAddress The address to receive the tokens on the destination chain.
    /// @param amount The amount of tokens to bridge.
    /// @param destChainId The chain ID of the destination chain.
    function bridge(
        address tokenAddress,
        address destinationAddress,
        uint256 amount,
        uint256 destChainId
    ) external payable nonReentrant whenNotPaused 
        whenTokenNotPaused(tokenAddress) whenChainNotPaused(destChainId) {
        require(destinationAddress != address(0), "Bridge: invalid destination");
        require(isSupportedChain(destChainId), "Bridge: unsupported destination chain");

        uint256 deadline = 0;
        // Calculate fee and enforce minAmount
        uint256 feeAmount = Math.mulDiv(amount, feePercent, FEE_DIVISOR);
        require(feeAmount <= amount, "Bridge: fee exceeds amount");  // Sanity check
        uint256 amountAfterFee = amount - feeAmount;
        
        require(amount >= minAmount[tokenAddress], "Bridge: amount < minAmount");
        require(amountAfterFee >= (minAmount[tokenAddress] * (FEE_DIVISOR - feePercent)) / FEE_DIVISOR, "Bridge: slippage too high");
        require(destChainId != srcChainId, "Bridge: cannot bridge to same chain");
        require(deadline <= block.timestamp + 1 days, "Bridge: deadline too far");  // ✅ Prevent DoS   
        require(deadline > 5 minutes && deadline <= block.timestamp + oracleTimeout, "Deadline exceeds oracle timeout");
        require(block.timestamp <= deadline, "Bridge: expired");

        // ✅ Checks-Effects-Interactions
        unchecked { nonces[msg.sender][srcChainId][destChainId]++; }  // ✅ Saves gas
        uint256 nonce = nonces[msg.sender][srcChainId][destChainId];

        // Process token/ETH transfer
        if (tokenAddress == address(0)) {
            require(msg.value == amount, "Bridge: incorrect ETH amount");
            require(msg.value >= minAmount[tokenAddress] + feeAmount, "Bridge: ETH amount too low");
            payable(feeRecipient).transfer(feeAmount);
            _lockedETH[msg.sender] += amountAfterFee;
        } else {
            if (_isTokenMintable(tokenAddress)) {
                IMintableERC20(tokenAddress).burn(msg.sender, amountAfterFee);  // Burn after fee
                IERC20(tokenAddress).safeTransfer(feeRecipient, feeAmount);      // Transfer fee separately
            } else {
                IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
                IERC20(tokenAddress).safeTransfer(feeRecipient, feeAmount);
                _lockedTokens[msg.sender][tokenAddress] += amountAfterFee;
            }
        }

        emit Bridge(
            tokenAddress,
            msg.sender,
            destinationAddress,
            amountAfterFee,
            feeAmount,
            srcChainId,
            destChainId,
            nonce,
            deadline
        );

        bytes32 txHash = keccak256(
            abi.encode(
                tokenAddress,
                msg.sender,
                destinationAddress,
                amount,
                srcChainId,
                destChainId,
                nonce
        ));
        _txHashDetails[txHash] = TxDetails({
            token: tokenAddress,
            user: msg.sender,
            amount: amountAfterFee
        });

        if (!chainlinkSupportedChains[destChainId]) {
            emit BridgeToUnsupportedChain(
                tokenAddress,
                msg.sender,
                destinationAddress,
                amount,
                destChainId,
                "Processor intervention required"
            );
        }
        // Store txHash -> destChainId mapping for Chainlink callbacks
        txHashToChainId[txHash] = destChainId;

        // Emit Chainlink event if destChainId supports Chainlink
        if (chainlinkSupportedChains[destChainId]) {
            _pendingTransactions.push(txHash);
            _isPendingTransaction[txHash] = true;
            emit BridgeInitiated(
                tokenAddress,
                msg.sender,
                destinationAddress,
                amount,
                feeAmount,
                srcChainId,
                destChainId,
                block.timestamp + oracleTimeout
            );
        }
    }

    // Processor function to transfer tokens
    function transferToken(
        address tokenAddress,
        address recipient,
        uint256 amount,
        uint256 fromChainId,
        bytes32 srcTxHash,
        uint256 nonce 
    ) external nonReentrant whenNotPaused {
        require(!_processedTransactions[srcTxHash], "Bridge: already processed");
        require(isSupportedChain(fromChainId), "Bridge: unsupported source chain");
        require(recipient != address(0), "Bridge: invalid recipient");
        require(amount >= minAmount[tokenAddress], "Bridge: amount < minAmount");

        // Get the destination chain ID from the transaction hash
        uint256 destChainId = txHashToChainId[srcTxHash];
        // Allow processor OR Chainlink validation
        require((chainlinkSupportedChains[destChainId] && oracleValidations[srcTxHash]) ||
                (msg.sender == processor && !chainlinkSupportedChains[destChainId]),
                "Bridge: unauthorized"
        );
        require((tokenAddress == address(0) && address(this).balance >= amount) ||
                (tokenAddress != address(0) && _lockedTokens[recipient][tokenAddress] >= amount),
                "Bridge: insufficient balance"
        );
        require(block.timestamp <= txHashToChainId[srcTxHash] + oracleTimeout,
                "Bridge: validation expired"
        );
        
        // EFFECTS: Mark as processed Before external calls
        _processedTransactions[srcTxHash] = true;
        require(nonce == nonces[recipient][fromChainId][srcChainId], "Bridge: invalid nonce");
        nonces[recipient][fromChainId][srcChainId] = nonce + 1;

        // INTERACTIONS (external calls) after state changes
        if (tokenAddress == address(0)) {
            require(address(this).balance >= amount, "Bridge: insufficient ETH");
            _lockedETH[recipient] -= amount;
            payable(recipient).transfer(amount);
        } else {
            require(_lockedTokens[recipient][tokenAddress] >= amount, "Bridge: insufficient tokens");
            _lockedTokens[recipient][tokenAddress] -= amount;
            if (_isTokenMintable(tokenAddress)) {
                // Mint tokens instead of transferring from bridge's balance
                try IMintableERC20(tokenAddress).mint(recipient, amount) {
                    // Success: proceed
                } catch {
                    revert("Bridge: token mint failed");
                }
            } else {
                IERC20(tokenAddress).safeTransfer(recipient, amount);
            }
        }

        // Emit the BridgeCompleted event
        emit BridgeCompleted(
            tokenAddress,
            msg.sender,
            recipient,
            amount,
            fromChainId,
            srcChainId,
            srcTxHash,
            nonce
        );
    }

    // --- Getters ---
    function getSupportedToken(uint256 index) external view returns (address) {
        return _supportedTokens.at(index);
    }

    function getSupportedChainIds() external view returns (uint256[] memory) {
        return _supportedChainIds.values();
    }

    // --- Chainlink Automation Callbacks ---

    function checkUpkeep(bytes calldata /* checkData */)
        external
        view
        override
        returns (bool upkeepNeeded, bytes memory performData)
    {
        // Check up to 10 chains at a time to prevent gas spikes
        uint256[] memory chains = _supportedChainIds.values();
        uint256 maxChecks = Math.min(chains.length, 10);  // Prevent gas spikes

        for (uint256 i = 0; i < maxChecks; i++) {
            uint256 chainId = chains[i];
            if (!chainlinkSupportedChains[chainId]) continue;

            bytes32 pendingTxHash = _findPendingTransaction(chainId);
            if (pendingTxHash != bytes32(0)) {
                upkeepNeeded = true;
                performData = abi.encode(pendingTxHash, chainId);
                return (upkeepNeeded, performData);
            }
        }
        upkeepNeeded = false;
    }

    function performUpkeep(bytes calldata performData) external override {
        (bytes32 txHash, uint256 destChainId) = abi.decode(performData, (bytes32, uint256));
        require(chainlinkSupportedChains[destChainId], "Bridge: Chainlink not supported");
        require(!oracleValidations[txHash], "Bridge: already validated");
        require(_isPendingTransaction[txHash], "Bridge: invalid txHash");
        require(block.timestamp <= txHashToChainId[txHash] + oracleTimeout, "Bridge: validation expired");

        // EFFECTS: Update state first
        oracleValidations[txHash] = true;
        _isPendingTransaction[txHash] = false;

        // INTERACTIONS: Emit last
        emit OracleValidationCompleted(txHash, destChainId);
    }   

    // --- Helper Functions ---

    // Helper function to get nonce key
    function _getNonceKey(address user, uint256 srcChain, uint256 destChain)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encode(user, srcChain, destChain));
    }

    // Helper function to add a pending transaction
    function _addPendingTransaction(bytes32 txHash) internal {
        require(_pendingTransactions.length < _maxPendingTransactions, "Bridge: too many pending txs");
        _pendingTransactions.push(txHash);
        _pendingTxTimestamps[txHash] = block.timestamp;
    }

    // Helper function to find pending transactions
    function _findPendingTransaction(uint256 chainId) internal view returns (bytes32) {
        for (uint256 i = 0; i < _pendingTransactions.length; i++) {
            bytes32 txHash = _pendingTransactions[i];
            if (txHashToChainId[txHash] == chainId && !oracleValidations[txHash]) {
                return txHash;
            }
        }
        return bytes32(0);
    }

    // Helper function to generate transaction hash
    function _generateTxHash(
        address tokenAddress,
        address sender,
        address destinationAddress,
        uint256 amount,
        uint256 fromChainId,
        uint256 toChainId,
        uint256 nonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                tokenAddress,
                sender,
                destinationAddress,
                amount,
                fromChainId,
                toChainId,
                nonce
            )
        );
    }

    // --- Oracle Management ---

    function isChainlinkConfigured() external view returns (bool) {
        return chainlinkOracle != address(0) && chainlinkJobId != bytes32(0);
    }

    // Enable/disable Chainlink for a chain
    function setChainlinkSupport(uint256 chainId, bool isSupported) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        chainlinkSupportedChains[chainId] = isSupported;
        emit ChainlinkSupportUpdated(chainId, isSupported);
    }

    // Update Chainlink oracle/job ID
    function setChainlinkConfig(address _oracle, bytes32 _jobId) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        chainlinkOracle = _oracle;
        chainlinkJobId = _jobId;
        emit ChainlinkConfigUpdated(_oracle, _jobId);
    }

    // Override oracle validation (emergency)
    function overrideOracleValidation(bytes32 txHash) external nonReentrant {
        if (msg.sender != processor) revert Bridge__Unauthorized(msg.sender);
        oracleValidations[txHash] = true;
        emit OracleValidationOverridden(txHash);
    }

    function setChainlinkSupportedChain(uint256 chainId, bool isSupported) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        chainlinkSupportedChains[chainId] = isSupported;
    }

    function setOracleTimeout(uint256 _timeout) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        oracleTimeout = _timeout;
    }

    // --- Admin Functions ---

    // Add a new supported token
    function addSupportedToken(address token) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(token != address(0), "Bridge: invalid token");
        require(_supportedTokens.length() < MAX_SUPPORTED_TOKENS, "Bridge: max tokens reached");
        // Check if the token is already supported
        require(!_supportedTokens.contains(token), "Bridge: token already supported");

        _supportedTokens.add(token);  // ✅ Correct
        _tokenIndices[token] = supportedTokens.length;
        supportedTokens.push(token); // Atomic update
        emit TokenSupportUpdated(token, true);
    }

    function removeSupportedToken(address token) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(token != address(0), "Bridge: invalid token");
        require(_supportedTokens.contains(token), "Bridge: token not supported");

        _supportedTokens.remove(token);  // ✅ Correct
        uint256 index = _tokenIndices[token];
        if (index < supportedTokens.length) {
            supportedTokens[index] = supportedTokens[supportedTokens.length - 1];
            _tokenIndices[supportedTokens[index]] = index;
        }
        supportedTokens.pop();
        delete _tokenIndices[token];
        emit TokenSupportUpdated(token, false);
    }

    function _addSupportedChain(uint256 chainId) private {
        require(!_supportedChainIds.contains(chainId), "Bridge: chain already supported");
        _supportedChainIds.add(chainId);
        emit ChainSupportUpdated(chainId, true);
    }

    function addSupportedChain(uint256 chainId) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(chainId < 10000, "Bridge: invalid chain ID");
        require(chainId != 0, "Bridge: invalid chain ID");
        require(chainId != srcChainId, "Bridge: cannot add source chain");
        _addSupportedChain(chainId);
    }

    function removeSupportedChain(uint256 chainId) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(chainId != srcChainId, "Bridge: cannot remove source chain");
        require(_supportedChainIds.contains(chainId), "Bridge: chain not supported");

        _supportedChainIds.remove(chainId);
        emit ChainSupportUpdated(chainId, false);
    }

    // --- View Functions ---

    function lockedETH(address user) public view returns (uint256) {
        return _lockedETH[user];
    }

    function lockedTokens(address user, address token) public view returns (uint256) {
        return _lockedTokens[user][token];
    }

    // --- Withdrawals ---

    function withdrawERC20(address tokenAddress, address to) external nonReentrant whenPaused {
        require(msg.sender == multisig || msg.sender == controller, "Bridge: unauthorized");
        uint256 amount = IERC20(tokenAddress).balanceOf(address(this));
        IERC20(tokenAddress).safeTransfer(to, amount);
        emit TokensWithdrawn(tokenAddress, to, amount);
    }

    function withdrawETH(address payable to) external nonReentrant whenPaused {
        require(msg.sender == multisig || msg.sender == controller, "Bridge: unauthorized");
        payable(to).transfer(address(this).balance);
        emit ETHWithdrawn(to, address(this).balance);
    }

    // --- Recovery Management ---

    function recoverMistakenMintableToken(address token) external nonReentrant {
        if (msg.sender != multisig) revert Bridge__Unauthorized(msg.sender);
        require(_mintableTokens[token], "Bridge: token not marked mintable");
        require(block.timestamp >= _recoveryTimelocks[token], "Bridge: recovery locked");

        // Transfer any accidentally locked tokens back to the bridge
        IERC20(token).safeTransferFrom(address(this), multisig, IERC20(token).balanceOf(address(this)));

        // Disable mintable flag
        _mintableTokens[token] = false;
        _recoveryTimelocks[token] = block.timestamp + 7 days;  // Prevent repeated calls
        emit MintableTokenUpdated(token, false);
    }

    function recoverERC20(address token, uint256 amount) external nonReentrant {
        if (msg.sender != multisig) revert Bridge__Unauthorized(msg.sender);
        uint256 recoverable = IERC20(token).balanceOf(address(this)) - _lockedTokens[address(this)][token];
        require(recoverable >= amount, "Bridge: insufficient recoverable balance");
        IERC20(token).safeTransfer(multisig, amount);
    }

    // --- Emergency Functions ---

    // Explicitly override Pausable functions
    function _pause() internal virtual override {
        Pausable._pause(); // Explicit call
    }

    function _unpause() internal virtual override {
        Pausable._unpause(); // Explicit call
    }

    function pause() external nonReentrant {
        require(msg.sender == multisig || msg.sender == controller, "Bridge: unauthorized");
        require(block.timestamp >= _unpauseTime, "Bridge: pause delayed");
        _unpauseTime = block.timestamp + unpauseDelay;

        if (emergencyWithdrawLockUntil == 0) {  // Only set if not already locked
            emergencyWithdrawLockUntil = block.timestamp + 3 days;
        }
        Pausable._pause();
    }

    function unpause() external nonReentrant {
        require(msg.sender == multisig || msg.sender == controller, "Bridge: unauthorized");
        require(block.timestamp >= _unpauseTime, "Bridge: unpause delayed");
        _unpauseTime = block.timestamp + unpauseDelay; // Reset for next pause
        emergencyWithdrawLockUntil = block.timestamp + 3 days;
        Pausable._unpause();
    }

    // Add new granular pause functions
    function pauseToken(address token) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(isSupportedToken(token), "Bridge: token not supported");
        _setTokenPaused(token, true);
        emit TokenPauseUpdated(token, true);
    }

    function unpauseToken(address token) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(isSupportedToken(token), "Bridge: token not supported");
        _setTokenPaused(token, false);
        emit TokenPauseUpdated(token, false);
    }

    function pauseChain(uint256 chainId) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(isSupportedChain(chainId), "Bridge: chain not supported");
        _pausedChains[chainId] = true;
        emit ChainPauseUpdated(chainId, true);
    }

    function unpauseChain(uint256 chainId) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(isSupportedChain(chainId), "Bridge: chain not supported");
        _pausedChains[chainId] = false;
        emit ChainPauseUpdated(chainId, false);
    }

    function emergencyWithdraw(address token, uint256 amount) external nonReentrant {
        require(block.timestamp >= emergencyWithdrawLockUntil, "Bridge: withdrawal locked");
        if (token == address(0)) {
            require(_lockedETH[msg.sender] >= amount, "Bridge: insufficient ETH");
            _lockedETH[msg.sender] -= amount;
            payable(msg.sender).transfer(amount);
        } else {
            require(_lockedTokens[msg.sender][token] >= amount, "Bridge: insufficient tokens");
            _lockedTokens[msg.sender][token] -= amount;
            IERC20(token).safeTransfer(msg.sender, amount);
        }
        emit EmergencyWithdrawal(msg.sender, token, amount);
    }

    function sweep(address token, address to, uint256 amount) external nonReentrant {
        if (msg.sender != multisig) revert Bridge__Unauthorized(msg.sender);
        require(token != address(0), "Bridge: ETH sweep not allowed");
        require(!isSupportedToken(token), "Bridge: cannot sweep supported tokens");

        uint256 bridgeBalance = IERC20(token).balanceOf(address(this));
        uint256 lockedBalance = 0;
        uint256 supportedTokensLength = _supportedTokens.length();  // Cache
        for (uint256 i = 0; i < supportedTokensLength; i++) {
            lockedBalance += _lockedTokens[address(this)][_supportedTokens.at(i)];
        }
        require(bridgeBalance - lockedBalance >= amount, "Bridge: insufficient sweepable balance");
        IERC20(token).safeTransfer(to, amount);
    }

    /**
    * @notice Cancels a pending bridge transaction and refunds the user.
    * @dev Can be called by the original user or the controller (for user support).
    * Only works for transactions to Chainlink-unsupported chains.
    * @param txHash The transaction hash of the pending bridge transaction.
    */
    function cancelPendingTransaction(bytes32 txHash) external nonReentrant {
        require(msg.sender == _txHashDetails[txHash].user ||
            (msg.sender == controller && block.timestamp >= _cancelTimelocks[txHash]),
            "Bridge: unauthorized or timelock active"
        );
        require(
            !chainlinkSupportedChains[txHashToChainId[txHash]],
            "Bridge: Chainlink-supported destination"
        );
        require(
            block.timestamp > txHashToChainId[txHash] + oracleTimeout,
            "Bridge: validation period active"
        );
        require(
            _isPendingTransaction[txHash],
            "Bridge: not pending"
        );

        TxDetails memory details = _txHashDetails[txHash];
        // Refund the user (not the caller, since the controller might be calling)
        if (details.token == address(0)) {
            require(_lockedETH[details.user] >= details.amount, "Bridge: insufficient ETH");
            _lockedETH[details.user] -= details.amount;
            payable(details.user).transfer(details.amount);
        } else {
            require(_lockedTokens[details.user][details.token] >= details.amount, "Bridge: insufficient tokens");
            _lockedTokens[details.user][details.token] -= details.amount;
            IERC20(details.token).safeTransfer(details.user, details.amount);
        }

        // Clean up
        delete _isPendingTransaction[txHash];
        delete txHashToChainId[txHash];
        delete _txHashDetails[txHash];
        emit TransactionCancelled(txHash, details.user);

        if (msg.sender == controller) {
            emit TransactionCancelledByController(txHash, details.user, msg.sender);
        }
    }

    // Controller must call this first, then wait (e.g., 1 day)
    function initiateCancelPendingTransaction(bytes32 txHash) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        _cancelTimelocks[txHash] = block.timestamp + 1 days;
    }

    // --- Fallback/Receive ---

    receive() external payable {
        revert("Bridge: Direct transfers not allowed (use bridge())");
    }

    fallback() external payable {
        revert("Bridge: Direct transfers not allowed (use bridge())");
    }

    // --- Setters ---

    /**
    * @notice Updates the delay required between pause/unpause operations.
    * @dev Restricted to controller or multisig. Enforces min/max bounds.
    * @param newDelay The new delay in seconds.
    */
    function setUnpauseDelay(uint256 newDelay) external nonReentrant {
        if (msg.sender != controller || msg.sender != multisig) revert Bridge__Unauthorized(msg.sender);
        require(
            newDelay >= 1 hours && newDelay <= 7 days,
            "Bridge: delay must be between 1 hour and 7 days"
        );

        // Emit event BEFORE state change (for front-running protection)
        emit UnpauseDelayUpdated(unpauseDelay, newDelay);

        unpauseDelay = newDelay;
    }

    /**
    * @dev Set the minimum amount of a token that can be bridged.
    * @param token Address of the token.
    * @param _minAmount Minimum amount of the token that can be bridged.
    */
    function setMinAmount(address token, uint256 _minAmount) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        minAmount[token] = _minAmount;
        emit MinAmountChanged(token, _minAmount);
    }

    /**
    * @dev Mark a token as mintable (must implement IMintableERC20).
    * @param token Address of the token.
    * @param isMintable Whether the token supports minting/burning.
    */
    function setMintableToken(address token, bool isMintable) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(token != address(0), "Bridge: invalid token");
        require(isSupportedToken(token), "Bridge: token not supported");
        _setTokenMintable(token, isMintable);
        emit MintableTokenUpdated(token, isMintable);
    }

    function updateMaxSupportedTokens(uint256 newMaxSupportedTokens) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(newMaxSupportedTokens > 100 && newMaxSupportedTokens <= 1000, "Bridge: New MAX_SUPPORTED_TOKENS must be > 100 ");
        MAX_SUPPORTED_TOKENS = newMaxSupportedTokens;
        emit MaxSupportedTokensUpdated(newMaxSupportedTokens);
    }

    function updateFeePercent(uint256 newPercent) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(newPercent <= 1000, "Bridge: fee too high");  // 10%
        feePercent = newPercent;
        emit FeePercentUpdated(newPercent);
    }

    function updateFeeRecipient(address newRecipient) external nonReentrant {
        if (msg.sender != controller) revert Bridge__Unauthorized(msg.sender);
        require(newRecipient != address(0), "Bridge: invalid fee recipient");
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(newRecipient);
    }

    function updateController(address newController) external nonReentrant {
        if (msg.sender != controller || msg.sender != multisig) revert Bridge__Unauthorized(msg.sender);
        require(newController != address(0), "Bridge: invalid controller");
        controller = newController;
        emit ControllerUpdated(newController);
    }

    function updateProcessor(address newProcessor) external nonReentrant {
        if (msg.sender != controller || msg.sender != multisig) revert Bridge__Unauthorized(msg.sender);
        require(newProcessor != address(0), "Bridge: invalid processor");
        processor = newProcessor;
        emit ProcessorUpdated(newProcessor);
    }

    function updateMultisig(address newMultisig) external nonReentrant {
        if (msg.sender != controller || msg.sender != multisig) revert Bridge__Unauthorized(msg.sender);
        multisig = newMultisig;
        emit MultisigUpdated(newMultisig);
    }
}