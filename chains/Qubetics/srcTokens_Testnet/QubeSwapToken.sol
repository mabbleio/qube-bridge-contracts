// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Capped.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title QubeSwapToken - v5.5
 * @author Mabble Protocol (@muroko)
 * @notice QST is a multi-chain token
 * @dev A custom ERC-20 token with EIP-2612 permit functionality.
 * This token contract provides a secure, feature-rich ERC-20 implementation with 
 * governance controls, trading status management, token recovery mechanisms, and 
 * gasless approvals.
 * @custom:security-contact security@mabble.io
 * Website: qubeswap.com
 */
contract QubeSwapToken is ERC20Capped, ERC20Permit, ReentrancyGuard, AccessControl {
    using Address for address;
    using Address for address payable;
    using SafeERC20 for IERC20;

    // --- Roles ---
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant RECOVERER_ROLE = keccak256("RECOVERER_ROLE");

    // --- Constants ---
    string private constant _NAME = "QubeSwapToken";
    string private constant _SYMBOL = "QST";
    uint8 private constant _DECIMALS = 18;
    uint256 public constant MAX_SUPPLY = 100_000_000 * 10**_DECIMALS;

    // --- Events ---
    event PoolWhitelisted(address indexed pool, bool isWhitelisted);
	event LotteryWhitelisted(address indexed lottery, bool isWhitelisted);
    event TradingStatusUpdated(bool indexed liveTrading);
    event TradingStatusQueued(bool indexed newStatus, uint256 timestamp);
    event TradingStatusChangeCanceled();
    event RecoverableTokenUpdated(address indexed token, bool allowed);
    event TokenRecovered(address indexed token, address indexed recipient, uint256 amount);
    event NativeTokenRecovered(address indexed recipient, uint256 amount);
    event Mint(address indexed to, uint256 amount);
    event AdminGranted(address indexed account);
    event AdminNominated(address indexed account);
    event AdminRenounced(address indexed admin);
    event Paused(bool isPaused);

    // --- Storage ---
    mapping(address => bool) private _recoverableTokens;
    mapping(address => bool) private _pendingAdmins;
    mapping(address => bool) private _whitelistedPools;
	mapping(address => bool) private _whitelistedLotteryQst;
    struct QueuedStatusChange {
        bool newStatus;
        uint256 timestamp;
    }

    uint256 public constant TIMELOCK_DURATION = 24 hours; // trading toggle delay: 24-hour
    QueuedStatusChange private _tradeableStatusChange;
    bool public liveTrading = true; // Default: transfer/trading enabled
    bool private _paused;

    // --- Constructor ---
    constructor() ERC20(_NAME, _SYMBOL) ERC20Permit(_NAME) ERC20Capped(MAX_SUPPLY) {
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(RECOVERER_ROLE, msg.sender);
        _useNonce(msg.sender); // Initialize nonce for permit

        uint256 amount;
        // Fixed Cap Supply Mint
        uint256 capMint = MAX_SUPPLY;
        require(totalSupply() + amount <= cap(), "Exceeds cap");
        _mint(msg.sender, capMint);
        emit Mint(msg.sender, capMint);  // Optional: Custom event for clarity
    }

    modifier whenNotPaused() {
        require(!_paused, "This Contract is Paused");
        _;
    }

    function setPaused(bool paused) external onlyRole(ADMIN_ROLE) nonReentrant {
        _paused = paused;
        emit Paused(paused);
    }

    // --- Override Internal Functions ---
    function _update(
        address from,
        address to,
        uint256 value
    ) internal virtual override(ERC20, ERC20Capped) {
        _checkTradeableStatus();  // Check trading status before transfer
		
        bool isFromPool = _whitelistedPools[from];
		bool isToPool = _whitelistedPools[to];
		
		bool isFromLottery = _whitelistedLotteryQst[from];
		bool isToLottery = _whitelistedLotteryQst[to];
		
		require(!_paused, "This Contract is Paused"); // Add to _transfer
		
        // Allow transfers if:
		// 1. Trading is live, OR
		// 2. Transfer is from/to an admin, OR
		// 3. Transfer is FROM a whitelisted pool (buying), OR
		// 4. Transfer is TO a whitelisted pool (but block selling)
		require(
			liveTrading ||
			hasRole(ADMIN_ROLE, from) ||
			hasRole(ADMIN_ROLE, to) ||
			isFromPool,  // ✅ Allow buying (from pool to user)
			"QST: transfer/trading is disabled until launch!"
		);
		
		// ✅ Allow buying/claiming (from QST-Lottery)
		// Even when LiveTrading is false.
		require(
			liveTrading || isToLottery || isFromLottery,
			"QST: transfer/trading is disabled until launch!"
		);
		
        // Block transfers TO whitelisted pools if not from a pool 
		// (prevent selling) if liveTrading is false
		require(
			liveTrading || !isToPool || isFromPool,
			"QST: Selling disabled until launch!"
		);
		
        // Use ERC20's _transfer to handle balances (avoids direct state manipulation)
        super._update(from, to, value);  // ✅ ERC20 handles balances
	}

    // --- Trading Control ---
    /// @notice Queues a change to trading status (enabled/disabled).
    /// @dev Emits `TradingStatusQueued`. Change takes effect after `TIMELOCK_DURATION`.
    /// @param _status Desired trading status (true = enabled, false = disabled).
    function setTradeable(bool _status) external onlyRole(ADMIN_ROLE) nonReentrant {
        require(_tradeableStatusChange.timestamp == 0 || block.timestamp > _tradeableStatusChange.timestamp, "Change already queued or pending");
        _tradeableStatusChange = QueuedStatusChange({
            newStatus: _status,
            timestamp: block.timestamp + TIMELOCK_DURATION
        });
        emit TradingStatusQueued(_status, _tradeableStatusChange.timestamp);
    }

    /// @dev Checks and applies queued trading status changes.
    function _checkTradeableStatus() internal {
        uint256 currentTime = block.timestamp;  // Cache
        if (_tradeableStatusChange.timestamp != 0 && currentTime >= _tradeableStatusChange.timestamp) {
            bool newStatus = _tradeableStatusChange.newStatus;
            if (liveTrading != newStatus) {
                liveTrading = newStatus;
                emit TradingStatusUpdated(newStatus);
            }
            _tradeableStatusChange.timestamp = 0;
        }
    }

    function getTradeableStatusChange() public view returns (bool, uint256) {
        return (_tradeableStatusChange.newStatus, _tradeableStatusChange.timestamp);
    }

    function cancelTradeableStatusChange() external onlyRole(ADMIN_ROLE) nonReentrant {
        require(_tradeableStatusChange.timestamp != 0, "No change queued");
        _tradeableStatusChange.timestamp = 0;
        emit TradingStatusChangeCanceled(); // Emit cancellation
    }

    // --- Token Recovery ---
    /// @dev Admin/Recoverer can whitelist tokens for recovery.
    function setRecoverableToken(address token, bool allowed) external onlyRole(ADMIN_ROLE) {
        _recoverableTokens[token] = allowed;
        emit RecoverableTokenUpdated(token, allowed);
    }

    /// @dev Recoverer can rescue stuck ERC20 tokens.
    function recoverToken(
        address token,
        address recipient,
        uint256 amount
    ) external onlyRole(RECOVERER_ROLE) nonReentrant {
        require(_recoverableTokens[token], "Token not recoverable");
        IERC20(token).safeTransfer(recipient, amount); // Safe transfer with revert on failure
        emit TokenRecovered(token, recipient, amount);
    }

    /// @dev Recoverer can rescue stuck native tokens (e.g., ETH).
    function recoverNativeToken(address payable recipient, uint256 amount) external onlyRole(RECOVERER_ROLE) nonReentrant {
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        emit NativeTokenRecovered(recipient, amount);
    }

    // Grant admin role (restricted to owner)
    function grantAdmin(address account) external onlyRole(ADMIN_ROLE) nonReentrant {
        _grantRole(ADMIN_ROLE, account);
        emit AdminGranted(account);
    }

    function renounceAdmin() external onlyRole(ADMIN_ROLE) nonReentrant {
        _revokeRole(ADMIN_ROLE, msg.sender);
        emit AdminRenounced(msg.sender);
    }

    function nominateAdmin(address account) external onlyRole(ADMIN_ROLE) nonReentrant {
        _pendingAdmins[account] = true;
        emit AdminNominated(account);
    }

    function acceptAdmin() external nonReentrant {
        require(_pendingAdmins[msg.sender], "Not nominated");
        _grantRole(ADMIN_ROLE, msg.sender);
        delete _pendingAdmins[msg.sender];
        emit AdminGranted(msg.sender);
    }

    /// @dev Admin whitelists/delists a trading pool pair.
    /// @param pool Address of the pool contract (e.g., Uniswap pair).
    /// @param isWhitelisted True to whitelist, false to remove.
    // Add function to manage whitelisted pools
    function setWhitelistedPool(address pool, bool isWhitelisted) external onlyRole(ADMIN_ROLE) nonReentrant {
        _whitelistedPools[pool] = isWhitelisted;
        emit PoolWhitelisted(pool, isWhitelisted);
    }
	
	/// @dev Admin whitelists/delists a Lottery contract.
    /// @param lottery Address of the lottery contract (e.g., QST-Lottery).
    /// @param isWhitelisted True to whitelist, false to remove.
    // Add function to manage whitelisted lotteryqst.
    function setWhitelistedLottery(address lottery, bool isWhitelisted) external onlyRole(ADMIN_ROLE) nonReentrant {
        _whitelistedLotteryQst[lottery] = isWhitelisted;
        emit LotteryWhitelisted(lottery, isWhitelisted);
    }

    // Add helper function to check whitelisted lotteryqst
    function _isWhitelistedLottery(address lottery) internal view returns (bool) {
        return _whitelistedLotteryQst[lottery];
    }

    /// @dev Supports EIP-165 interface detection.
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId ||  // ERC-165
            interfaceId == type(IERC20).interfaceId ||   // ERC-20
            interfaceId == type(IERC20Metadata).interfaceId ||  // ERC-20 Metadata
            interfaceId == type(IERC20Permit).interfaceId ||  // ERC-20 Permit
            super.supportsInterface(interfaceId);  // AccessControl (ERC-165)
    }   
}