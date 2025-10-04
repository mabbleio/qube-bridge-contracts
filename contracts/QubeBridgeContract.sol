// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./interfaces/IMintableERC20.sol";

/**
 * @title QubeBridge - v3.5
 * @author Mabble Protocol (@muroko)
 * @notice QubeBridge is a cross-chain Bridge
 * @custom:security-contact security@mabble.io
 * Website: qubeswap.com
*/
contract QubeBridge is Ownable, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // --- State Variables ---
    uint256 public immutable srcChainId;  // Origin deploy chain ID
    address public controller;
    address public multisig;
    address public feeRecipient;  // Address to receive bridge fees
    uint256 public feePercent;
    uint256 public unpauseDelay = 48 hours;
    uint256 private _unpauseTime;
    bool private _paused;  // Pause state

    // Track supported tokens globally (or per-chain if needed)
    address[] public supportedTokens;
    mapping(address => bool) private _supportedTokens;

    // Track supported destination chains (optional)
    uint256[] public supportedChainIds;
    mapping(uint256 => bool) private _supportedChainIds;

    // Nonce tracking per (fromChainId => toChainId)
    mapping(uint256 => mapping(uint256 => uint256)) public nonces;

    // Track locked ETH and tokens per user
    mapping(address => uint256) private _lockedETH;
    mapping(address => mapping(address => uint256)) private _lockedTokens;

    // Track which tokens are mintable (optional)
    mapping(address => bool) private _mintableTokens;

    // --- Events ---
    event Bridge(
        address indexed tokenAddress,
        address indexed from,
        address indexed to,
        uint256 amount,
        uint256 feeAmount,
        uint256 fromChainId,
        uint256 toChainId,
        uint256 nonce
    );
    event BridgeCompleted(
        address indexed tokenAddress,
        address indexed executor,
        address indexed to,
        uint256 amount,
        uint256 fromChainId,
        uint256 toChainId,
        bytes32 srcTxHash,
        uint256 nonce  // nonce
    );
    event TokenSupportUpdated(address indexed token, bool isSupported);
    event ChainSupportUpdated(uint256 indexed chainId, bool isSupported);
    event FeePercentUpdated(uint256 newPercent);
    event FeeRecipientUpdated(address newRecipient);  // Track fee recipient changes
    event ControllerUpdated(address newController);
    event MultisigUpdated(address newMultisig);
    event TokensWithdrawn(address indexed token, address indexed to, uint256 amount);
    event ETHWithdrawn(address indexed to, uint256 amount);
    // event TokenMintableStatusUpdated(address indexed token, bool isMintable);
    event MintableTokenUpdated(address indexed token, bool isMintable);

    // --- Modifiers ---
    modifier onlyBridge() {
        require(msg.sender == address(this), "Not bridge");
        _;
    }


    // --- Constructor ---
    constructor(
        uint256 _srcChainId,
        address _controller,
        address _multisig,
        address _feeRecipient  // Optional (defaults to controller if zero)
    ) Ownable(msg.sender) {
        require(_controller != address(0), "Bridge: invalid controller");
        require(_multisig != address(0), "Bridge: invalid multisig");
        require(_srcChainId != 0, "Bridge: invalid chain ID");
        srcChainId = _srcChainId;
        controller = _controller;
        multisig = _multisig;
        feeRecipient = _feeRecipient == address(0) ? _controller : _feeRecipient;
        feePercent = 0;

        // Automatically support the source chain
        _addSupportedChain(_srcChainId);
    }

    // --- Helper Functions ---
    function isSupportedToken(address token) public view returns (bool) {
        return _supportedTokens[token];
    }

    function isSupportedChain(uint256 chainId) public view returns (bool) {
        return _supportedChainIds[chainId];
    }

    // --- Core Functions ---
    function bridge(
        address tokenAddress,
        address destinationAddress,
        uint256 amount,
        uint256 destChainId,
        uint256 minAmount,
        uint256 deadline
    ) external payable nonReentrant whenNotPaused {
        require(amount >= minAmount, "Bridge: slippage too high");
        require(destChainId != srcChainId, "Bridge: same chain");
        require(isSupportedToken(tokenAddress), "Bridge: token not supported");
        require(isSupportedChain(destChainId), "Bridge: chain not supported");
        require(block.timestamp <= deadline, "Bridge: expired");

        uint256 feeAmount = (amount * feePercent) / 10_000;
        uint256 amountAfterFee = amount - feeAmount;
        require(amountAfterFee >= minAmount, "Bridge: slippage too high after fee");

        uint256 nonce = ++nonces[srcChainId][destChainId];

        if (tokenAddress == address(0)) {
            require(msg.value == amount, "Bridge: incorrect amount");
            // Transfer fee to feeRecipient (ETH)
            payable(feeRecipient).transfer(feeAmount);
            // Record locked ETH (post-fee)
            _lockedETH[msg.sender] += amountAfterFee;
        } else {
            IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
            // Transfer fee to feeRecipient (ERC20)
            IERC20(tokenAddress).safeTransfer(feeRecipient, feeAmount);
            // Record locked tokens (post-fee)
            _lockedTokens[msg.sender][tokenAddress] += amountAfterFee;
        }

        if (tokenAddress == address(0)) {
            require(msg.value == amount, "Bridge: incorrect amount");
            // Transfer fee to feeRecipient (ETH)
            payable(feeRecipient).transfer(feeAmount);
            // Lock ETH (post-fee)
            _lockedETH[msg.sender] += amountAfterFee;
        } else {
            if (_mintableTokens[tokenAddress]) {
                // Burn tokens from user instead of transferring to bridge
                IMintableERC20(tokenAddress).burn(msg.sender, amount);
                // Transfer fee separately (if needed)
                IERC20(tokenAddress).safeTransferFrom(msg.sender, feeRecipient, feeAmount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
                // Transfer fee to feeRecipient (ERC20)
                IERC20(tokenAddress).safeTransfer(feeRecipient, feeAmount);
                // Lock tokens (post-fee)
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
            nonce
        );
    }

    function sendToken(
        address tokenAddress,
        address recipient,
        uint256 amount,
        uint256 fromChainId,
        bytes32 srcTxHash,
        uint256 nonce 
    ) external nonReentrant whenNotPaused {
        require(msg.sender == multisig || msg.sender == controller, "Bridge: unauthorized");
        require(recipient != address(0), "Bridge: invalid recipient");
        require(isSupportedChain(fromChainId), "Bridge: source chain not supported");

        // Deduct locked ETH / locked tokens
        if (tokenAddress == address(0)) {
            _lockedETH[recipient] -= amount;
        } else {
            _lockedTokens[recipient][tokenAddress] -= amount;
        }

        emit BridgeCompleted(
            tokenAddress,
            msg.sender,
            recipient,
            amount,
            fromChainId,
            srcChainId,
            srcTxHash,
            nonce  // Pass the nonce
        );

        if (tokenAddress == address(0)) {
            payable(recipient).transfer(amount);
        } else {
            if (_mintableTokens[tokenAddress]) {
                // Mint tokens instead of transferring from bridge's balance
                IMintableERC20(tokenAddress).mint(recipient, amount);
            } else {
                IERC20(tokenAddress).safeTransfer(recipient, amount);
            }
        }
    }

    /**
    * @dev Mark a token as mintable (must implement IMintableERC20).
    * @param token Address of the token.
    * @param isMintable Whether the token supports minting/burning.
    */
    function setMintableToken(address token, bool isMintable) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        require(isSupportedToken(token), "Bridge: token not supported");
        _mintableTokens[token] = isMintable;
        emit MintableTokenUpdated(token, isMintable);
    }

    // --- Admin Functions ---
    function updateFeeRecipient(address newRecipient) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        require(newRecipient != address(0), "Bridge: invalid recipient");
        feeRecipient = newRecipient;
        emit FeeRecipientUpdated(newRecipient);
    }

    function addSupportedToken(address token) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        require(token != address(0), "Bridge: invalid token");
        require(!_supportedTokens[token], "Bridge: token already supported");

        _supportedTokens[token] = true;
        supportedTokens.push(token);
        emit TokenSupportUpdated(token, true);
    }

    function removeSupportedToken(address token) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        require(token != address(0), "Bridge: invalid token");
        require(_supportedTokens[token], "Bridge: token not supported");

        _supportedTokens[token] = false;
        // Remove from array (swap-and-pop)
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }
        emit TokenSupportUpdated(token, false);
    }

    function _addSupportedChain(uint256 chainId) private {
        require(!_supportedChainIds[chainId], "Bridge: chain already supported");
        _supportedChainIds[chainId] = true;
        supportedChainIds.push(chainId);
        emit ChainSupportUpdated(chainId, true);
    }

    function addSupportedChain(uint256 chainId) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        require(chainId != 0, "Bridge: invalid chain ID");
        require(chainId != srcChainId, "Bridge: cannot add source chain");
        _addSupportedChain(chainId);
    }

    function removeSupportedChain(uint256 chainId) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        require(chainId != srcChainId, "Bridge: cannot remove source chain");
        require(_supportedChainIds[chainId], "Bridge: chain not supported");

        _supportedChainIds[chainId] = false;
        // Remove from array (swap-and-pop)
        for (uint256 i = 0; i < supportedChainIds.length; i++) {
            if (supportedChainIds[i] == chainId) {
                supportedChainIds[i] = supportedChainIds[supportedChainIds.length - 1];
                supportedChainIds.pop();
                break;
            }
        }
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
        require(msg.sender == controller, "Bridge: unauthorized");
        uint256 amount = IERC20(tokenAddress).balanceOf(address(this));
        IERC20(tokenAddress).safeTransfer(to, amount);
        emit TokensWithdrawn(tokenAddress, to, amount);
    }

    function withdrawETH(address payable to) external nonReentrant whenPaused {
        require(msg.sender == controller, "Bridge: unauthorized");
        payable(to).transfer(address(this).balance);
        emit ETHWithdrawn(to, address(this).balance);
    }

    // --- Emergency Functions ---
    function unpause() external {
        require(msg.sender == multisig || msg.sender == controller, "Bridge: unauthorized");
        require(block.timestamp >= _unpauseTime, "Bridge: unpause delayed");
        _unpause();
    }

    function pause() external {
        require(msg.sender == multisig || msg.sender == controller, "Bridge: unauthorized");
        _pause();
        _unpauseTime = block.timestamp + unpauseDelay;
    }

    // --- Fallback/Receive ---
    receive() external payable {
        revert("Bridge: ETH transfers not allowed (use bridge())");
    }

    fallback() external payable {
        revert("Bridge: ETH transfers not allowed (use bridge())");
    }

    // --- Setters ---
    function updateFeePercent(uint256 newPercent) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        feePercent = newPercent;
        emit FeePercentUpdated(newPercent);
    }

    function updateController(address newController) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        controller = newController;
        emit ControllerUpdated(newController);
    }

    function updateMultisig(address newMultisig) external nonReentrant {
        require(msg.sender == controller, "Bridge: unauthorized");
        multisig = newMultisig;
        emit MultisigUpdated(newMultisig);
    }
}