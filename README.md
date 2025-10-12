# Qube-Bridge-Contracts
Qube Bridge Contracts


## Notice
QubeBridge is a Secure Custom Private Bridge operated by Mabble Protocol
used solely by QubeSwap Dex for its users to Bridge Assets and Trade.
The Bridge work flow relied on a Backend Processor Server off-chain 
validation and a multisig for admin operations.


# QubeBridge Contract
**Version**: 6.2
**Author**: Mabble Protocol ([@muroko](https://github.com/muroko))
**Website**: [qubeswap.com](https://qubeswap.com)
**Security Contact**: [security@mabble.io](mailto:security@mabble.io)

---

## **Overview**
**QubeBridge** is a **secure, custom private bridge** designed exclusively for **QubeSwap DEX** to enable cross-chain asset transfers. It supports:
- **ERC20 tokens** (mintable and non-mintable).
- **Native ETH** bridging.
- **Chainlink Automation** for trusted validation.
- **Off-chain processor** fallback for non-Chainlink chains.

The bridge is **operated by Mabble Protocol** and uses a **multisig** for admin operations, ensuring decentralized control.

---

## **Key Features**
| Feature                     | Description                                                                                     |
|-----------------------------|-------------------------------------------------------------------------------------------------|
| **Cross-Chain Transfers**   | Bridge assets between supported EVM chains.                                                   |
| **Mintable/Non-Mintable**   | Supports both mintable (burn-and-mint) and non-mintable (lock-and-unlock) tokens.              |
| **Chainlink Automation**    | Trusted oracle validation for supported chains.                                               |
| **Off-Chain Processor**     | Manual validation for non-Chainlink chains.                                                   |
| **Granular Pausing**        | Pause globally, per-token, or per-chain.                                                      |
| **Fee System**              | Configurable fees (default: 2%) sent to `feeRecipient`.                                       |
| **Emergency Tools**         | Timelocked withdrawals, transaction cancellations, and recovery functions.                     |
| **Reentrancy Protection**   | Uses OpenZeppelin’s `ReentrancyGuard`.                                                         |
| **Two-Step Ownership**      | Secure admin handover via `Ownable2Step`.                                                      |
| **Gas Optimizations**       | Batched Chainlink checks, cached lengths, and efficient storage.                              |

---

## **Architecture**
### **1. Core Components**
#### **Structs**
- `TxDetails`: Stores transaction metadata (`token`, `user`, `amount`).
- **Bitmask Flags**: Track token properties (paused, mintable) in a single byte.

#### **State Variables**
| Variable                     | Type               | Description                                                                 |
|------------------------------|--------------------|-----------------------------------------------------------------------------|
| `_supportedTokens`           | `EnumerableSet`    | List of supported ERC20 tokens.                                             |
| `_supportedChainIds`        | `EnumerableSet`    | List of supported destination chains.                                       |
| `_lockedTokens`              | `mapping`          | Tracks user-locked ERC20 tokens.                                             |
| `_lockedETH`                 | `mapping`          | Tracks user-locked ETH.                                                     |
| `_processedTransactions`     | `mapping`          | Prevents replay attacks.                                                    |
| `chainlinkOracle`            | `address`          | Chainlink Automation registry.                                              |
| `oracleValidations`          | `mapping`          | Tracks validated transactions.                                               |
| `nonces`                     | `mapping`          | Prevents replay attacks per user/chain pair.                                |

#### **Modifiers**
| Modifier               | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `nonReentrant`         | Prevents reentrancy attacks.                                                |
| `whenNotPaused`        | Ensures the bridge is not paused.                                           |
| `whenTokenNotPaused`   | Ensures the token is not paused.                                            |
| `whenChainNotPaused`   | Ensures the destination chain is not paused.                                |

---

### **2. Workflow**
#### **Bridging Process**
1. **User Initiates Bridge** (`bridge()`):
   - Locks tokens/ETH on the source chain.
   - Emits a `Bridge` event for off-chain detection.
   - For **Chainlink-supported chains**, the transaction is added to `_pendingTransactions`.

2. **Validation**:
   - **Chainlink Chains**: Automated oracle validation via `checkUpkeep`/`performUpkeep`.
   - **Non-Chainlink Chains**: Manual validation by the `processor`.

3. **Completion** (`transferToken()`):
   - On the **destination chain**, the processor/oracle calls `transferToken()` to:
     - **Mint tokens** (if `isMintable`).
     - **Transfer from liquidity pool** (if non-mintable).
     - **Send ETH** (if native token).

4. **Events**:
   - `BridgeInitiated`: Transaction created.
   - `BridgeCompleted`: Transaction finalized.
   - `OracleValidationCompleted`: Chainlink validation successful.

#### **Fee Structure**
- **Default Fee**: 2% (configurable via `updateFeePercent`).
- **Fee Recipient**: Configurable `feeRecipient` address.
- **Slippage Protection**: Ensures users receive at least `minAmount` after fees.

---

### **3. Security Model**
| Mechanism               | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| **Reentrancy Guard**    | Prevents reentrancy attacks in all external functions.                     |
| **Pausable**            | Global/token/chain-level pausing.                                          |
| **Timelocks**           | Delays for critical actions (e.g., unpausing, token removal).             |
| **Multisig Control**    | Admin functions require multisig approval.                                  |
| **Nonce System**        | Prevents replay attacks per user/chain pair.                                |
| **Input Validation**    | Comprehensive checks for addresses, amounts, and chain IDs.                |
| **Emergency Withdrawals** | Timelocked user fund recovery.                                             |

---

## **Supported Assets**
### **1. Token Types**
| Type          | Description                                                                 | Example                     |
|---------------|-----------------------------------------------------------------------------|-----------------------------|
| **Mintable**  | Tokens implementing `IMintableERC20` (burn-and-mint model).                | USDC, DAI                   |
| **Non-Mintable** | Tokens requiring a **liquidity pool** on the destination chain.          | WETH, UNI                   |
| **ETH**       | Native ETH (locked and transferred directly).                              | ETH                          |

### **2. Liquidity Pool (For Non-Mintable Tokens)**
- The bridge **must hold a balance** of non-mintable tokens on the destination chain.
- Managed via:
  - `depositLiquidity()`: Add tokens to the pool.
  - `withdrawLiquidity()`: Remove tokens (emergency only).

---

## **Roles & Permissions**
| Role          | Description                                                                 | Key Functions                                                                 |
|---------------|-----------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Controller** | Admin-like role (managed by Mabble Protocol).                              | Add/remove tokens/chains, set fees, pause/unpause.                            |
| **Processor**  | Off-chain validator for non-Chainlink chains.                              | Calls `transferToken()` to finalize bridges.                                 |
| **Multisig**   | Emergency/recovery role.                                                    | Recover funds, override validations, manage liquidity.                        |
| **User**       | End users bridging assets.                                                  | Call `bridge()`, `emergencyWithdraw()`, `cancelPendingTransaction()`.         |
| **Chainlink**  | Oracle for supported chains.                                                | Validates transactions via `checkUpkeep`/`performUpkeep`.                   |

---

## **Functions**
### **1. Core Functions**
| Function                     | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| `bridge()`                   | Locks tokens/ETH and initiates cross-chain transfer.                      |
| `transferToken()`            | Finalizes the bridge on the destination chain (mint/transfer).            |
| `cancelPendingTransaction()` | Refunds users if bridging fails (timelocked).                              |
| `emergencyWithdraw()`        | Allows users to withdraw locked funds after a delay.                       |

### **2. Admin Functions**
| Function                     | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| `addSupportedToken()`        | Adds a new ERC20 token to the bridge.                                      |
| `removeSupportedToken()`     | Removes a token (timelocked).                                               |
| `setMintableToken()`         | Marks a token as mintable (requires `IMintableERC20`).                     |
| `pause()`/`unpause()`        | Globally pauses/unpauses the bridge.                                        |
| `pauseToken()`/`unpauseToken()` | Pauses/unpauses a specific token.                                          |
| `setChainlinkConfig()`       | Configures Chainlink Automation.                                            |
| `updateFeePercent()`        | Adjusts the bridge fee (max 5%).                                           |

### **3. Chainlink Automation**
| Function                     | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| `checkUpkeep()`               | Checks for pending transactions (called by Chainlink).                    |
| `performUpkeep()`            | Validates a pending transaction (called by Chainlink).                     |
| `overrideOracleValidation()` | Manually validates a transaction (processor/multisig).                   |

### **4. Emergency & Recovery**
| Function                     | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| `recoverERC20()`             | Recovers mistakenly sent ERC20 tokens.                                      |
| `sweep()`                    | Recovers unsupported tokens (multisig only).                                |
| `depositLiquidity()`         | Adds tokens to the liquidity pool (for non-mintable assets).                |
| `withdrawLiquidity()`       | Removes tokens from the pool (emergency).                                   |

---

## **Events**
| Event                          | Description                                                                 |
|--------------------------------|-----------------------------------------------------------------------------|
| `Bridge`                      | Emitted when a bridge is initiated.                                         |
| `BridgeCompleted`             | Emitted when a bridge is finalized.                                        |
| `BridgeInitiated`             | Chainlink-specific event for pending transactions.                          |
| `TokenSupportUpdated`         | Emitted when a token is added/removed.                                     |
| `FeePercentUpdated`           | Emitted when the fee percentage changes.                                   |
| `OracleValidationCompleted`   | Emitted when Chainlink validates a transaction.                             |
| `EmergencyWithdrawal`         | Emitted when a user withdraws locked funds.                                |
| `TransactionCancelled`        | Emitted when a pending transaction is cancelled.                           |

---

## **Security Considerations**
### **1. Audits & Testing**
- **Third-Party Audit**: Recommended before mainnet deployment (e.g., OpenZeppelin, ConsenSys Diligence).
- **Fuzz Testing**: Use **Foundry** or **Echidna** to test edge cases (reentrancy, front-running).
- **Formal Verification**: Consider **Certora** or **MythX** for critical functions.

### **2. Risks & Mitigations**
| Risk                          | Mitigation                                                                 |
|-------------------------------|----------------------------------------------------------------------------|
| **Reentrancy**                | `nonReentrant` modifier on all external functions.                        |
| **Front-Running**             | Timelocks on sensitive actions (e.g., unpausing, token removal).         |
| **Oracle Failure**            | Fallback to manual processor validation.                                   |
| **Liquidity Shortfall**       | `depositLiquidity()` ensures non-mintable tokens are available.           |
| **Admin Centralization**      | Multisig control for critical functions.                                  |
| **Fee Manipulation**          | Capped at 5% and configurable only by `controller`.                        |

### **3. Best Practices**
- **Upgradeability**: Consider deploying behind a **proxy** (e.g., OpenZeppelin Transparent Proxy).
- **Monitoring**: Set up alerts for:
  - Large `emergencyWithdraw` calls.
  - Changes to `controller`/`processor`/`multisig`.
  - Failed `transferToken` calls (potential exploits).
- **Bug Bounty**: Launch a program (e.g., via [Immunefi](https://immunefi.com/)).

---

## **Deployment**
### **1. Prerequisites**
- **Compiler**: Solidity `^0.8.28`.
- **Dependencies**:
  - OpenZeppelin (`@openzeppelin/contracts`).
  - Chainlink (`@chainlink/contracts`).
- **Environment**: Hardhat/Foundry for testing.

### **2. Constructor Parameters**
| Parameter               | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `_srcChainId`           | Chain ID where the bridge is deployed.                                     |
| `_controller`           | Admin address (e.g., Mabble Protocol).                                    |
| `_processor`            | Off-chain validator address.                                               |
| `_multisig`             | Multisig address for emergency operations.                                 |
| `_feeRecipient`         | Address to receive bridge fees.                                             |
| `_chainlinkOracle`      | Chainlink Automation registry (use `address(0)` if unsupported).         |
| `_chainlinkJobId`       | Chainlink job ID (use `bytes32(0)` if unsupported).                         |

### **3. Steps**
1. **Testnet Deployment**:
   - Deploy to **Sepolia/Goerli**.
   - Test bridging, pausing, and emergency withdrawals.

2. **Mainnet Deployment**:
   - Use a **multi-sig wallet** (e.g., Gnosis Safe) for `controller` and `multisig`.
   - Start with a **low fee** (e.g., 0.5%) and increase gradually.
   - **Pause the contract** initially and enable it after verifying parameters.

3. **Post-Deployment**:
   - Publish the contract address/ABI on [Etherscan](https://etherscan.io/) and [DefiLlama](https://defillama.com/).
   - Set up a **bug bounty program**.

---

## **Usage Examples**
### **1. Bridging Tokens**
```solidity
// User bridges 100 USDC to Chain ID 42161 (Arbitrum)
QubeBridge bridge;
bridge.bridge(
    address(USDC),          // Token address
    userAddressOnArbitrum,  // Recipient on Arbitrum
    100 * 1e6,              // Amount (with decimals)
    42161                   // Destination chain ID
);
```


## QubeBridge | To Do Next
Switch to a more Decentralized Bridge approach
with features like:
-Governor DAO Manager along with a Multi-sig Timelock
-On-chain transactions verification
-A cross-chain messaging system no external processor
-and more ...
