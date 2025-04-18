# MultisigWallet

A Solidity implementation of a k-of-n multisignature wallet that allows execution of arbitrary transactions when enough signers approve.

## Features

- **K-of-N Signature Scheme**: Configurable threshold of required signatures
- **Arbitrary Execution**: Call any function on any contract with any parameters
- **Signer Management**: Add or remove signers with existing signers' approval
- **ETH Handling**: Send and receive ETH
- **Replay Protection**: Nonce-based transaction uniqueness

## Usage

### Setup

```solidity
// Deploy with initial signers and threshold
address[] memory signers = [address1, address2, address3];
uint256 threshold = 2; // Require 2-of-3 signatures
MultisigWallet wallet = new MultisigWallet(signers, threshold);
```

### Execute Transactions

```solidity
// 1. Calculate transaction hash
bytes32 txHash = wallet.getTransactionHash(targetAddress, value, data, wallet.nonce());

// 2. Sign by multiple signers
wallet.signTransaction(txHash); // Called by each signer

// 3. Execute when enough signatures collected
wallet.executeTransaction(targetAddress, value, data, [signer1, signer2]);
```

### Update Signers

```solidity
// Update signer set with approval from current signers
address[] memory newSigners = [address1, address4, address5];
uint256 newThreshold = 2;
wallet.updateSigners(newSigners, newThreshold, [signer1, signer2]);
```

## Security Features

- Reentrancy protection
- Duplicate signer prevention
- Transaction replay protection

# MultisigWallet Tests

## Setup

Tests use Foundry's testing framework. Make sure you have installed:
- [Foundry](https://getfoundry.sh/)

## Running Tests

```bash
# Run all tests
forge test

# Run with verbose output
forge test -vv

# Run specific test function
forge test --match-test testSendEtherToContract -vv
```

## Test Categories

The test suite covers the following functional areas:

1. **Deployment Tests**
   - Verify signers are set correctly
   - Verify threshold value is correct
   - Test invalid deployment scenarios

2. **Transaction Signing Tests**
   - Test signing functionality
   - Verify only authorized signers can sign
   - Test prevention of double-signing

3. **Transaction Execution Tests**
   - Test ETH transfers to contracts
   - Test ETH transfers to EOAs
   - Test contract method calls with parameters
   - Test error conditions (reverts, insufficient signatures)

4. **Signer Management Tests**
   - Test adding new signers
   - Test removing existing signers
   - Test changing threshold
   - Test invalid signer updates

## Mock Contract

Tests use a Mock contract to simulate external contract interactions, which provides:
- Functions to receive ETH
- Functions that can be called by the wallet
- Functions that intentionally revert
- State variables to verify interactions

## Key Test Functions

- `testSendEtherToContract` - Tests sending ETH to a contract
- `testSendEtherToContractWithFunction` - Tests sending ETH while calling a function
- `testSendEtherToEOA` - Tests sending ETH to an externally owned account
- `testUpdateSigners` - Tests updating the set of signers
- `testExecuteTransactionEmitsEvent` - Tests proper event emission

# MultisigWallet Scripts

This collection of scripts demonstrates how to interact with the MultisigWallet contract using Foundry's Forge scripting system. These scripts provide examples of common operations and use cases for a k-of-n multisignature wallet.

## Prerequisites

- [Foundry](https://getfoundry.sh/) installed
- Local Anvil node running
- The MultisigWallet and Mock contracts deployed

## Setup

1. Install Foundry:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

2. Start Anvil in a separate terminal:
```bash
anvil
```

3. Install dependencies:
```bash
forge install foundry-rs/forge-std
```

## Available Scripts

### 1. Basic ETH Transfer (`BasicEthTransfer.s.sol`)

Demonstrates a simple ETH transfer from the multisig wallet to a recipient.

```bash
forge script script/BasicEthTransfer.s.sol --rpc-url http://localhost:8545 --broadcast --private-key PK
```

Features:
- Deploys the MultisigWallet contract
- Funds the wallet with ETH
- Signs a transaction with multiple signers
- Executes an ETH transfer to a recipient

### 2. Contract Interaction (`ContractInteraction.s.sol`)

Shows how to call a function on another contract through the multisig wallet.

```bash
forge script script/ContractInteraction.s.sol --rpc-url http://localhost:8545 --broadcast --private-key PK
```

Features:
- Deploys the Mock contract
- Calls the Mock's deposit function with ETH
- Verifies the state changes in the receiver contract


### 3. Update Signers (`UpdateSigners.s.sol`)

Demonstrates changing the set of authorized signers.

```bash
forge script script/UpdateSigners.s.sol --rpc-url http://localhost:8545 --broadcast --private-key PK
```

Features:
- Adds new signers and removes existing ones
- Changes the threshold value
- Verifies the updated signer set

### 4. Error Handling (`ErrorHandling.s.sol`)

Shows common error cases and how they're handled.

```bash
forge script script/ErrorHandling.s.sol --rpc-url http://localhost:8545 --broadcast --private-key PK
```

Features:
- Tests insufficient signers scenario
- Demonstrates contract rejecting ETH
- Shows function call reverts
- Tests insufficient balance conditions

Note: This script doesn't actually execute the failing transactions (to avoid script termination). Uncomment the execution blocks to see each error case in action.

### 5. Set Specific Value (`SetValue.s.sol`)

Shows calling a function with a specific parameter value.

```bash
forge script script/SetValue.s.sol --rpc-url http://localhost:8545 --broadcast --private-key PK
```

Features:
- Calls the setValue function with the value 1907
- Verifies the value was set correctly in the target contract

## Script Structure

Each script follows a similar structure:

1. **Setup Phase**: Sets up variables, addresses, and contracts
2. **Transaction Preparation**: Creates and prepares the transaction(s) to execute
3. **Signing Phase**: Signs the transaction with authorized signers
4. **Execution Phase**: Executes the transaction through the multisig wallet
5. **Verification Phase**: Verifies the transaction had the expected effect

## Troubleshooting

1. **Stack too deep error**:
   If you encounter this error, break down functions into smaller ones or use memory instead of storage for complex data structures.

2. **Transaction reverts**:
   - Check the function signature and parameters
   - Ensure enough signers have signed the transaction
   - Verify the wallet has sufficient funds for ETH transfers

3. **Nonce issues**:
   - Make sure you're using the correct nonce for each transaction
   - Remember the nonce increments after each successful transaction

4. **Script fails to broadcast**:
   - Ensure Anvil is running
   - Check that you're using the correct RPC URL
   - Verify you're using the correct private keys
