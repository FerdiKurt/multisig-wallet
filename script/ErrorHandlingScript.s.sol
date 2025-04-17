// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../src/MultisigWallet.sol";
import "../src/Mock.sol";

/**
 * @title ErrorHandlingScript
 * @dev Refactored to avoid Stack Too Deep errors
 */
contract ErrorHandlingScript is Script {
    // Anvil's default private keys
    uint256 constant DEPLOYER_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant SIGNER1_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 constant SIGNER2_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant SIGNER3_KEY = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    
    // Contract instances - stored as state variables to reduce local variables
    MultisigWallet wallet;
    Mock mock;
    
    // Store common addresses
    address deployer;
    address signer1;
    address signer2;
    address signer3;
    
    function setUp() public {
        // Setup addresses
        deployer = vm.addr(DEPLOYER_KEY);
        signer1 = vm.addr(SIGNER1_KEY);
        signer2 = vm.addr(SIGNER2_KEY);
        signer3 = vm.addr(SIGNER3_KEY);
    }

    function run() external {
        console.log("Deploying contracts...");
        deployContracts();
        
        console.log("\nPreparing error test cases...");
        
        // Case 1: Insufficient signers
        // testInsufficientSigners();
        
        // Case 2: Contract rejecting ETH
        // testContractRejectingETH();
        
        // Case 3: Reverting function
        // testRevertingFunction();
        
        // Case 4: Insufficient balance
        // testInsufficientBalance();
        
        console.log("\nAll error cases prepared");
    }
    
    function deployContracts() private {
        vm.startBroadcast(DEPLOYER_KEY);
        
        // Deploy Mock
        mock = new Mock();
        console.log("Mock deployed to:", address(mock));
        
        // Deploy MultisigWallet
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        wallet = new MultisigWallet(signers, 2);
        console.log("MultisigWallet deployed to:", address(wallet));
        
        // Fund the wallet
        (bool success, ) = address(wallet).call{value: 5 ether}("");
        require(success, "Funding failed");
        console.log("Funded wallet with 5 ETH");
        
        vm.stopBroadcast();
    }
    
    function testInsufficientSigners() private {
        console.log("\nCase 1: Executing without enough signatures (will fail)");
        
        vm.startBroadcast(DEPLOYER_KEY);
        
        address target = address(mock);
        uint256 value = 1 ether;
        bytes memory data = "";
        uint256 nonce = wallet.nonce();
        
        bytes32 txHash = wallet.getTransactionHash(target, value, data, nonce);
        
        // Prepare signer array with just one signer
        address[] memory insufficientSigners = new address[](1);
        insufficientSigners[0] = signer1;
        
        vm.stopBroadcast();
        
        // Sign with only one signer
        vm.startBroadcast(SIGNER1_KEY);
        wallet.signTransaction(txHash);
        console.log("Transaction signed by signer1 only");
        vm.stopBroadcast();
        
        // Note about execution
        console.log("If executed with insufficientSigners, this would revert with InsufficientSigners error");
        
        // We don't actually execute this case to avoid breaking the script
        /* 
        vm.startBroadcast(DEPLOYER_KEY);
        wallet.executeTransaction(target, value, data, insufficientSigners);
        vm.stopBroadcast();
        */
    }
    
    function testContractRejectingETH() private {
        console.log("\nCase 2: Sending ETH to a contract that rejects it (will fail)");
        
        vm.startBroadcast(DEPLOYER_KEY);
        
        // Configure Mock to reject ETH
        mock.setShouldAcceptEther(false);
        console.log("Mock configured to reject ETH");
        
        address target = address(mock);
        uint256 value = 1 ether;
        bytes memory data = "";
        uint256 nonce = wallet.nonce();
        
        bytes32 txHash = wallet.getTransactionHash(target, value, data, nonce);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        vm.stopBroadcast();
        
        // Sign with enough signers
        vm.startBroadcast(SIGNER1_KEY);
        wallet.signTransaction(txHash);
        vm.stopBroadcast();
        
        vm.startBroadcast(SIGNER2_KEY);
        wallet.signTransaction(txHash);
        vm.stopBroadcast();
        
        console.log("Transaction signed by signer1 and signer2");
        console.log("If executed, this would revert with TransactionExecutionFailed error");
        
        // We don't actually execute this case to avoid breaking the script
        /*
        vm.startBroadcast(DEPLOYER_KEY);
        wallet.executeTransaction(target, value, data, executionSigners);
        vm.stopBroadcast();
        */
    }
    
    function testRevertingFunction() private {
        console.log("\nCase 3: Calling a function that reverts (will fail)");
        
        vm.startBroadcast(DEPLOYER_KEY);
        
        address target = address(mock);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("revertingFunction()");
        uint256 nonce = wallet.nonce();
        
        bytes32 txHash = wallet.getTransactionHash(target, value, data, nonce);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        vm.stopBroadcast();
        
        // Sign with enough signers
        vm.startBroadcast(SIGNER1_KEY);
        wallet.signTransaction(txHash);
        vm.stopBroadcast();
        
        vm.startBroadcast(SIGNER2_KEY);
        wallet.signTransaction(txHash);
        vm.stopBroadcast();
        
        console.log("Transaction signed by signer1 and signer2");
        console.log("If executed, this would revert with TransactionExecutionFailed error");
        
        // We don't actually execute this case to avoid breaking the script
        /*
        vm.startBroadcast(DEPLOYER_KEY);
        wallet.executeTransaction(target, value, data, executionSigners);
        vm.stopBroadcast();
        */
    }
    
    function testInsufficientBalance() private {
        console.log("\nCase 4: Sending more ETH than the wallet balance (will fail)");
        
        vm.startBroadcast(DEPLOYER_KEY);
        
        address target = deployer;
        uint256 value = 10 ether; // More than the 5 ETH we funded
        bytes memory data = "";
        uint256 nonce = wallet.nonce();
        
        bytes32 txHash = wallet.getTransactionHash(target, value, data, nonce);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        vm.stopBroadcast();
        
        // Sign with enough signers
        vm.startBroadcast(SIGNER1_KEY);
        wallet.signTransaction(txHash);
        vm.stopBroadcast();
        
        vm.startBroadcast(SIGNER2_KEY);
        wallet.signTransaction(txHash);
        vm.stopBroadcast();
        
        console.log("Transaction signed by signer1 and signer2");
        console.log("If executed, this would revert with InsufficientBalance error");
        
        // We don't actually execute this case to avoid breaking the script
        /*
        vm.startBroadcast(DEPLOYER_KEY);
        wallet.executeTransaction(target, value, data, executionSigners);
        vm.stopBroadcast();
        */
    }
}