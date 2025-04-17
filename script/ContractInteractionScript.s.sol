// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../src/MultisigWallet.sol";
import "../src/Mock.sol";

contract ContractInteractionScript is Script {
    // Anvil's default private keys
    uint256 constant ANVIL_DEPLOYER_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant ANVIL_SIGNER1_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 constant ANVIL_SIGNER2_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant ANVIL_SIGNER3_KEY = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    
    // Contract instances
    MultisigWallet wallet;
    Mock mock;
    
    // Transaction parameters
    uint256 constant FUND_AMOUNT = 5 ether;
    uint256 constant TRANSFER_AMOUNT = 1 ether;
    
    function setUp() public {}

    function run() external {
        // Setup addresses
        address deployer = vm.addr(ANVIL_DEPLOYER_KEY);
        address signer1 = vm.addr(ANVIL_SIGNER1_KEY);
        address signer2 = vm.addr(ANVIL_SIGNER2_KEY);
        address signer3 = vm.addr(ANVIL_SIGNER3_KEY);
        
        console.log("Deploying from:", deployer);
        
        // Deploy contracts
        deployContracts(signer1, signer2, signer3);
        
        // Fund the wallet
        fundWallet();
        
        // Prepare transaction
        bytes32 txHash = prepareTransaction();
        
        // Sign transaction
        signTransaction(txHash);
        
        // Execute transaction
        executeTransaction(txHash, signer1, signer2);
    }
    
    function deployContracts(address signer1, address signer2, address signer3) internal {
        vm.startBroadcast(ANVIL_DEPLOYER_KEY);
        
        // Deploy Mock
        mock = new Mock();
        console.log("Mock deployed to:", address(mock));
        
        // Deploy MultisigWallet
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        uint256 threshold = 2;
        
        wallet = new MultisigWallet(signers, threshold);
        console.log("MultisigWallet deployed to:", address(wallet));
        
        vm.stopBroadcast();
    }
    
    function fundWallet() internal {
        vm.startBroadcast(ANVIL_DEPLOYER_KEY);
        
        (bool success, ) = address(wallet).call{value: FUND_AMOUNT}("");
        require(success, "Funding failed");
        console.log("Funded wallet with", FUND_AMOUNT / 1e18, "ETH");
        
        vm.stopBroadcast();
    }
    
    function prepareTransaction() internal returns (bytes32) {
        vm.startBroadcast(ANVIL_DEPLOYER_KEY);
        
        // Set up transaction
        address target = address(mock);
        bytes memory data = abi.encodeWithSignature("deposit()");
        uint256 nonce = wallet.nonce();
        
        // Calculate hash
        bytes32 txHash = wallet.getTransactionHash(
            target,
            TRANSFER_AMOUNT,
            data,
            nonce
        );
        console.log("Transaction hash:", vm.toString(txHash));
        
        vm.stopBroadcast();
        return txHash;
    }
    
    function signTransaction(bytes32 txHash) internal {
        // Sign with signer1
        vm.startBroadcast(ANVIL_SIGNER1_KEY);
        wallet.signTransaction(txHash);
        console.log("Transaction signed by signer1");
        vm.stopBroadcast();
        
        // Sign with signer2
        vm.startBroadcast(ANVIL_SIGNER2_KEY);
        wallet.signTransaction(txHash);
        console.log("Transaction signed by signer2");
        vm.stopBroadcast();
    }
    
    function executeTransaction(bytes32 txHash, address signer1, address signer2) internal {
        vm.startBroadcast(ANVIL_DEPLOYER_KEY);
        
        // Log initial state
        logInitialState();

         // Check if we have enough signatures
        bool hasEnoughSigs = wallet.hasEnoughSignatures(txHash);
        console.log("Has enough signatures:", hasEnoughSigs);
        
        // Execute transaction
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        console.log("Executing transaction to call deposit() with ETH...");
        wallet.executeTransaction(
            address(mock),
            TRANSFER_AMOUNT,
            abi.encodeWithSignature("deposit()"),
            executionSigners
        );
        
        // Log final state
        logFinalState();
        
        vm.stopBroadcast();
    }
    
    function logInitialState() internal view {
        uint256 initialWalletBalance = address(wallet).balance;
        uint256 initialReceiverBalance = address(mock).balance;
        console.log("Initial wallet balance:", initialWalletBalance / 1e18, "ETH");
        console.log("Initial mock balance:", initialReceiverBalance / 1e18, "ETH");
    }
    
    function logFinalState() internal view {
        uint256 finalWalletBalance = address(wallet).balance;
        uint256 finalReceiverBalance = address(mock).balance;
        console.log("Final wallet balance:", finalWalletBalance / 1e18, "ETH");
        console.log("Final mock balance:", finalReceiverBalance / 1e18, "ETH");
        
        // Check Mock state
        uint256 lastValueReceived = mock.lastValueReceived();
        address lastSender = mock.lastSender();
        console.log("Last value received:", lastValueReceived / 1e18, "ETH");
        console.log("Last sender:", lastSender);
        console.log("Is wallet address:", lastSender == address(wallet));
    }
}