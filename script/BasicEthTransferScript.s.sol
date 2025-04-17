// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../src/MultisigWallet.sol";

contract BasicEthTransferScript is Script {
    // Anvil's first default private key
    uint256 constant ANVIL_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant SIGNER1_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 constant SIGNER2_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant SIGNER3_KEY = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    uint256 constant RECIPIENT_KEY = 0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a;
    
    // Contract instances
    MultisigWallet wallet;
    
    function setUp() public {
        // No setup needed
    }

    function run() external {
        // Setup addresses
        address deployer = vm.addr(ANVIL_PRIVATE_KEY); // 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
        address signer1 = vm.addr(SIGNER1_KEY);
        address signer2 = vm.addr(SIGNER2_KEY);
        address signer3 = vm.addr(SIGNER3_KEY);
        address recipient = vm.addr(RECIPIENT_KEY);
        
        // Log information
        console.log("Deploying from:", deployer);
        console.log("Signers:", signer1, signer2, signer3);
        console.log("Recipient:", recipient);
        
        // Deploy wallet
        deployWallet(signer1, signer2, signer3);
        
        // Fund wallet
        fundWallet();
        
        // Prepare transaction
        bytes32 txHash = prepareTransaction(recipient);
        
        // Sign transaction
        signTransaction(txHash);
        
        // Execute transaction
        executeTransaction(recipient, txHash, signer1, signer2);
    }
    
    function deployWallet(address signer1, address signer2, address signer3) internal {
        vm.startBroadcast(ANVIL_PRIVATE_KEY);
        
        // Deploy the MultisigWallet contract
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        uint256 threshold = 2;
        
        // Log the deployment information
        wallet = new MultisigWallet(signers, threshold);
        console.log("MultisigWallet deployed to:", address(wallet));
        console.log("Number of signers:", wallet.getSignerCount());
        console.log("Threshold:", wallet.threshold());
        
        vm.stopBroadcast();
    }
    
    function fundWallet() internal {
        vm.startBroadcast(ANVIL_PRIVATE_KEY);
        
        uint256 fundAmount = 5 ether;
        (bool success, ) = address(wallet).call{value: fundAmount}("");
        require(success, "Funding failed");
        console.log("Funded wallet with", fundAmount / 1e18, "ETH");
        
        vm.stopBroadcast();
    }
    
    function prepareTransaction(address recipient) internal returns (bytes32) {
        vm.startBroadcast(ANVIL_PRIVATE_KEY);
        
        // Set up the transaction to send ETH to recipient
        uint256 transferAmount = 1 ether;
        address target = recipient;
        bytes memory data = ""; // Empty data for simple ETH transfer
        uint256 nonce = wallet.nonce();
        
        // Calculate transaction hash
        bytes32 txHash = wallet.getTransactionHash(
            target,
            transferAmount,
            data,
            nonce
        );
        console.log("Transaction hash:", vm.toString(txHash));
        
        vm.stopBroadcast();
        
        return txHash;
    }
    
    function signTransaction(bytes32 txHash) internal {
        // Sign with signer1
        vm.startBroadcast(SIGNER1_KEY);
        wallet.signTransaction(txHash);
        console.log("Transaction signed by signer1");
        vm.stopBroadcast();
        
        // Sign with signer2
        vm.startBroadcast(SIGNER2_KEY);
        wallet.signTransaction(txHash);
        console.log("Transaction signed by signer2");
        vm.stopBroadcast();
    }
    
    function executeTransaction(address recipient, bytes32 txHash, address signer1, address signer2) internal {
        vm.startBroadcast(ANVIL_PRIVATE_KEY);
        
        // Check if we have enough signatures
        bool hasEnoughSigs = wallet.hasEnoughSignatures(txHash);
        console.log("Has enough signatures:", hasEnoughSigs);
        
        // Log initial balances
        uint256 initialWalletBalance = address(wallet).balance;
        uint256 initialRecipientBalance = recipient.balance;
        console.log("Initial wallet balance:", initialWalletBalance / 1e18, "ETH");
        console.log("Initial recipient balance:", initialRecipientBalance / 1e18, "ETH");
        
        // Execute the transaction
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        console.log("Executing transaction...");
        uint256 transferAmount = 1 ether;
        wallet.executeTransaction(
            recipient,
            transferAmount,
            "",
            executionSigners
        );
        
        // Log final balances
        uint256 finalWalletBalance = address(wallet).balance;
        uint256 finalRecipientBalance = recipient.balance;
        console.log("Final wallet balance:", finalWalletBalance / 1e18, "ETH");
        console.log("Final recipient balance:", finalRecipientBalance / 1e18, "ETH");
        console.log("ETH transferred:", (finalRecipientBalance - initialRecipientBalance) / 1e18, "ETH");
        
        // Verify nonce was incremented
        uint256 newNonce = wallet.nonce();
        console.log("New nonce:", newNonce);
        
        vm.stopBroadcast();
    }
}