// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../src/MultisigWallet.sol";

contract UpdateSignersScript is Script {
    // Anvil's default private keys
    uint256 constant DEPLOYER_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant SIGNER1_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 constant SIGNER2_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant SIGNER3_KEY = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    uint256 constant NEW_SIGNER4_KEY = 0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a;
    uint256 constant NEW_SIGNER5_KEY = 0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba;
    
    // Contract instance
    MultisigWallet wallet;
    
    // Addresses
    address deployer;
    address signer1;
    address signer2;
    address signer3;
    address newSigner4;
    address newSigner5;
    
    // Signer arrays
    address[] initialSigners;
    address[] newSigners;
    
    function setUp() public {
        // Setup addresses
        deployer = vm.addr(DEPLOYER_KEY);
        signer1 = vm.addr(SIGNER1_KEY);
        signer2 = vm.addr(SIGNER2_KEY);
        signer3 = vm.addr(SIGNER3_KEY);
        newSigner4 = vm.addr(NEW_SIGNER4_KEY);
        newSigner5 = vm.addr(NEW_SIGNER5_KEY);
    }

    function run() external {
        // Log initial signers
        logInitialSetup();
        
        // Deploy the wallet
        deployWallet();
        
        // Prepare the update
        bytes32 updateHash = prepareUpdate();
        
        // Sign the update
        signUpdate(updateHash);
        
        // Execute the update
        executeUpdate();
        
        // Verify the new signer set
        verifyNewSigners();
    }
    
    function logInitialSetup() internal view{
        console.log("Initial signers:");
        console.log("Signer 1:", signer1);
        console.log("Signer 2:", signer2);
        console.log("Signer 3:", signer3);
        
        console.log("New signers to add:");
        console.log("New signer 4:", newSigner4);
        console.log("New signer 5:", newSigner5);
    }
    
    function deployWallet() internal {
        vm.startBroadcast(DEPLOYER_KEY);
        
        // Deploy the MultisigWallet contract
        initialSigners = new address[](3);
        initialSigners[0] = signer1;
        initialSigners[1] = signer2;
        initialSigners[2] = signer3;
        uint256 initialThreshold = 2;
        
        wallet = new MultisigWallet(initialSigners, initialThreshold);
        console.log("MultisigWallet deployed to:", address(wallet));
        console.log("Initial threshold:", initialThreshold);
        
        vm.stopBroadcast();
    }
    
    function prepareUpdate() internal returns (bytes32) {
        vm.startBroadcast(DEPLOYER_KEY);
        
        // Create new signers array (add new signers, remove one)
        newSigners = new address[](4);
        newSigners[0] = signer1;
        newSigners[1] = signer2; 
        newSigners[2] = newSigner4; // New signer
        newSigners[3] = newSigner5; // New signer
        uint256 newThreshold = 3;
        
        console.log("New signers:");
        console.log("- Signer 1:", signer1);
        console.log("- Signer 2:", signer2);
        console.log("- New signer 4:", newSigner4);
        console.log("- New signer 5:", newSigner5);
        console.log("New threshold:", newThreshold);
        
        // Get the nonce
        uint256 nonce = wallet.nonce();
        
        // Calculate update hash
        bytes32 updateHash = keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            newSigners,
            newThreshold,
            nonce
        ));
        console.log("Update hash:", vm.toString(updateHash));
        
        vm.stopBroadcast();
        return updateHash;
    }
    
    function signUpdate(bytes32 updateHash) internal {
        // Sign with signer1
        vm.startBroadcast(SIGNER1_KEY);
        wallet.signTransaction(updateHash);
        console.log("Update signed by signer1");
        vm.stopBroadcast();
        
        // Sign with signer2
        vm.startBroadcast(SIGNER2_KEY);
        wallet.signTransaction(updateHash);
        console.log("Update signed by signer2");
        vm.stopBroadcast();
    }
    
    function executeUpdate() internal {
        vm.startBroadcast(DEPLOYER_KEY);
        
        // Execute the update
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        console.log("Updating signers...");
        wallet.updateSigners(
            newSigners,
            3, // New threshold
            executionSigners
        );
        console.log("Signers updated successfully");
        
        vm.stopBroadcast();
    }
    
    function verifyNewSigners() internal {
        vm.startBroadcast(DEPLOYER_KEY);
        
        // Verify the new signer set
        uint256 signerCount = wallet.getSignerCount();
        console.log("New signer count:", signerCount);
        
        // Check each signer's status
        console.log("Signer authorization status:");
        console.log("- Signer 1:", wallet.isAuthorizedSigner(signer1));
        console.log("- Signer 2:", wallet.isAuthorizedSigner(signer2));
        console.log("- Signer 3:", wallet.isAuthorizedSigner(signer3)); // Should be false
        console.log("- New signer 4:", wallet.isAuthorizedSigner(newSigner4));
        console.log("- New signer 5:", wallet.isAuthorizedSigner(newSigner5));
        
        // Check the new threshold
        console.log("New threshold value:", wallet.threshold());
        
        // Verify nonce was incremented
        console.log("New nonce value:", wallet.nonce());
        
        vm.stopBroadcast();
    }
}