// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import "../src/MultisigWallet.sol";
import "../src/Mock.sol";

/**
 * @title SetValueScript
 * @dev Demonstrates calling setValue(uint256) with parameter 1907 through the multisig wallet
 */
contract SetValueScript is Script {
    // Anvil's default private keys
    uint256 constant DEPLOYER_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant SIGNER1_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 constant SIGNER2_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant SIGNER3_KEY = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    
    // Contract instances
    MultisigWallet wallet;
    Mock mock;
    
    // Store addresses
    address deployer;
    address signer1;
    address signer2;
    address signer3;
    
    // The specific value we want to set
    uint256 constant SPECIFIC_VALUE = 1907;
    
    function setUp() public {
        // Setup addresses
        deployer = vm.addr(DEPLOYER_KEY);
        signer1 = vm.addr(SIGNER1_KEY);
        signer2 = vm.addr(SIGNER2_KEY);
        signer3 = vm.addr(SIGNER3_KEY);
    }

    function run() external {
        console.log("Running SetValue Script with parameter:", SPECIFIC_VALUE);
        
        // Deploy contracts
        deployContracts();
        
        // Encode the specific call to setValue with 1907
        bytes32 txHash = prepareSetValueCall();
        
        // Sign the transaction
        signTransaction(txHash);
        
        // Execute the transaction
        executeTransaction(txHash);
        
        // Verify the value was set correctly
        verifyValueWasSet();
    }
    
    function deployContracts() private {
        vm.startBroadcast(DEPLOYER_KEY);
        
        // Deploy Mock
        mock = new Mock();
        console.log("Mock deployed to:", address(mock));
        
        // Log initial value
        console.log("Initial value in Mock:", mock.value());
        
        // Deploy MultisigWallet
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        wallet = new MultisigWallet(signers, 2);
        console.log("MultisigWallet deployed to:", address(wallet));
        
        // Fund the wallet
        (bool success, ) = address(wallet).call{value: 1 ether}("");
        require(success, "Funding failed");
        console.log("Funded wallet with 1 ETH");
        
        vm.stopBroadcast();
    }
    
    function prepareSetValueCall() private returns (bytes32) {
        vm.startBroadcast(DEPLOYER_KEY);
        
        // Encode the function call for setValue(1907)
        address target = address(mock);
        uint256 value = 0; // No ETH is being sent
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", SPECIFIC_VALUE);
        uint256 nonce = wallet.nonce();
        
        // Calculate transaction hash
        bytes32 txHash = wallet.getTransactionHash(target, value, data, nonce);
        console.log("\nPrepared transaction to call setValue(", SPECIFIC_VALUE, ")");
        console.log("Transaction hash:", vm.toString(txHash));
        
        vm.stopBroadcast();
        return txHash;
    }
    
    function signTransaction(bytes32 txHash) private {
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
    
    function executeTransaction(bytes32 txHash) private {
        vm.startBroadcast(DEPLOYER_KEY);

        // Check if we have enough signatures
        bool hasEnoughSigs = wallet.hasEnoughSignatures(txHash);
        console.log("Has enough signatures:", hasEnoughSigs);
        
        // Prepare execution parameters
        address target = address(mock);
        uint256 value = 0; // No ETH is being sent
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", SPECIFIC_VALUE);
        
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        console.log("\nExecuting transaction to call setValue(", SPECIFIC_VALUE, ")...");
        wallet.executeTransaction(
            target,
            value,
            data,
            executionSigners
        );
        console.log("Transaction executed successfully!");
        
        vm.stopBroadcast();
    }
    
    function verifyValueWasSet() private {
        vm.startBroadcast(DEPLOYER_KEY);
        
        uint256 newValue = mock.value();
        console.log("\nVerifying Mock's value:");
        console.log("Current value:", newValue);
        
        if (newValue == SPECIFIC_VALUE) {
            console.log("Value was correctly set to", SPECIFIC_VALUE);
        } else {
            console.log("Value was not set correctly!");
            console.log("Expected:", SPECIFIC_VALUE);
            console.log("Actual:", newValue);
        }
        
        vm.stopBroadcast();
    }
}