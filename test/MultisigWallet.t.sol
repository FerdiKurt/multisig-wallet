// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/MultisigWallet.sol";
import "../src/Mock.sol";

contract MultisigWalletTest is Test {
    MultisigWallet public wallet;
    Mock public mockContract;
    
    address[] public signers;
    uint256 public constant THRESHOLD = 2; // k of n
    
    address public owner;
    address public signer1;
    address public signer2;
    address public signer3;
    address public nonSigner;
    
    function setUp() public {
        // Setup addresses
        owner = address(this);
        signer1 = address(0x1);
        signer2 = address(0x2);
        signer3 = address(0x3);
        nonSigner = address(0x4);
        
        // Setup signers array
        signers.push(signer1);
        signers.push(signer2);
        signers.push(signer3);
        
        // Deploy mock contract
        mockContract = new Mock();
        
        // Deploy multisig wallet
        wallet = new MultisigWallet(signers, THRESHOLD);
        
        // Fund the wallet with some ETH for tests
        vm.deal(address(wallet), 10 ether);
    }
    
    // ============ Deployment Tests ============
    
    function testCorrectSigners() public view {
        for (uint256 i = 0; i < signers.length; i++) {
            assertEq(wallet.signers(i), signers[i]);
            assertTrue(wallet.isAuthorizedSigner(signers[i]));
        }
        
        assertEq(wallet.getSignerCount(), signers.length);
    }
    
    function testCorrectThreshold() public view {
        assertEq(wallet.threshold(), THRESHOLD);
    }
    
    function testNonSignerNotAuthorized() public view {
        assertFalse(wallet.isAuthorizedSigner(nonSigner));
    }
    
    function testRevertDeployWithInvalidThresholdZero() public {
        address[] memory testSigners = new address[](3);
        testSigners[0] = signer1;
        testSigners[1] = signer2;
        testSigners[2] = signer3;

        vm.expectRevert(MultisigWallet.InvalidThreshold.selector);
        new MultisigWallet(testSigners, 0); // Should fail with InvalidThreshold
    }
    
    function testDeployWithInvalidThresholdTooHigh() public {
        address[] memory testSigners = new address[](3);
        testSigners[0] = signer1;
        testSigners[1] = signer2;
        testSigners[2] = signer3;
        
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.InvalidThreshold.selector));
        new MultisigWallet(testSigners, 4); // Should fail with InvalidThreshold
    }
    
    function testDeployWithNoSigners() public {
        address[] memory testSigners = new address[](0);
        
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.NoSignersProvided.selector));
        new MultisigWallet(testSigners, 1); // Should fail with NoSignersProvided
    }
    
    function testDeployWithDuplicateSigners() public {
        address[] memory testSigners = new address[](2);
        testSigners[0] = signer1;
        testSigners[1] = signer1; // Duplicate
        
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.DuplicateSigner.selector));
        new MultisigWallet(testSigners, 1); // Should fail with DuplicateSigner
    }
    
    function testDeployWithZeroAddressSigner() public {
        address[] memory testSigners = new address[](2);
        testSigners[0] = signer1;
        testSigners[1] = address(0); // Zero address
        
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.InvalidSignerAddress.selector));
        new MultisigWallet(testSigners, 1); // Should fail with InvalidSignerAddress
    }
    
    // ============ Transaction Signing Tests ============
    
    function testSignTransaction() public {
        bytes32 txHash = _createTestTxHash();
        
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        assertTrue(wallet.signed(txHash, signer1));
    }
    
    function testSignTransactionEmitsEvent() public {
        bytes32 txHash = _createTestTxHash();
        
        vm.expectEmit(true, true, false, true);
        emit TransactionSigned(txHash, signer1);
        
        vm.prank(signer1);
        wallet.signTransaction(txHash);
    }
    
    function testNonSignerCannotSign() public {
        bytes32 txHash = _createTestTxHash();
        
        vm.prank(nonSigner);
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.NotAuthorizedSigner.selector));
        wallet.signTransaction(txHash);
    }
    
    function testCannotDoubleSign() public {
        bytes32 txHash = _createTestTxHash();
        
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer1);
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.AlreadySigned.selector));
        wallet.signTransaction(txHash);
    }
    
    function testHasEnoughSignatures() public {
        bytes32 txHash = _createTestTxHash();
        
        // Initially no signatures
        assertFalse(wallet.hasEnoughSignatures(txHash));
        
        // One signature (less than threshold)
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        assertFalse(wallet.hasEnoughSignatures(txHash));
        
        // Two signatures (equal to threshold)
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        assertTrue(wallet.hasEnoughSignatures(txHash));
    }
    
    // ============ Transaction Execution Tests ============
    
  function testSendEtherToContract() public {
        // Setup transaction
        address target = address(mockContract);
        uint256 value = 1 ether;
        bytes memory data = ""; // Empty data for a simple ETH transfer
        
        // Create and sign transaction
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Check initial balances
        uint256 initialWalletBalance = address(wallet).balance;
        uint256 initialReceiverBalance = address(mockContract).balance;
        
        // Execute the transaction
        wallet.executeTransaction(target, value, data, executionSigners);
        
        // Verify balances after transfer
        assertEq(address(wallet).balance, initialWalletBalance - value, "Wallet balance not decreased correctly");
        assertEq(address(mockContract).balance, initialReceiverBalance + value, "Receiver balance not increased correctly");
        assertEq(mockContract.lastValueReceived(), value, "Received value not tracked correctly");
        assertEq(mockContract.lastSender(), address(wallet), "Sender not tracked correctly");
    }

      // Test sending ETH to a contract with a specific function
    function testSendEtherToContractWithFunction() public {
        // Setup transaction to call the deposit function with ETH
        address target = address(mockContract);
        uint256 value = 1 ether;
        bytes memory data = abi.encodeWithSignature("deposit()");
        
        // Create and sign transaction
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Check initial balances
        uint256 initialWalletBalance = address(wallet).balance;
        uint256 initialReceiverBalance = address(mockContract).balance;
        
        // Execute the transaction
        wallet.executeTransaction(target, value, data, executionSigners);
        
        // Verify balances after transfer
        assertEq(address(wallet).balance, initialWalletBalance - value, "Wallet balance not decreased correctly");
        assertEq(address(mockContract).balance, initialReceiverBalance + value, "Receiver balance not increased correctly");
        assertEq(mockContract.lastValueReceived(), value, "Received value not tracked correctly");
        assertEq(mockContract.lastSender(), address(wallet), "Sender not tracked correctly");
    }

      // Test sending ETH to a contract that rejects ETH
    function testRevertSendEtherToRejectingContract() public {
        // Configure the test receiver to reject ETH
        mockContract.setShouldAcceptEther(false);
        
        // Setup transaction
        address target = address(mockContract);
        uint256 value = 1 ether;
        bytes memory data = ""; // Empty data for a simple ETH transfer
        
        // Create and sign transaction
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Execute the transaction - should revert
        vm.expectRevert();
        wallet.executeTransaction(target, value, data, executionSigners);
    }


    // Test sending ETH to an EOA (Externally Owned Account)
    function testSendEtherToEOA() public {
        // Setup transaction to send ETH to an EOA
        address target = address(0x5); // Some EOA address
        uint256 value = 1 ether;
        bytes memory data = ""; // Empty data for a simple ETH transfer
        
        // Fund the wallet explicitly
        vm.deal(address(wallet), 10 ether);
        
        // Create and sign transaction
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Check initial balances
        uint256 initialWalletBalance = address(wallet).balance;
        uint256 initialTargetBalance = address(target).balance;
        
        // Execute the transaction
        wallet.executeTransaction(target, value, data, executionSigners);
        
        // Verify balances after transfer
        assertEq(address(wallet).balance, initialWalletBalance - value, "Wallet balance not decreased correctly");
        assertEq(address(target).balance, initialTargetBalance + value, "Target balance not increased correctly");
    }


    // Test executing a failing function (not ETH transfer related)
    function testRevertExecuteRevertingFunction() public {
        // Setup transaction to call a function that will revert
        address target = address(mockContract);
        uint256 value = 0; // No ETH
        bytes memory data = abi.encodeWithSignature("revertingFunction()");
        
        // Create and sign transaction
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Execute the transaction - should revert
        vm.expectRevert();
        wallet.executeTransaction(target, value, data, executionSigners);
    }
    
    function testExecuteTransactionEmitsEvent() public {
        // Setup transaction
        address target = address(mockContract);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 123);
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        // Sign transaction
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Expect event
        vm.expectEmit(true, true, false, true);
        emit TransactionExecuted(txHash, target, value, data);
        
        // Execute transaction
        wallet.executeTransaction(target, value, data, executionSigners);
    }
    
    function testIncrementsNonceAfterExecution() public {
        // Setup transaction
        address target = address(mockContract);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 123);
        uint256 initialNonce = wallet.nonce();
        bytes32 txHash = wallet.getTransactionHash(target, value, data, initialNonce);
        
        // Sign transaction
        vm.startPrank(signer1);
        wallet.signTransaction(txHash);
        vm.stopPrank();
        
        vm.startPrank(signer2);
        wallet.signTransaction(txHash);
        vm.stopPrank();
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Execute transaction
        wallet.executeTransaction(target, value, data, executionSigners);
        
        // Verify nonce increment
        assertEq(wallet.nonce(), initialNonce + 1);
    }
    
    function testMarksTransactionAsExecuted() public {
        // Setup and execute transaction
        address target = address(mockContract);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 123);
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        // Sign transaction
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Execute transaction
        wallet.executeTransaction(target, value, data, executionSigners);
        
        // Verify transaction marked as executed
        assertTrue(wallet.executed(txHash));
    }
    
    function testCannotExecuteWithInsufficientSigners() public {
        // Setup transaction
        address target = address(mockContract);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 123);
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        // Sign transaction with only one signer
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        // Prepare signers array with just one signer
        address[] memory executionSigners = new address[](1);
        executionSigners[0] = signer1;
        
        // Attempt execution
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.InsufficientSigners.selector));
        wallet.executeTransaction(target, value, data, executionSigners);
    }
    
    function testCannotExecuteWithInvalidSigners() public {
        // Setup transaction
        address target = address(mockContract);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 123);
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        // Sign transaction
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        // Prepare signers array with one valid and one invalid signer
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = nonSigner;
        
        // Attempt execution
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.NotEnoughValidSignatures.selector));
        wallet.executeTransaction(target, value, data, executionSigners);
    }
    
    function testCannotExecuteWithZeroTargetAddress() public {
        // Setup transaction
        address target = address(0);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 123);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Attempt execution
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.InvalidTargetAddress.selector));
        wallet.executeTransaction(target, value, data, executionSigners);
    }
    
    function testCannotExecuteSameTransactionTwice() public {
        // Setup transaction
        address target = address(mockContract);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 123);
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        // Sign transaction
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        
        // Prepare signers array
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;
        
        // Execute transaction first time
        wallet.executeTransaction(target, value, data, executionSigners);
        
        // Attempt to execute same transaction again
        vm.expectRevert(); // TransactionAlreadyExecuted
        wallet.executeTransaction(target, value, data, executionSigners);
    }
    
    // ============ Signer Management Tests ============
    
    function testUpdateSigners() public {
        // Setup new signers and threshold
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = nonSigner; // Adding nonSigner, removing signer3
        uint256 newThreshold = 2;
        
        // Get update hash
        bytes32 updateHash = keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            newSigners,
            newThreshold,
            wallet.nonce()
        ));
        
        // Sign the update
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        vm.prank(signer2);
        wallet.signTransaction(updateHash);
        
        // Prepare signers array for update
        address[] memory updateSigners = new address[](2);
        updateSigners[0] = signer1;
        updateSigners[1] = signer2;
        
        // Execute update
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
        
        // Verify signer changes
        assertEq(wallet.getSignerCount(), newSigners.length);
        assertTrue(wallet.isAuthorizedSigner(signer1));
        assertTrue(wallet.isAuthorizedSigner(signer2));
        assertTrue(wallet.isAuthorizedSigner(nonSigner));
        assertFalse(wallet.isAuthorizedSigner(signer3));
    }
    
    function testUpdateSignersEmitsEvents() public {
        // Setup new signers and threshold
        address[] memory newSigners = new address[](2);
        newSigners[0] = signer1;
        newSigners[1] = nonSigner; // Adding nonSigner, removing signer2 and signer3
        uint256 newThreshold = 1;
        
        // Get update hash
        bytes32 updateHash = keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            newSigners,
            newThreshold,
            wallet.nonce()
        ));
        
        // Sign the update
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        vm.prank(signer2);
        wallet.signTransaction(updateHash);
        
        // Prepare signers array for update
        address[] memory updateSigners = new address[](2);
        updateSigners[0] = signer1;
        updateSigners[1] = signer2;
        
        // Expect events
        vm.expectEmit(true, false, false, true);
        emit SignerRemoved(signer1); // Will be removed first, then added back
        
        vm.expectEmit(true, false, false, true);
        emit SignerRemoved(signer2);
        
        vm.expectEmit(true, false, false, true);
        emit SignerRemoved(signer3);
        
        vm.expectEmit(true, false, false, true);
        emit SignerAdded(signer1);
        
        vm.expectEmit(true, false, false, true);
        emit SignerAdded(nonSigner);
        
        vm.expectEmit(false, false, false, true);
        emit ThresholdChanged(newThreshold);
        
        // Execute update
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
    }
    
    function testUpdateSignersIncrementsNonce() public {
        // Setup new signers and threshold
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = nonSigner;
        uint256 newThreshold = 2;
        
        uint256 initialNonce = wallet.nonce();
        
        // Get update hash
        bytes32 updateHash = keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            newSigners,
            newThreshold,
            initialNonce
        ));
        
        // Sign the update
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        vm.prank(signer2);
        wallet.signTransaction(updateHash);
        
        // Prepare signers array for update
        address[] memory updateSigners = new address[](2);
        updateSigners[0] = signer1;
        updateSigners[1] = signer2;
        
        // Execute update
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
        
        // Verify nonce incremented
        assertEq(wallet.nonce(), initialNonce + 1);
    }
    
    function testCannotUpdateWithInsufficientSigners() public {
        // Setup new signers and threshold
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = nonSigner;
        uint256 newThreshold = 2;
        
        // Get update hash
        bytes32 updateHash = keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            newSigners,
            newThreshold,
            wallet.nonce()
        ));
        
        // Sign with only one signer
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        // Prepare signers array with only one signer
        address[] memory updateSigners = new address[](1);
        updateSigners[0] = signer1;
        
        // Attempt update
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.InsufficientSigners.selector));
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
    }
    
    function testCannotUpdateWithInvalidSigners() public {
        // Setup new signers and threshold
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = nonSigner;
        uint256 newThreshold = 2;
        
        // Get update hash
        bytes32 updateHash = keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            newSigners,
            newThreshold,
            wallet.nonce()
        ));
        
        // Sign with only one valid signer
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        // Prepare signers array with one valid and one invalid signer
        address[] memory updateSigners = new address[](2);
        updateSigners[0] = signer1;
        updateSigners[1] = nonSigner;
        
        // Attempt update
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.NotEnoughValidSignatures.selector));
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
    }
    
    function testCannotUpdateWithZeroThreshold() public {
        // Setup new signers and threshold
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = nonSigner;
        uint256 newThreshold = 0; // Invalid threshold
        
        // Prepare signers array
        address[] memory updateSigners = new address[](2);
        updateSigners[0] = signer1;
        updateSigners[1] = signer2;
        
        // Attempt update
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.InvalidThreshold.selector));
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
    }
    
    function testCannotUpdateWithThresholdTooHigh() public {
        // Setup new signers and threshold
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = nonSigner;
        uint256 newThreshold = 4; // Higher than number of signers
        
        // Prepare signers array
        address[] memory updateSigners = new address[](2);
        updateSigners[0] = signer1;
        updateSigners[1] = signer2;
        
        // Attempt update
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.InvalidThreshold.selector));
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
    }
    
    function testCannotUpdateWithDuplicateSigners() public {
        // Setup new signers with duplicate
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = signer1; // Duplicate
        uint256 newThreshold = 2;

        // Get update hash
        bytes32 updateHash = keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            newSigners,
            newThreshold,
            wallet.nonce()
        ));
        
        // Sign the update
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        vm.prank(signer2);
        wallet.signTransaction(updateHash);
        
        // Prepare signers array
        address[] memory updateSigners = new address[](2);
        updateSigners[0] = signer1;
        updateSigners[1] = signer2;
        
        // Attempt update
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.DuplicateSigner.selector));
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
    }
    
    function testCannotUpdateWithZeroAddressSigner() public {
        // Setup new signers with zero address
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = address(0); // Zero address
        uint256 newThreshold = 2;

          // Get update hash
        bytes32 updateHash = keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            newSigners,
            newThreshold,
            wallet.nonce()
        ));
        
        // Sign the update
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        vm.prank(signer2);
        wallet.signTransaction(updateHash);
        
        // Prepare signers array
        address[] memory updateSigners = new address[](2);
        updateSigners[0] = signer1;
        updateSigners[1] = signer2;
        
        // Attempt update
        vm.expectRevert(abi.encodeWithSelector(MultisigWallet.InvalidSignerAddress.selector));
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
    }
    
    // ============ Helper Functions ============
    
    function _createTestTxHash() internal view returns (bytes32) {
        address target = address(mockContract);
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 123);
        uint256 nonce = wallet.nonce();
        
        return wallet.getTransactionHash(target, value, data, nonce);
    }
    
    // Required to receive ETH in tests
    receive() external payable {}
    
    // Event definitions for testing emitted events
    event TransactionSigned(bytes32 indexed txHash, address indexed signer);
    event TransactionExecuted(bytes32 indexed txHash, address indexed target, uint256 value, bytes data);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdChanged(uint256 newThreshold);
}