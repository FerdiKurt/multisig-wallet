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
    
    // Transaction parameters used in multiple tests
    address mockAddress;
    uint256 transferAmount;
    
    // Events definition for tests
    event TransactionSigned(bytes32 indexed txHash, address indexed signer);
    event TransactionExecuted(bytes32 indexed txHash, address indexed target, uint256 value, bytes data);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdChanged(uint256 newThreshold);
    
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
        mockAddress = address(mockContract);
        
        // Deploy multisig wallet
        wallet = new MultisigWallet(signers, THRESHOLD);
        
        // Fund the wallet with some ETH for tests
        vm.deal(address(wallet), 10 ether);
        
        // Common value for transfers
        transferAmount = 1 ether;
    }

    // Required to receive ETH in tests
    receive() external payable {}
    
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
        address[] memory testSigners = _createTestSigners();
        vm.expectRevert(MultisigWallet.InvalidThreshold.selector);
        new MultisigWallet(testSigners, 0); // Should fail with InvalidThreshold
    }
    
    function testDeployWithInvalidThresholdTooHigh() public {
        address[] memory testSigners = _createTestSigners();
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
        bytes memory data = ""; // Empty data for a simple ETH transfer
        _testSuccessfulTransaction(mockAddress, transferAmount, data);
        
        // Verify Mock contract received the ETH and recorded data correctly
        assertEq(mockContract.lastValueReceived(), transferAmount, "Received value not tracked correctly");
        assertEq(mockContract.lastSender(), address(wallet), "Sender not tracked correctly");
    }

    function testSendEtherToContractWithFunction() public {
        bytes memory data = abi.encodeWithSignature("deposit()");
        _testSuccessfulTransaction(mockAddress, transferAmount, data);
        
        // Verify Mock contract received the ETH and recorded data correctly
        assertEq(mockContract.lastValueReceived(), transferAmount, "Received value not tracked correctly");
        assertEq(mockContract.lastSender(), address(wallet), "Sender not tracked correctly");
    }

    function testRevertSendEtherToRejectingContract() public {
        // Configure the test receiver to reject ETH
        mockContract.setShouldAcceptEther(false);
        
        bytes memory data = ""; 
        address[] memory executionSigners = _getExecutionSigners();
        
        // Execute the transaction - should revert
        vm.expectRevert();
        wallet.executeTransaction(mockAddress, transferAmount, data, executionSigners);
    }

    function testSendEtherToEOA() public {
        address eoa = address(0x5); // Some EOA address
        bytes memory data = ""; 
        _testSuccessfulTransaction(eoa, transferAmount, data);
    }

    function testRevertExecuteRevertingFunction() public {
        bytes memory data = abi.encodeWithSignature("revertingFunction()");
        address[] memory executionSigners = _getExecutionSigners();
        
        // Execute the transaction - should revert
        vm.expectRevert();
        wallet.executeTransaction(mockAddress, 0, data, executionSigners);
    }
    
    function testExecuteTransactionEmitsEvent() public {
        (address target, uint256 value, bytes memory data) = _setupStandardTransaction();
        bytes32 txHash = _signTransaction(target, value, data);
        address[] memory executionSigners = _getExecutionSigners();
        
        // Expect event
        vm.expectEmit(true, true, false, true);
        emit TransactionExecuted(txHash, target, value, data);
        
        // Execute transaction
        wallet.executeTransaction(target, value, data, executionSigners);
    }

    function testIncrementsNonceAfterExecution() public {
        (address target, uint256 value, bytes memory data) = _setupStandardTransaction();
        uint256 initialNonce = wallet.nonce();
        
        _testSuccessfulTransaction(target, value, data);
        
        // Verify nonce increment
        assertEq(wallet.nonce(), initialNonce + 1);
    }

    function testMarksTransactionAsExecuted() public {
        (address target, uint256 value, bytes memory data) = _setupStandardTransaction();
        bytes32 txHash = _signTransaction(target, value, data);
        address[] memory executionSigners = _getExecutionSigners();
        
        // Execute transaction
        wallet.executeTransaction(target, value, data, executionSigners);
        
        // Verify transaction marked as executed
        assertTrue(wallet.executed(txHash));
    }

    function testCannotExecuteWithInsufficientSigners() public {
        (address target, uint256 value, bytes memory data) = _setupStandardTransaction();
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        // Sign transaction with only one signer
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        // Prepare signers array with just one signer
        address[] memory executionSigners = new address[](1);
        executionSigners[0] = signer1;
        
        // Attempt execution
        _attemptFailingExecution(
            target, 
            value, 
            data, 
            executionSigners, 
            abi.encodeWithSelector(MultisigWallet.InsufficientSigners.selector)
        );
    }

    function testCannotExecuteWithInvalidSigners() public {
        (address target, uint256 value, bytes memory data) = _setupStandardTransaction();
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        // Sign transaction
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        // Prepare signers array with one valid and one invalid signer
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = nonSigner;
        
        // Attempt execution
        _attemptFailingExecution(
            target, 
            value, 
            data, 
            executionSigners, 
            abi.encodeWithSelector(MultisigWallet.NotEnoughValidSignatures.selector)
        );
    }

    function testCannotExecuteWithZeroTargetAddress() public {
        (,uint256 value, bytes memory data) = _setupStandardTransaction();
        address zeroTarget = address(0);
        address[] memory executionSigners = _getExecutionSigners();
        
        // Attempt execution
        _attemptFailingExecution(
            zeroTarget, 
            value, 
            data, 
            executionSigners, 
            abi.encodeWithSelector(MultisigWallet.InvalidTargetAddress.selector)
        );
    }

    function testCannotExecuteSameTransactionTwice() public {
        (address target, uint256 value, bytes memory data) = _setupStandardTransaction();
        _signTransaction(target, value, data);
        address[] memory executionSigners = _getExecutionSigners();
        
        // Execute transaction first time
        wallet.executeTransaction(target, value, data, executionSigners);
        
        // Attempt to execute same transaction again
        _attemptFailingExecution(target, value, data, executionSigners, "");
    }
    
    // ============ Signer Management Tests ============
    
    function testUpdateSigners() public {
        (address[] memory newSigners, uint256 newThreshold) = _createStandardNewSigners();
        _executeUpdateSigners(newSigners, newThreshold);
        
        // Verify signer changes
        assertEq(wallet.getSignerCount(), newSigners.length);
        assertTrue(wallet.isAuthorizedSigner(signer1));
        assertTrue(wallet.isAuthorizedSigner(signer2));
        assertTrue(wallet.isAuthorizedSigner(nonSigner));
        assertFalse(wallet.isAuthorizedSigner(signer3));
    }

    function testUpdateSignersEmitsEvents() public {
        // Setup different set of signers to test more event emissions
        address[] memory newSigners = new address[](2);
        newSigners[0] = signer1;
        newSigners[1] = nonSigner; // Adding nonSigner, removing signer2 and signer3
        uint256 newThreshold = 1;
        
        bytes32 updateHash = _getUpdateHash(newSigners, newThreshold);
        _signUpdateBySigners(updateHash);
        address[] memory updateSigners = _getExecutionSigners();
        
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
        (address[] memory newSigners, uint256 newThreshold) = _createStandardNewSigners();
        
        uint256 initialNonce = wallet.nonce();
        _executeUpdateSigners(newSigners, newThreshold);
        
        // Verify nonce incremented
        assertEq(wallet.nonce(), initialNonce + 1);
    }

    function testCannotUpdateWithInsufficientSigners() public {
        (address[] memory newSigners, uint256 newThreshold) = _createStandardNewSigners();
        bytes32 updateHash = _getUpdateHash(newSigners, newThreshold);
        
        // Sign with only one signer
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        // Prepare signers array with only one signer
        address[] memory updateSigners = new address[](1);
        updateSigners[0] = signer1;
        
        // Attempt update
        _attemptFailingUpdate(
            newSigners, 
            newThreshold, 
            updateSigners, 
            abi.encodeWithSelector(MultisigWallet.InsufficientSigners.selector)
        );
    }

    function testCannotUpdateWithInvalidSigners() public {
        (address[] memory newSigners, uint256 newThreshold) = _createStandardNewSigners();
        bytes32 updateHash = _getUpdateHash(newSigners, newThreshold);
        
        // Sign with only one valid signer
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        // Prepare signers array with one valid and one invalid signer
        address[] memory updateSigners = new address[](2);
        updateSigners[0] = signer1;
        updateSigners[1] = nonSigner;
        
        // Attempt update
        _attemptFailingUpdate(
            newSigners, 
            newThreshold, 
            updateSigners, 
            abi.encodeWithSelector(MultisigWallet.NotEnoughValidSignatures.selector)
        );
    }

    function testCannotUpdateWithZeroThreshold() public {
        (address[] memory newSigners,) = _createStandardNewSigners();
        uint256 invalidThreshold = 0; // Invalid threshold
        address[] memory updateSigners = _getExecutionSigners();
        
        // Attempt update
        _attemptFailingUpdate(
            newSigners, 
            invalidThreshold, 
            updateSigners, 
            abi.encodeWithSelector(MultisigWallet.InvalidThreshold.selector)
        );
    }

    function testCannotUpdateWithThresholdTooHigh() public {
        (address[] memory newSigners,) = _createStandardNewSigners();
        uint256 tooHighThreshold = 4; // Higher than number of signers
        address[] memory updateSigners = _getExecutionSigners();
        
        // Attempt update
        _attemptFailingUpdate(
            newSigners, 
            tooHighThreshold, 
            updateSigners, 
            abi.encodeWithSelector(MultisigWallet.InvalidThreshold.selector)
        );
    }

    function testCannotUpdateWithDuplicateSigners() public {
        // Setup new signers with duplicate
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = signer1; // Duplicate
        uint256 newThreshold = 2;

        bytes32 updateHash = _getUpdateHash(newSigners, newThreshold);
        _signUpdateBySigners(updateHash);
        address[] memory updateSigners = _getExecutionSigners();
        
        // Attempt update
        _attemptFailingUpdate(
            newSigners, 
            newThreshold, 
            updateSigners, 
            abi.encodeWithSelector(MultisigWallet.DuplicateSigner.selector)
        );
    }

    function testCannotUpdateWithZeroAddressSigner() public {
        // Setup new signers with zero address
        address[] memory newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = address(0); // Zero address
        uint256 newThreshold = 2;

        bytes32 updateHash = _getUpdateHash(newSigners, newThreshold);
        _signUpdateBySigners(updateHash);
        address[] memory updateSigners = _getExecutionSigners();
        
        // Attempt update
        _attemptFailingUpdate(
            newSigners, 
            newThreshold, 
            updateSigners, 
            abi.encodeWithSelector(MultisigWallet.InvalidSignerAddress.selector)
        );
    }
    
    // ============ Helper Functions ============
    
    function _createTestSigners() internal view returns (address[] memory) {
        address[] memory testSigners = new address[](3);
        testSigners[0] = signer1;
        testSigners[1] = signer2;
        testSigners[2] = signer3;

        return testSigners;
    }

    function _createTestTxHash() internal view returns (bytes32) {
        address target = mockAddress;
        uint256 value = 0;
        bytes memory data = abi.encodeWithSignature("setValue(uint256)", 123);
        uint256 nonce = wallet.nonce();
        
        return wallet.getTransactionHash(target, value, data, nonce);
    }
    
    function _getExecutionSigners() internal view returns (address[] memory) {
        address[] memory executionSigners = new address[](2);
        executionSigners[0] = signer1;
        executionSigners[1] = signer2;

        return executionSigners;
    }
    
    function _signTransaction(address target, uint256 value, bytes memory data) internal returns (bytes32) {
        bytes32 txHash = wallet.getTransactionHash(target, value, data, wallet.nonce());
        
        vm.prank(signer1);
        wallet.signTransaction(txHash);
        
        vm.prank(signer2);
        wallet.signTransaction(txHash);
        
        return txHash;
    }

    function _setupStandardTransaction() internal view returns (address target, uint256 value, bytes memory data) {
        target = mockAddress;
        value = 0;
        data = abi.encodeWithSignature("setValue(uint256)", 123);
        return (target, value, data);
    }

    function _attemptFailingExecution(
        address target, 
        uint256 value, 
        bytes memory data, 
        address[] memory executionSigners,
        bytes memory revertData
    ) internal {
        if (revertData.length > 0) {
            vm.expectRevert(revertData);
        } else {
            vm.expectRevert();
        }
        wallet.executeTransaction(target, value, data, executionSigners);
    }
    
    function _testSuccessfulTransaction(address target, uint256 value, bytes memory data) internal {
       _signTransaction(target, value, data);
        address[] memory executionSigners = _getExecutionSigners();
        
        // Check initial balances
        uint256 initialWalletBalance = address(wallet).balance;
        uint256 initialTargetBalance = address(target).balance;
        
        // Execute the transaction
        wallet.executeTransaction(target, value, data, executionSigners);
        
        // Verify balances after transfer
        assertEq(address(wallet).balance, initialWalletBalance - value, "Wallet balance not decreased correctly");
        assertEq(address(target).balance, initialTargetBalance + value, "Target balance not increased correctly");
    }

    function _createStandardNewSigners() internal view returns (address[] memory newSigners, uint256 newThreshold) {
        newSigners = new address[](3);
        newSigners[0] = signer1;
        newSigners[1] = signer2;
        newSigners[2] = nonSigner; // Adding nonSigner, removing signer3
        newThreshold = 2;
        return (newSigners, newThreshold);
    }

    function _attemptFailingUpdate(
        address[] memory newSigners, 
        uint256 newThreshold, 
        address[] memory updateSigners,
        bytes memory revertData
    ) internal {
        vm.expectRevert(revertData);
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
    }
    
    function _getUpdateHash(address[] memory newSigners, uint256 newThreshold) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            newSigners,
            newThreshold,
            wallet.nonce()
        ));
    }
    
    function _signUpdateBySigners(bytes32 updateHash) internal {
        vm.prank(signer1);
        wallet.signTransaction(updateHash);
        
        vm.prank(signer2);
        wallet.signTransaction(updateHash);
    }
    
    function _executeUpdateSigners(address[] memory newSigners, uint256 newThreshold) internal {
        bytes32 updateHash = _getUpdateHash(newSigners, newThreshold);
        _signUpdateBySigners(updateHash);
        address[] memory updateSigners = _getExecutionSigners();
        
        wallet.updateSigners(newSigners, newThreshold, updateSigners);
    }
}