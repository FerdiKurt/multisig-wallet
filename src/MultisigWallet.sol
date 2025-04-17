// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title MultisigWallet
 * @dev A multisignature wallet that supports a k-of-n signature scheme.
 * Allows execution of arbitrary methods on any contract when enough valid signatures are provided.
 * Implements custom errors for more efficient error handling and reliable ETH transfers.
 */
contract MultisigWallet {
    // Custom Errors
    error NoSignersProvided();
    error InvalidThreshold();
    error InvalidSignerAddress();
    error DuplicateSigner();
    error NotAuthorizedSigner();
    error AlreadySigned();
    error InvalidTargetAddress();
    error InsufficientSigners();
    error TransactionAlreadyExecuted();
    error NotEnoughValidSignatures();
    error TransactionExecutionFailed();
    error InsufficientBalance();

    // Events
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdChanged(uint256 newThreshold);
    event TransactionExecuted(
        bytes32 indexed txHash,
        address indexed target,
        uint256 value,
        bytes data
    );
    event TransactionSigned(bytes32 indexed txHash, address indexed signer);
    event EtherReceived(address indexed sender, uint256 amount);

    // State variables
    mapping(address => bool) public isAuthorizedSigner;
    address[] public signers;
    uint256 public threshold; // k in k-of-n

    // Mapping from transaction hash to signer => signed status
    mapping(bytes32 => mapping(address => bool)) public signed;
    
    // Mapping to track executed transactions to prevent replay attacks
    mapping(bytes32 => bool) public executed;

    // Nonce to prevent replay attacks across chains
    uint256 public nonce;

    /**
     * @dev Constructor sets initial signers and threshold
     * @param _signers Array of initial signers' addresses
     * @param _threshold Number of signatures required to execute a transaction
     */
    constructor(address[] memory _signers, uint256 _threshold) {
        if (_signers.length == 0) revert NoSignersProvided();
        if (_threshold == 0 || _threshold > _signers.length) revert InvalidThreshold();

        for (uint256 i = 0; i < _signers.length; i++) {
            address signer = _signers[i];
            if (signer == address(0)) revert InvalidSignerAddress();
            if (isAuthorizedSigner[signer]) revert DuplicateSigner();

            isAuthorizedSigner[signer] = true;
            signers.push(signer);
            emit SignerAdded(signer);
        }

        threshold = _threshold;
        emit ThresholdChanged(_threshold);
    }

    /**
    * @dev Fallback function to receive ETH
    */
    receive() external payable {
        emit EtherReceived(msg.sender, msg.value);
    }

    /**
     * @dev Calculates the hash of a transaction
     * @param _target Address of the contract to call
     * @param _value Amount of ETH to send
     * @param _data Calldata for the transaction
     * @param _nonce Current nonce value
     * @return Transaction hash
     */
    function getTransactionHash(
        address _target,
        uint256 _value,
        bytes memory _data,
        uint256 _nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), _target, _value, _data, _nonce));
    }

    /**
     * @dev Signs a transaction
     * @param _txHash Hash of the transaction to sign
     */
    function signTransaction(bytes32 _txHash) external {
        if (!isAuthorizedSigner[msg.sender]) revert NotAuthorizedSigner();
        if (signed[_txHash][msg.sender]) revert AlreadySigned();
        
        signed[_txHash][msg.sender] = true;
        emit TransactionSigned(_txHash, msg.sender);
    }

    /**
     * @dev Executes a transaction if it has enough valid signatures
     * @param _target Address of the contract to call
     * @param _value Amount of ETH to send
     * @param _data Calldata for the transaction
     * @param _signers Array of signers who have signed this transaction
     */
    function executeTransaction(
        address _target,
        uint256 _value,
        bytes memory _data,
        address[] memory _signers
    ) external {
        if (_target == address(0)) revert InvalidTargetAddress();
        if (_signers.length < threshold) revert InsufficientSigners();
        
        // Check if wallet has enough ETH balance
        if (_value > address(this).balance) revert InsufficientBalance();
        
        // Calculate transaction hash
        bytes32 txHash = getTransactionHash(_target, _value, _data, nonce);
        if (executed[txHash]) revert TransactionAlreadyExecuted();
        
        // Verify signatures
        uint256 validSignatures = 0;
        for (uint256 i = 0; i < _signers.length; i++) {
            address signer = _signers[i];
            
            // Check if signer is authorized and has signed
            if (isAuthorizedSigner[signer] && signed[txHash][signer]) {
                validSignatures++;
            }
        }
        
        if (validSignatures < threshold) revert NotEnoughValidSignatures();
        
        // Mark as executed and increment nonce before external call (to avoid reentrancy)
        executed[txHash] = true;
        nonce++;
        
        // Execute transaction using a low-level call for maximum flexibility
        bool success;
        
        // Use a separate internal function for the actual call to avoid stack too deep errors
        success = _executeCall(_target, _value, _data);
        
        if (!success) revert TransactionExecutionFailed();
        
        emit TransactionExecuted(txHash, _target, _value, _data);
    }
    
    /**
     * @dev Internal function to execute the actual call with proper error handling
     * @param _target Address of the contract to call
     * @param _value Amount of ETH to send
     * @param _data Calldata for the transaction
     * @return success Whether the call succeeded
     */
    function _executeCall(
        address _target,
        uint256 _value,
        bytes memory _data
    ) private returns (bool success) {
        // Explicitly allocate a specific gas amount for the call (leaving some for our operations)
        uint256 gasToSend = gasleft() - 10000;
        
        // Use assembly for maximum control and to properly propagate errors
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Call the target contract
            // "mload(0x40)" is the "free memory pointer" that points to available memory
            let ptr := mload(0x40)
            mstore(ptr, mload(_data))
            let dataLength := mload(_data)
            let srcPtr := add(_data, 0x20) // Skip the length field
            let destPtr := add(ptr, 0x20)
            
            // Copy dataLength bytes from srcPtr to destPtr
            for { let i := 0 } lt(i, dataLength) { i := add(i, 0x20) } {
                mstore(add(destPtr, i), mload(add(srcPtr, i)))
            }
            
            // Perform the call with ETH transfer
            success := call(
                gasToSend,   // gas
                _target,     // recipient
                _value,      // ether value
                add(ptr, 0x20), // input data start (skip length field)
                mload(_data),   // input data length
                0,              // output data start (we're not reading any output)
                0               // output data length
            )
        }
        
        // Return whether the call succeeded
        return success;
    }

    /**
     * @dev Updates the set of signers (add or remove)
     * @param _newSigners Array of new signers
     * @param _newThreshold New threshold value
     * @param _signers Array of current signers who have signed this update
     */
    function updateSigners(
        address[] memory _newSigners,
        uint256 _newThreshold,
        address[] memory _signers
    ) external {
        if (_newSigners.length == 0) revert NoSignersProvided();
        if (_newThreshold == 0 || _newThreshold > _newSigners.length) revert InvalidThreshold();
        if (_signers.length < threshold) revert InsufficientSigners();
        
        // Calculate update hash
        bytes32 updateHash = keccak256(abi.encodePacked(
            "UPDATE_SIGNERS",
            _newSigners,
            _newThreshold,
            nonce
        ));
        
        // Verify signatures
        uint256 validSignatures = 0;
        for (uint256 i = 0; i < _signers.length; i++) {
            address signer = _signers[i];
            
            // Check if signer is authorized and has signed
            if (isAuthorizedSigner[signer] && signed[updateHash][signer]) {
                validSignatures++;
            }
        }
        
        if (validSignatures < threshold) revert NotEnoughValidSignatures();
        
        // Remove existing signers
        for (uint256 i = 0; i < signers.length; i++) {
            isAuthorizedSigner[signers[i]] = false;
            emit SignerRemoved(signers[i]);
        }
        
        // Clear signers array
        delete signers;
        
        // Add new signers
        for (uint256 i = 0; i < _newSigners.length; i++) {
            address newSigner = _newSigners[i];
            if (newSigner == address(0)) revert InvalidSignerAddress();
            
            // Check for duplicates in the new array
            for (uint256 j = 0; j < i; j++) {
                if (_newSigners[j] == newSigner) revert DuplicateSigner();
            }
            
            isAuthorizedSigner[newSigner] = true;
            signers.push(newSigner);
            emit SignerAdded(newSigner);
        }
        
        // Update threshold
        threshold = _newThreshold;
        emit ThresholdChanged(_newThreshold);
        
        // Increment nonce
        nonce++;
    }

    /**
     * @dev Returns the total number of signers
     */
    function getSignerCount() external view returns (uint256) {
        return signers.length;
    }
    
    /**
     * @dev Returns all signers
     */
    function getAllSigners() external view returns (address[] memory) {
        return signers;
    }

    /**
     * @dev Checks if a transaction has enough signatures
     * @param _txHash Hash of the transaction
     */
    function hasEnoughSignatures(bytes32 _txHash) external view returns (bool) {
        uint256 count = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signed[_txHash][signers[i]]) {
                count++;
                if (count >= threshold) {
                    return true;
                }
            }
        }
        return false;
    }
}