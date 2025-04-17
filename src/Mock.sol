// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Mock
 * @dev Mock contract to test Multisig Wallet
 */
contract Mock {
    uint256 public lastValueReceived;
    address public lastSender;
    bool public shouldAcceptEther = true;
    uint256 public value;
    
    event FundsReceived(address sender, uint256 amount);
    
    /**
    * @dev Sets the value variable
    * @param _value New value to set
    */
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    // Configurable function to accept or reject ETH
    function setShouldAcceptEther(bool _shouldAccept) external {
        shouldAcceptEther = _shouldAccept;
    }
    
    // This function can be called to transfer ETH to this contract
    function deposit() external payable {
        lastValueReceived = msg.value;
        lastSender = msg.sender;
        emit FundsReceived(msg.sender, msg.value);
    }
    
    // This function can be called to test a function that might fail
    function revertingFunction() external pure {
        revert("Function reverted on purpose");
    }
    
    // Receive function to accept ETH
    receive() external payable {
        if (!shouldAcceptEther) {
            revert("ETH transfers not accepted");
        }
        
        lastValueReceived = msg.value;
        lastSender = msg.sender;
        emit FundsReceived(msg.sender, msg.value);
    }
    
    // Return balance of this contract
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}