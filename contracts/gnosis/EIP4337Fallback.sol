//SPDX-License-Identifier: GPL
pragma solidity ^0.8.7;

/* solhint-disable no-inline-assembly */

import "@gnosis.pm/safe-contracts/contracts/handler/DefaultCallbackHandler.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../interfaces/IAccount.sol";
import "./EIP4337Manager.sol";

using ECDSA for bytes32;

/**
 * The GnosisSafe enables adding custom functions implementation to the Safe by setting a 'fallbackHandler'.
 * This 'fallbackHandler' adds an implementation of 'validateUserOp' to the GnosisSafe.
 * Note that the implementation of the 'validateUserOp' method is located in the EIP4337Manager.
 * Upon receiving the 'validateUserOp', a Safe with EIP4337Fallback enabled makes a 'delegatecall' to EIP4337Manager.
 */
contract EIP4337Fallback is DefaultCallbackHandler, IAccount, IERC1271 {
    // bytes4(keccak256("isValidSignature(bytes,bytes)")
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x20c13b0b;
    bytes4 internal constant UPDATED_MAGIC_VALUE = 0x1626ba7e;
    // keccak256("SafeMessage(bytes message)");
    bytes32 private constant SAFE_MSG_TYPEHASH = 0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    address immutable public eip4337manager;
    constructor(address _eip4337manager) {
        eip4337manager = _eip4337manager;
    }

    /**
     * delegate the contract call to the EIP4337Manager
     */
    function delegateToManager() internal returns (bytes memory) {
        // delegate entire msg.data (including the appended "msg.sender") to the EIP4337Manager
        // will work only for GnosisSafe contracts
        GnosisSafe safe = GnosisSafe(payable(msg.sender));
        (bool success, bytes memory ret) = safe.execTransactionFromModuleReturnData(eip4337manager, 0, msg.data, Enum.Operation.DelegateCall);
        if (!success) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        return ret;
    }

    /**
     * called from the Safe. delegate actual work to EIP4337Manager
     */
    function validateUserOp(UserOperation calldata, bytes32, uint256) override external returns (uint256 deadline){
        bytes memory ret = delegateToManager();
        return abi.decode(ret, (uint256));
    }

    /**
     * called from the Safe. delegate actual work to EIP4337Manager
     */
    function executeAndRevert(
        address,
        uint256,
        bytes memory,
        Enum.Operation
    ) external {
        delegateToManager();
    }

     /**
     * @notice Legacy EIP-1271 signature validation method.
     * @dev Implementation of ISignatureValidator (see `interfaces/ISignatureValidator.sol`)
     * @param _data Arbitrary length data signed on the behalf of address(msg.sender).
     * @param _signature Signature byte array associated with _data.
     * @return The EIP-1271 magic value.
     */
    function isValidSignature(bytes memory _data, bytes memory _signature) public view returns (bytes4) {
        // Caller should be a Safe
        GnosisSafe safe = GnosisSafe(payable(msg.sender));
        bytes memory messageData = encodeMessageDataForSafe(safe, _data);
        bytes32 messageHash = keccak256(messageData);
        if (_signature.length == 0) {
            require(safe.signedMessages(messageHash) != 0, "Hash not approved");
        } else {
            safe.checkSignatures(messageHash, messageData, _signature);
        }
        return EIP1271_MAGIC_VALUE;
    }

    /**
     * @dev Returns the hash of a message to be signed by owners.
     * @param message Raw message bytes.
     * @return Message hash.
     */
    function getMessageHash(bytes memory message) public view returns (bytes32) {
        return getMessageHashForSafe(GnosisSafe(payable(msg.sender)), message);
    }

    /**
     * @dev Returns the pre-image of the message hash (see getMessageHashForSafe).
     * @param safe Safe to which the message is targeted.
     * @param message Message that should be encoded.
     * @return Encoded message.
     */
    function encodeMessageDataForSafe(GnosisSafe safe, bytes memory message) public view returns (bytes memory) {
        bytes32 safeMessageHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message)));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), safe.domainSeparator(), safeMessageHash);
    }

    /**
     * @dev Returns hash of a message that can be signed by owners.
     * @param safe Safe to which the message is targeted.
     * @param message Message that should be hashed.
     * @return Message hash.
     */
    function getMessageHashForSafe(GnosisSafe safe, bytes memory message) public view returns (bytes32) {
        return keccak256(encodeMessageDataForSafe(safe, message));
    }

    /**
     * @notice Implementation of updated EIP-1271 signature validation method.
     * @param _dataHash Hash of the data signed on the behalf of address(msg.sender)
     * @param _signature Signature byte array associated with _dataHash
     * @return Updated EIP1271 magic value if signature is valid, otherwise 0x0
     */
    function isValidSignature(bytes32 _dataHash, bytes calldata _signature) external view returns (bytes4) {
        ISignatureValidator validator = ISignatureValidator(msg.sender);
        bytes4 value = validator.isValidSignature(abi.encode(_dataHash), _signature);
        return (value == EIP1271_MAGIC_VALUE) ? UPDATED_MAGIC_VALUE : bytes4(0);
    }

    function executeScheduledTransaction(
        uint256,
        uint256,
        address,
        uint256,
        bytes memory,
        Enum.Operation
    ) external {
        delegateToManager();
    }

    function setEllipticCurve(bytes memory) external {
        delegateToManager();
    }

    function flipScheduleModule() external {
        delegateToManager();
    }

    function enableSpendingLimit() external {
        delegateToManager();
    }

    function disableSpendingLimit() external {
        delegateToManager();
    }

    function executeWhithGuardianAndRevert(
        address,
        uint256,
        bytes memory,
        Enum.Operation,
        ISpendingLimit.SignatureData[] calldata
    ) external {
        delegateToManager();
    }

    function executeWithCurveAndRevert(
        address,
        uint256,
        bytes memory,
        Enum.Operation
    ) external {
        delegateToManager();
    }

    function spendingLimit() external returns (bool status) {
        bytes memory retData = delegateToManager();
        status = abi.decode(retData, (bool));
    }

    function whetherLimitRouter() external returns(bool status) {
        bytes memory retData = delegateToManager();
        status = abi.decode(retData, (bool));
    }

    function ellipticCurvePublicKey() external returns (bytes memory key) {
        bytes memory retData = delegateToManager();
        key = abi.decode(retData, (bytes));
    }
}