//SPDX-License-Identifier: GPL
pragma solidity ^0.8.7;


import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

interface ISpendingLimit {
    struct SignatureData {
        address signer;
        bytes signature;
    }

    function executeLimitTransaction(
        address _wallet,
        address _to,
        uint256 _value,
        bytes calldata _data,
        Enum.Operation _operation
    ) external;

    function encodeExecuteWhithGuardianData(
        address _wallet,
        address _to,
        uint256 _value,
        bytes memory _data,
        Enum.Operation _operation
    ) external view returns(bytes32);

    function validateGuardiansSignature(
        address _wallet, 
        bytes32 _dataHash, 
        SignatureData[] calldata _signatureData 
    ) external;
}