// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Faucet is Ownable{

    error SendError(address to, uint256 value, bytes data);

    struct SendData{
        address to;
        uint256 value;
        bytes data;
    }

    // revert with explicit byte array (probably reverted info from call)
    function revertWithData(bytes memory returnData) internal pure {
        assembly {
            revert(add(returnData, 32), mload(returnData))
        }
    }

    // get returned data from last call or calldelegate
    function getReturnData() internal pure returns (bytes memory returnData) {
        assembly {
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(returndatasize(), 0x20)))
            mstore(ptr, returndatasize())
            returndatacopy(add(ptr, 0x20), 0, returndatasize())
            returnData := ptr
        }
    }

    function call(
        address to,
        uint256 value,
        bytes memory data,
        uint256 txGas
    ) internal returns (bool success) {
        assembly {
            success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
        }
    }

    function multiSend(SendData[] calldata multiData) external onlyOwner {
        for (uint i = 0; i < multiData.length; i++) {
            bool success = call(multiData[i].to, multiData[i].value, multiData[i].data, gasleft());
            if (!success) {
                revertWithData(getReturnData());
            }
        }
    }

    receive() external payable {
    }
}