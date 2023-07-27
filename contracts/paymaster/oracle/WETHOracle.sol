// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../IOracle.sol";

/**
 * The price is 1:1 with ETH
 * If it is another token, you can call uniswap's on-chain api to query the price
 */
contract WETHOracle is IOracle {
    function getTokenValueOfEth(uint256 ethOutput) external pure returns (uint256 tokenInput) {
        return ethOutput;
    }
}