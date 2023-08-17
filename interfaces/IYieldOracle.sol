// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

interface IYieldOracle {
    function currentPrice() external view returns (uint128);
    function oldPrice() external view returns (uint128);    
}
