// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

interface IYieldOracle {
    function currentPrice() external view returns (uint128);
    function oldPrice() external view returns (uint128);  
    function fromEudToEui(uint256 eudAmount) external view returns (uint256);
    function fromEuiToEud(uint256 euiAmount) external view returns (uint256);  
}
