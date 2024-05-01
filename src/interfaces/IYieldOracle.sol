// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IYieldOracle {
    function currentPrice() external view returns (uint128);
    function previousPrice() external view returns (uint128);  
    function fromEudToEui(uint256 eudAmount) external view returns (uint256);
    function fromEuiToEud(uint256 euiAmount) external view returns (uint256);  
}
