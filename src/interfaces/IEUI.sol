// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IEUI {
    function decimals() external view returns (uint8);

    function totalAssets() external view returns (uint256);

    function allowance(
        address owner,
        address spender
    ) external view returns (uint256);

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);

    function mint(address to, uint256 amount) external;

    function burn(address from, uint256 amount) external;
}
