// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IEUD {
    function decimals() external view returns (uint8);

    function balanceOf(address account) external view returns (uint256);

    function allowance(
        address owner,
        address spender
    ) external view returns (uint256);

    function transfer(address to, uint256 amount) external returns (bool);

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);

    function investMint(address to, uint256 amount) external;

    function investBurn(address from, uint256 amount) external;

    function investBurn(address from, address spender, uint256 amount) external;
}
