// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

interface ITokenFlipper {
    function flipToEUD(
        address owner,
        address receiver,
        uint256 amount
    ) external returns (uint256);

    function flipToEUI(
        address owner,
        address receiver,
        uint256 amount
    ) external returns (uint256);

    function fromEudToEui(uint256 eudAmount) external view returns (uint256);

    function fromEuiToEud(uint256 euiAmount) external view returns (uint256);
}
