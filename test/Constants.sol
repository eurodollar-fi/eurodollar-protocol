// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

contract Constants {
    uint256 public constant MIN_PRICE = 1e18; // Minimum EUI/USDE price
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MINT_ROLE = keccak256("MINT_ROLE");
    bytes32 public constant INVEST_TOKEN_ROLE = keccak256("INVEST_TOKEN_ROLE");
    bytes32 public constant BURN_ROLE = keccak256("BURN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant FREEZE_ROLE = keccak256("FREEZE_ROLE");
    bytes32 public constant BLOCK_ROLE = keccak256("BLOCK_ROLE");
    bytes32 public constant ALLOW_ROLE = keccak256("ALLOW_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
}
