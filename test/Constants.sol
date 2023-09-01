// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.13;

contract Constants {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MINT_ROLE = keccak256("MINT_ROLE");
    bytes32 public constant BURN_ROLE = keccak256("BURN_ROLE");
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant FREEZE_ROLE = keccak256("FREEZE_ROLE");
    bytes32 public constant BLOCK_ROLE = keccak256("BLOCK_ROLE");
    bytes32 public constant ALLOW_ROLE = keccak256("ALLOW_ROLE");
}