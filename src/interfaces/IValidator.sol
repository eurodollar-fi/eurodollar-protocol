// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited
pragma solidity ^0.8.21;

interface IValidator {
    function isValid(
        address from,
        address to
    ) external view returns (bool valid);
    function isValidStrict(
        address from,
        address to
    ) external view returns (bool valid);

    function isWhitelisted(address account) external view returns (bool);
    function isBlacklisted(address account) external view returns (bool);
}
