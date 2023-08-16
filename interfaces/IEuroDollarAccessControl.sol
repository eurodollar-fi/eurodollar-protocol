// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

interface IEuroDollarAccessControl {
    function hasRole(
        bytes32 role,
        address account
    ) external view returns (bool);
}
