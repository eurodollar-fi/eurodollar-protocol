// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "./RoleControl.sol";

/**
 * @author  Fenris
 * @title   EUIAllowlist
 * @dev     A contract that manages an allowlist of addresses using RoleControl for access control.
 * @dev     Addresses on the allowlist are granted specific permissions within the system.
 * @dev     The contract allows adding and removing addresses from the allowlist based on the `ALLOWLIST_ROLE`.
 */
contract Allowlist is RoleControl {
    mapping(address => bool) public allowlist;

    // event
    event AddedToAllowlist(address indexed account);
    event RemovedFromAllowlist(address indexed account);

    /**
     * @notice  This function is called internally to add an address to the allowlist.
     * @notice  The address must not be already on the allowlist.
     * @notice  Emits an `AddedToAllowlist` event upon successful addition.
     * @dev     Internal function to add an address to the allowlist.
     * @param   account The address to be added to the allowlist.
     */
    function _addToAllowlist(address account) internal {
        require(!allowlist[account], "account is already in allowlist");
        allowlist[account] = true;
        emit AddedToAllowlist(account);
    }

    function addToAllowlist(
        address[] memory accounts
    ) external onlyRole(ALLOWLIST_ROLE) {
        for (uint256 i; i < accounts.length; i++) {
            _addToAllowlist(accounts[i]);
        }
    }

    function _removeFromAllowlist(address account) internal {
        require(allowlist[account], "account is not in allowlist");
        allowlist[account] = false;
        emit RemovedFromAllowlist(account);
    }

    /**
     * @notice  This function is accessible only to accounts with the `ALLOWLIST_ROLE`.
     * @notice  The address must be currently on the allowlist.
     * @notice  Emits a `RemovedFromAllowlist` event upon successful removal.
     * @dev     Allows the `ALLOWLIST_ROLE` to remove an address from the allowlist.
     * @param   accounts The address to be removed from the allowlist.
     */
    function removeFromAllowlist(
        address[] memory accounts
    ) external onlyRole(ALLOWLIST_ROLE) {
        for (uint256 i; i < accounts.length; i++) {
            _removeFromAllowlist(accounts[i]);
        }
    }
}
