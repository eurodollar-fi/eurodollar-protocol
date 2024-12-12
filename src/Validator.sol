// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IValidator.sol";

/**
 * @title BlacklistValidator
 * @dev Implements a validator which manages whitelisted and blacklisted addresses for transfer validation.
 */
contract Validator is AccessControl, IValidator {
    enum Status {
        VOID,
        WHITELISTED,
        BLACKLISTED
    }

    event Whitelisted(address indexed account);
    event Blacklisted(address indexed account);
    event Voided(address indexed account);

    bytes32 public constant WHITELISTER_ROLE = keccak256("WHITELISTER_ROLE");
    bytes32 public constant BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");

    /// @dev Address to corresponding list status mapping
    mapping(address => Status) public accountStatus;

    /**
     * @dev Constructor setting up initial roles.
     * @param _initialOwner Address to be granted the DEFAULT_ADMIN_ROLE.
     * @param _whitelister Address to be granted the WHITELISTER_ROLE.
     * @param _blacklister Address to be granted the BLACKLISTER_ROLE.
     */
    constructor(address _initialOwner, address _whitelister, address _blacklister) {
        _grantRole(DEFAULT_ADMIN_ROLE, _initialOwner);
        _grantRole(WHITELISTER_ROLE, _whitelister);
        _grantRole(BLACKLISTER_ROLE, _blacklister);
    }

    /**
     * @dev Adds address to the whitelist.
     * @param account Address to add.
     */
    function _whitelist(address account) internal {
        accountStatus[account] = Status.WHITELISTED;
        emit Whitelisted(account);
    }

    /**
     * @dev Adds a single address to the whitelist.
     * @param account Address to add.
     */
    function whitelist(address account) external onlyRole(WHITELISTER_ROLE) {
        _whitelist(account);
    }

    /**
     * @dev Adds multiple addresses to the whitelist.
     * @param accounts Array of addresses to add.
     */
    function whitelist(address[] calldata accounts) external onlyRole(WHITELISTER_ROLE) {
        for (uint256 i; i < accounts.length; i++) {
            _whitelist(accounts[i]);
        }
    }

    /**
     * @dev Adds address to the blacklist.
     * @param account Address to add.
     */
    function _blacklist(address account) internal {
        accountStatus[account] = Status.BLACKLISTED;
        emit Blacklisted(account);
    }

    /**
     * @dev Adds a single address to the blacklist.
     * @param account Address to add.
     */
    function blacklist(address account) external onlyRole(BLACKLISTER_ROLE) {
        _blacklist(account);
    }

    /**
     * @dev Adds multiple addresses to the blacklist.
     * @param accounts Array of addresses to add.
     */
    function blacklist(address[] calldata accounts) external onlyRole(BLACKLISTER_ROLE) {
        for (uint256 i; i < accounts.length; i++) {
            _blacklist(accounts[i]);
        }
    }

    /**
     * @dev Removes address from the blacklist.
     * @param account Address to remove.
     */
    function _void(address account) internal {
        accountStatus[account] = Status.VOID;
        emit Voided(account);
    }

    /**
     * @dev Removes a single address from both whitelist and blacklist.
     * @param account Address to remove.
     */
    function void(address account) external onlyRole(WHITELISTER_ROLE) {
        _void(account);
    }

    /**
     * @dev Removes multiple addresses from both whitelist and blacklist.
     * @param accounts Array of addresses to remove.
     */
    function void(address[] calldata accounts) external onlyRole(WHITELISTER_ROLE) {
        for (uint256 i; i < accounts.length; i++) {
            _void(accounts[i]);
        }
    }

    /**
     * @dev Validates token transfer based on the blacklist.
     * @dev Takes into account burning and minting.
     * @param from Address sending tokens.
     * @param to Address receiving tokens.
     * @return valid True if the transfer is valid, false otherwise.
     */
    function isValid(address from, address to) external view returns (bool valid) {
        return to == address(0x0)
            || (
                accountStatus[to] != Status.BLACKLISTED
                    && (from == address(0x0) || accountStatus[from] != Status.BLACKLISTED)
            );
    }

    /**
     * @dev Strictly validates token transfer based on whitelist.
     * @dev Takes into account burning and minting.
     * @param from Address sending tokens.
     * @param to Address receiving tokens.
     * @return valid True if the transfer is valid, false otherwise.
     */
    function isValidStrict(address from, address to) external view returns (bool valid) {
        return to == address(0x0)
            || (
                accountStatus[to] == Status.WHITELISTED
                    && (from == address(0x0) || accountStatus[from] == Status.WHITELISTED)
            );
    }

    /**
     * @dev Returns whether account is whitelisted.
     * @return True if account is whitelisted.
     */
    function isWhitelisted(address account) external view returns (bool) {
        return accountStatus[account] == Status.WHITELISTED;
    }

    /**
     * @dev Returns whether account is blacklisted.
     * @return True if account is blacklisted.
     */
    function isBlacklisted(address account) external view returns (bool) {
        return accountStatus[account] == Status.BLACKLISTED;
    }
}
