// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "oz/proxy/ERC1967/ERC1967Proxy.sol";
import "oz/access/AccessControl.sol";

/**
 * @author  Fenris
 * @title   TokenProxy
 * @dev     A transparent proxy contract using ERC1967Proxy pattern to delegate calls to a logic contract.
 * @dev     It inherits from ERC1967Proxy, which enables it to upgrade the implementation logic.
 * @dev     This contract is used to facilitate upgrades without changing the contract address.
 */
contract TokenProxy is ERC1967Proxy, AccessControl {

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /**
     * @notice  The constructor is called once during deployment to set the initial implementation and data.
     * @dev     Constructor to initialize the proxy contract.
     * @param   _logic The address of the initial logic contract that the proxy delegates calls to.
     * @param   _data The data containing the logic contract initialization code.
     */
    constructor(
        address _logic,
        bytes memory _data,
        address account
    ) ERC1967Proxy(_logic, _data) {
        _grantRole(DEFAULT_ADMIN_ROLE, account);
    }

    /**
     * @notice  This function allows querying the current logic contract implementation.
     * @dev     Returns the current implementation address of the proxy contract.
     * @return  impl The address of the current logic contract implementation.
     */
    function implementation() external view returns (address impl) {
        // Custom implementation of foo in the derived contract
        impl = _implementation();
        return impl;
    }

    /**
     * @notice  This function allows upgrading the logic contract implementation.
     * @dev     Upgrades the implementation logic to a new contract address.
     * @param   newImplementation The address of the new logic contract to which calls will be delegated.
     */
    function upgradeTo(
        address newImplementation
    ) external onlyRole(UPGRADER_ROLE) {
        _upgradeTo(newImplementation);
    }
}
