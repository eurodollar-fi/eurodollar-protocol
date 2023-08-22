// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;
import "openzeppelin-contracts/contracts/security/Pausable.sol";
import "openzeppelin-contracts/contracts/access/AccessControl.sol";

/**
 * @author  Fenris
 * @title   YieldOracle
 * @dev     A contract that implements a yield oracle for EuroInvest (EUI) based on epoch-based pricing.
 * @dev     The oracle provides price data to determine how much EuroDollar (EUD) is needed to flip to EUI tokens for each epoch.
 * @dev     The oracle allows price updates based on the `ORACLE_ROLE` and pausing functionality using the `PAUSE_ROLE`.
 */
contract YieldOracle is Pausable, AccessControl {
    uint128 public oldPrice;
    uint128 public currentPrice;

    // Roles
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    /**
     * @notice  The constructor sets up the contract with the specified access control address, initial prices, and the maximum price increase.
     * @dev     Constructor to initialize the YieldOracle contract.
     * @param   account The address of the EuroDollarAccessControl contract for role-based access control.
     */
    constructor(
        address account
    ) Pausable() {
        _grantRole(DEFAULT_ADMIN_ROLE, account);
        oldPrice = 1e18;
        currentPrice = 1e18;
    }

    // Pausable
    /**
     * @notice  This function can only be called by an account with the `PAUSE_ROLE`.
     * @notice  It pauses certain functionalities of the contract, preventing certain actions.
     * @notice  Once paused, certain operations may not be available until the contract is unpaused.
     * @dev     Pauses the contract functionality.
     */
    function pause() public onlyRole(PAUSE_ROLE) {
        _pause();
    }

    /**
     * @notice  This function can only be called by an account with the `PAUSE_ROLE`.
     * @notice  It resumes certain functionalities of the contract that were previously paused.
     * @notice  Once unpaused, the contract regains its full functionality.
     * @dev     Unpauses the contract functionality.
     */
    function unpause() public onlyRole(PAUSE_ROLE) {
        _unpause();
    }

    /**
     * @notice  This function is accessible only to accounts with the `ORACLE_ROLE`.
     * @notice  The new price must not exceed the allowed price increase compared to the previous epoch's price.
     * @notice  The new price must be greater than or equal to the previous epoch's price.
     * @notice  The epoch number is incremented after successful price update.
     * @dev     Function to update the price for the next epoch.
     * @param   newPrice The new price for the next epoch.
     * @return  bool    A boolean indicating the success of the price update.
     */
    function updatePrice(
        uint128 newPrice
    ) external onlyRole(ORACLE_ROLE) whenNotPaused returns (bool) {
        oldPrice = currentPrice;
        currentPrice = newPrice;
        return true;
    }
}
