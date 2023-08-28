// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited
pragma solidity ^0.8.12;
import "oz/security/Pausable.sol";
import "oz/access/AccessControl.sol";
import "oz/utils/math/Math.sol";

/**
 * @author  Fenris
 * @title   YieldOracle
 * @dev     A contract that implements a yield oracle for EuroInvest (EUI) based on epoch-based pricing.
 * @dev     The oracle provides price data to determine how much EuroDollar (EUD) is needed to flip to EUI tokens for each epoch.
 * @dev     The oracle allows price updates based on the `ORACLE_ROLE` and pausing functionality using the `PAUSE_ROLE`.
 */
contract YieldOracle is Pausable, AccessControl {
    using Math for uint256;

    uint128 public oldPrice;
    uint128 public currentPrice;
    uint256 public maxPriceIncrease;
    uint256 public lastUpdate;
    uint256 public delay;

    // Roles
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    /**
     * @notice  The constructor sets up the contract with the specified access control address, initial prices, and the maximum price increase.
     * @dev     Constructor to initialize the YieldOracle contract.
     * @param   account The address of the EuroDollarAccessControl contract for role-based access control.
     */
    constructor(address account) {
        _grantRole(DEFAULT_ADMIN_ROLE, account);
        oldPrice = 1e18;
        currentPrice = 1e18;
        lastUpdate = block.timestamp;
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
        require(block.timestamp >= lastUpdate + delay, "YieldOracle: price can only be updated once per hour");
        require(newPrice-currentPrice <= maxPriceIncrease, "YieldOracle: price increase exceeds maximum allowed");
        lastUpdate = block.timestamp;
        oldPrice = currentPrice;
        currentPrice = newPrice;
        return true;
    }

    function setMaxPriceIncrease(uint256 _maxPriceIncrease) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused returns (bool) {
        maxPriceIncrease = _maxPriceIncrease;
        return true;
    }


    function setDelay(uint256 _delay) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused returns (bool) {
        delay = _delay;
        return true;
    }

    /**
     * @notice  This function is a read-only function and does not modify any state in the contract.
     * @dev     Function to calculate the equivalent amount of EUI tokens for a given amount of EUD tokens.
     * @param   eudAmount  The amount of EUD tokens for which the equivalent EUI tokens need to be calculated.
     * @return  uint256  The equivalent amount of EUI tokens based on the current price from the yield oracle.
     */
    function fromEudToEui(uint256 eudAmount) public view returns (uint256) {
        return
            eudAmount.mulDiv(
                10 ** 18,
                currentPrice,
                Math.Rounding.Down
            );
    }

    /**
     * @notice  This function is a read-only function and does not modify any state in the contract.
     * @dev     Function to calculate the equivalent amount of EUD tokens for a given amount of EUI tokens.
     * @param   euiAmount  The amount of EUI tokens for which the equivalent EUD tokens need to be calculated.
     * @return  uint256  The equivalent amount of EUD tokens based on the previous epoch price from the yield oracle.
     */
    function fromEuiToEud(uint256 euiAmount) public view returns (uint256) {
        return
            euiAmount.mulDiv(
                oldPrice,
                10 ** 18,
                Math.Rounding.Down
            );
    }
}
