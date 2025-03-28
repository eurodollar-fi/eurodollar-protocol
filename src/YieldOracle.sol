// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited
pragma solidity ^0.8.21;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IYieldOracle} from "./interfaces/IYieldOracle.sol";

contract YieldOracle is IYieldOracle, Ownable {
    /*  CONSTANTS */

    uint256 internal constant MIN_PRICE = 1e18; // Minimum price
    uint256 internal constant NO_PRICE = 0; // Sentinel value to indicate empty

    /*  STATE VARIABLES */

    /// @notice Address of the oracle that updates the price.
    address public oracle;

    /// @notice Last time the price was updated.
    uint256 public lastUpdate;
    /// @notice Delay between updates.
    uint256 public updateDelay;
    /// @notice Delay between commits.
    uint256 public commitDelay;

    uint256 public previousPrice;
    uint256 public currentPrice;
    uint256 public nextPrice;
    uint256 public maxPriceIncrease;

    /*  EVENTS */

    /// @notice Emitted when the price is updated.
    event PriceUpdated(uint256 newPrice);
    /// @notice Emitted when the price is committed.
    event PriceCommitted(uint256 newCurrentPrice);

    /*  MODIFIERS */

    /// @notice Modifier to assure the caller is the oracle.
    modifier onlyOracle() {
        require(msg.sender == oracle, "Restricted to oracle only");
        _;
    }

    /*  CONSTRUCTOR */

    constructor(
        address _initialOwner,
        address _initialOracle
    ) Ownable(_initialOwner) {
        oracle = _initialOracle;

        previousPrice = MIN_PRICE;
        currentPrice = MIN_PRICE;
        nextPrice = NO_PRICE;
        maxPriceIncrease = 0.1e18;

        updateDelay = 1 days;
        commitDelay = 1 hours;

        lastUpdate = block.timestamp;
    }

    /*  PUBLIC FUNCTIONS */

    /**
     * @notice Updates the price.
     * @param price The new price to be set.
     */
    function updatePrice(uint256 price) external onlyOracle {
        // Enforce at least updateDelay between updates
        require(
            lastUpdate + updateDelay < block.timestamp,
            "Insufficient update delay"
        );

        if (nextPrice != NO_PRICE) {
            previousPrice = currentPrice;
            currentPrice = nextPrice;

            emit PriceCommitted(currentPrice);
        }

        require(
            price - currentPrice <= maxPriceIncrease,
            "Price out of bounds"
        );

        nextPrice = price;
        lastUpdate = block.timestamp;

        emit PriceUpdated(price);
    }

    /**
     * @notice Commits the price.
     */
    function commitPrice() public {
        require(nextPrice - currentPrice >= 0, "Price out of bounds");

        // Enforce at least commitDelay after the last update
        require(
            lastUpdate + commitDelay < block.timestamp,
            "Insufficient commit delay"
        );

        previousPrice = currentPrice;
        currentPrice = nextPrice;
        nextPrice = NO_PRICE;

        emit PriceCommitted(currentPrice);
    }

    /*  ADMIN FUNCTIONS */

    /**
     * @notice Sets the oracle.
     * @param _oracle The new oracle.
     */
    function setOracle(address _oracle) external onlyOwner {
        oracle = _oracle;
    }

    /**
     * @notice Updates the maximum price increase.
     * @param _maxPriceIncrease The new maximum price increase.
     */
    function setMaxPriceIncrease(uint256 _maxPriceIncrease) external onlyOwner {
        maxPriceIncrease = _maxPriceIncrease;
    }

    /**
     * @notice Updates the commit delay.
     * @param delay The new commit delay.
     */
    function setCommitDelay(uint256 delay) external onlyOwner {
        require(delay <= updateDelay, "Delay out of bounds");

        commitDelay = delay;
    }

    /**
     * @notice Updates the update delay.
     * @param delay The new update delay.
     */
    function setUpdateDelay(uint256 delay) external onlyOwner {
        require(commitDelay <= delay, "Delay out of bounds");

        updateDelay = delay;
    }

    /**
     * @notice Updates the current price.
     * @param price The new current price.
     */
    function setCurrentPrice(uint256 price) external onlyOwner {
        require(
            MIN_PRICE <= price && previousPrice <= price,
            "Price out of bounds"
        );

        currentPrice = price;
    }

    /**
     * @notice Updates the previous price.
     * @param price The new previous price.
     */
    function setPreviousPrice(uint256 price) external onlyOwner {
        require(
            MIN_PRICE <= price && price <= currentPrice,
            "Price out of bounds"
        );

        previousPrice = price;
    }

    /**
     * @notice Resets the next price.
     */
    function resetNextPrice() external onlyOwner {
        nextPrice = NO_PRICE;
    }

    /**
     * @notice Converts assets to shares.
     * @param assets The amount of assets.
     * @return The amount of shares.
     */
    function assetsToShares(uint256 assets) external view returns (uint256) {
        return Math.mulDiv(assets, 10 ** 18, currentPrice);
    }

    /**
     * @notice Converts shares to assets.
     * @param shares The amount of shares.
     * @return The amount of assets.
     */
    function sharesToAssets(uint256 shares) external view returns (uint256) {
        return Math.mulDiv(shares, previousPrice, 10 ** 18);
    }
}
