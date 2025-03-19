// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Constants} from "./Constants.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {console} from "forge-std/console.sol";

import {stdError} from "forge-std/StdError.sol";

uint256 constant MIN_PRICE = 1e18;
uint256 constant NO_PRICE = 0;

error OwnableUnauthorizedAccount(address account);

abstract contract YieldOracleInvariants is Test, Constants {
    YieldOracle public yieldOracle;

    // function invariant_MonotonePrices() external view {
    //     assertGe(yieldOracle.currentPrice(), yieldOracle.previousPrice(), "Current price must never decrease over time");
    //     if (yieldOracle.nextPrice() > 0) {
    //         assertGe(yieldOracle.nextPrice(), yieldOracle.currentPrice(), "Next price must never decrease over time");
    //     }
    // }

    // function invariant_MinPrice() external view {
    //     assertGe(yieldOracle.currentPrice(), MIN_PRICE, "Prices must always be at least MIN_PRICE");
    //     assertGe(yieldOracle.previousPrice(), MIN_PRICE, "Prices must always be at least MIN_PRICE");
    // }

    // function invariant_NoFreeLunch() external view {
    //     uint256 someEud = 1.41247819372198e25;
    //     uint256 someEui = yieldOracle.assetsToShares(someEud);

    //     assertLe(
    //         yieldOracle.sharesToAssets(someEui), someEud, "Converting back and forth should never incease balance"
    //     );
    // }

    // function invariant_PriceIncrease() external view {
    //     assertGt(yieldOracle.maxPriceIncrease(), 0, "Price increase should be greater than 0");
    // }

    // function invariant_Delay() external view {
    //     assertGt(yieldOracle.updateDelay(), 0, "Update delay should be greater than 0");
    //     assertGt(yieldOracle.commitDelay(), 0, "Commit delay should be greater than 0");
    //     assertGt(
    //         yieldOracle.updateDelay(), yieldOracle.commitDelay(), "Update delay should be greater than commit delay"
    //     );
    // }
}

contract YieldOracleTest is Test, YieldOracleInvariants {
    function setUp() public {
        yieldOracle = new YieldOracle(address(this), address(0x0));
    }

    function testConstructor() public view {
        assertEq(yieldOracle.owner(), address(this));
        assertEq(yieldOracle.previousPrice(), MIN_PRICE);
        assertEq(yieldOracle.currentPrice(), MIN_PRICE);
        assertEq(yieldOracle.nextPrice(), NO_PRICE);
        assertEq(yieldOracle.maxPriceIncrease(), 1e17);
        assertEq(yieldOracle.updateDelay(), 1 days);
        assertEq(yieldOracle.commitDelay(), 1 hours);
    }

    function testGrantOracleRole(address account) public {
        yieldOracle.setOracle(account);
        assertEq(yieldOracle.oracle(), account);
    }

    function testAdminUpdateMaxPriceIncrease(uint256 amount) public {
        yieldOracle.setMaxPriceIncrease(amount);
        assertEq(yieldOracle.maxPriceIncrease(), amount);
    }

    function testSetDelay(uint256 delay) public {
        delay = bound(delay, yieldOracle.commitDelay(), type(uint256).max);
        assertEq(yieldOracle.owner(), address(this));

        yieldOracle.setUpdateDelay(delay);
        assertEq(yieldOracle.updateDelay(), delay);
    }

    function testUpdatePrice(address oracle, uint256 advanceUpdate, uint256 advanceCommit, uint256 increase) public {
        advanceUpdate = bound(advanceUpdate, yieldOracle.updateDelay(), 30 days);
        advanceCommit = bound(advanceCommit, yieldOracle.commitDelay() + 1, yieldOracle.updateDelay());

        uint256 price0 = yieldOracle.currentPrice();
        uint256 price1 = bound(increase, price0, price0 + yieldOracle.maxPriceIncrease());
        uint256 price2 = bound(increase, price1, price1 + yieldOracle.maxPriceIncrease());

        yieldOracle.setOracle(oracle);

        console.log("Hello1");

        skip(advanceUpdate + 1);
        vm.prank(oracle);
        yieldOracle.updatePrice(price1);
        assertEqDecimal(yieldOracle.previousPrice(), MIN_PRICE, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price0, 18);
        skip(advanceCommit + 1);
        assertEqDecimal(yieldOracle.previousPrice(), MIN_PRICE, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price0, 18);
        yieldOracle.commitPrice();
        assertEqDecimal(yieldOracle.previousPrice(), price0, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price1, 18);

        console.log("Hello2");

        skip(advanceUpdate + 1);
        vm.prank(oracle);
        yieldOracle.updatePrice(price2);
        assertEqDecimal(yieldOracle.previousPrice(), price0, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price1, 18);
        skip(advanceCommit + 1);
        assertEqDecimal(yieldOracle.previousPrice(), price0, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price1, 18);
        console.log("Hello3 previous", yieldOracle.previousPrice());
        console.log("Hello3 current", yieldOracle.currentPrice());
        console.log("Hello3 next", yieldOracle.nextPrice());
        yieldOracle.commitPrice();
        assertEqDecimal(yieldOracle.previousPrice(), price1, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price2, 18);
    }

    function testUnauthorizedUpdatePrice(address notOracle, address oracle) public {
        yieldOracle.setOracle(oracle);
        vm.assume(notOracle != address(this));
        assertNotEq(yieldOracle.oracle(), notOracle);

        vm.expectRevert("Restricted to oracle only");
        vm.prank(notOracle);
        yieldOracle.updatePrice(MIN_PRICE);
    }

    function testNotEnoughTimeBetweenPriceUpdates(address oracle, uint256 delay) public {
        delay = bound(delay, 0, yieldOracle.updateDelay() - 1);
        yieldOracle.setOracle(oracle);
        skip(delay);

        vm.expectRevert("Insufficient update delay");
        vm.prank(oracle);
        yieldOracle.updatePrice(MIN_PRICE);
    }

    function testPriceUpdateAboveLimit(address oracle, uint256 increase) public {
        increase = bound(increase, yieldOracle.maxPriceIncrease() + 1, type(uint256).max - yieldOracle.currentPrice());
        uint256 price = yieldOracle.currentPrice() + increase;
        yieldOracle.setOracle(oracle);
        skip(yieldOracle.updateDelay() + 1);

        vm.expectRevert("Price out of bounds");
        vm.prank(oracle);
        yieldOracle.updatePrice(price);
    }

    function testPriceUpdateBelowLimit(address oracle, uint256 price) public {
        price = bound(price, 0, MIN_PRICE - 1);
        yieldOracle.setOracle(oracle);
        skip(yieldOracle.updateDelay() + 1);

        vm.expectRevert(stdError.arithmeticError);
        vm.prank(oracle);
        yieldOracle.updatePrice(price);
    }

    function testAdminSetCurrentPriceBelowLimit(uint256 price) public {
        price = bound(price, 0, MIN_PRICE - 1);

        vm.expectRevert("Price out of bounds");
        yieldOracle.setCurrentPrice(price);
    }

    function testAdminSetCurrentPriceBelowOldPrice(uint256 price) public {
        price = bound(price, MIN_PRICE + 1, 1e37); // setting MIN_PRICE+1 to avoid revert for currentPrice < MIN_PRICE
        yieldOracle.setCurrentPrice(price); // First set high current price
        yieldOracle.setPreviousPrice(price);

        vm.expectRevert("Price out of bounds");
        yieldOracle.setCurrentPrice(price - 1);
    }

    function testAdminSetOldPriceBelowLimit(uint256 price) public {
        price = bound(price, 0, MIN_PRICE - 1);

        vm.expectRevert("Price out of bounds");
        yieldOracle.setPreviousPrice(price);
    }

    function testFromEudtoEui(uint256 amount, uint256 oldPrice, uint256 currentPrice) public {
        oldPrice = bound(oldPrice, 1e18, 1e37);
        currentPrice = bound(currentPrice, oldPrice, 1e37);
        amount = bound(amount, 1, 1e37);
        yieldOracle.setCurrentPrice(currentPrice);
        yieldOracle.setPreviousPrice(oldPrice);
        assertEq(yieldOracle.assetsToShares(amount), Math.mulDiv(amount, 1e18, currentPrice));
    }

    function testFromEuiToEud(uint256 amount, uint256 oldPrice, uint256 currentPrice) public {
        oldPrice = bound(oldPrice, 1e18, 1e37);
        currentPrice = bound(currentPrice, oldPrice, 1e37);
        amount = bound(amount, 1, 1e37);
        yieldOracle.setCurrentPrice(currentPrice);
        yieldOracle.setPreviousPrice(oldPrice);
        assertEq(yieldOracle.sharesToAssets(amount), Math.mulDiv(amount, oldPrice, 1e18));
    }

    /// forge-config: default.fuzz.runs = 2048
    function test_NumericalStability(uint256 price, uint256 balance) public {
        // Calculate an upperbound for EUI assuming a hourly 10 cent increase hourly
        // for 100 years
        uint256 maxPriceIncrease = 0.1e18;
        uint256 lowerBoundPrice = MIN_PRICE;
        uint256 hourlyFor100Years = (365 days * 100) / 1 hours;
        uint256 upperBoundPrice = lowerBoundPrice + maxPriceIncrease * hourlyFor100Years;

        price = bound(price, lowerBoundPrice, upperBoundPrice);

        // Use a balance between 0.1 cent and 1000 trillion EUD
        balance = bound(balance, 0.001e18, 1e33);

        yieldOracle.setCurrentPrice(price);
        yieldOracle.setPreviousPrice(price);

        assertEq(
            yieldOracle.currentPrice(),
            yieldOracle.previousPrice(),
            "Prices must be equal to isolate loss to truncation"
        );

        uint256 eudAmount = yieldOracle.sharesToAssets(balance);
        uint256 euiAmount = yieldOracle.assetsToShares(eudAmount);

        assertApproxEqRelDecimal(euiAmount, balance, 0.0000000001e18, 18);
    }
}

contract Ownable is Test, YieldOracleInvariants {
    address admin;
    address pauser;
    address oracle;
    address nobody;

    function setUp() public {
        admin = address(this);
        oracle = makeAddr("oracle");
        nobody = makeAddr("nobody");
        yieldOracle = new YieldOracle(admin, oracle);
    }

    function test_RevertWhen_RoleIsNobody() public {
        vm.startPrank(nobody);

        vm.expectRevert("Restricted to oracle only");
        yieldOracle.updatePrice(MIN_PRICE);

        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, nobody));
        yieldOracle.setMaxPriceIncrease(1e17);

        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, nobody));
        yieldOracle.setUpdateDelay(1 hours);

        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, nobody));
        yieldOracle.setCurrentPrice(MIN_PRICE);

        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, nobody));
        yieldOracle.setPreviousPrice(MIN_PRICE);

        // Allowed methods
        yieldOracle.sharesToAssets(MIN_PRICE);
        yieldOracle.assetsToShares(MIN_PRICE);

        vm.stopPrank();
    }

    function test_RevertWhen_RoleIsAdmin() public {
        assertEq(yieldOracle.owner(), admin);
        vm.startPrank(admin);

        vm.expectRevert("Restricted to oracle only");
        yieldOracle.updatePrice(MIN_PRICE);

        // Allowed methods
        yieldOracle.setMaxPriceIncrease(1e17);
        yieldOracle.setUpdateDelay(1 hours);
        yieldOracle.setCurrentPrice(MIN_PRICE);
        yieldOracle.setPreviousPrice(MIN_PRICE);
        yieldOracle.sharesToAssets(MIN_PRICE);
        yieldOracle.assetsToShares(MIN_PRICE);

        vm.stopPrank();
    }

    function test_RevertWhen_RoleIsOracle() public {
        assertEq(yieldOracle.owner(), admin);
        vm.startPrank(oracle);

        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, oracle));
        yieldOracle.setMaxPriceIncrease(1e17);

        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, oracle));
        yieldOracle.setUpdateDelay(1 hours);

        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, oracle));
        yieldOracle.setCurrentPrice(MIN_PRICE);

        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, oracle));
        yieldOracle.setPreviousPrice(MIN_PRICE);

        // Allowed methods
        skip(yieldOracle.updateDelay() + 1); // make updatePrice a legal operation
        yieldOracle.updatePrice(MIN_PRICE);
        yieldOracle.sharesToAssets(MIN_PRICE);
        yieldOracle.assetsToShares(MIN_PRICE);

        vm.stopPrank();
    }
}

contract UpdatePrice is Test, YieldOracleInvariants {
    function setUp() public {
        yieldOracle = new YieldOracle(address(this), address(this));

        skip(yieldOracle.updateDelay() + 1);
    }

    modifier skipEpochs(uint256 epochs) {
        // simulate 10 epochs
        for (uint256 i = 0; i < epochs; i++) {
            skip(yieldOracle.updateDelay() + 1);
            yieldOracle.updatePrice(yieldOracle.currentPrice() + yieldOracle.maxPriceIncrease());
            skip(yieldOracle.commitDelay() + 1);
            yieldOracle.commitPrice();
        }

        skip(yieldOracle.updateDelay() + 1);

        _;
    }

    function testFuzz_RevertWhen_PriceIsBelowLimit(uint256 price) public {
        price = bound(price, 0, MIN_PRICE - 1);

        vm.expectRevert(stdError.arithmeticError);
        yieldOracle.updatePrice(price);
    }

    function testFuzz_RevertWhen_PriceIsAboveLimit(uint256 price) public {
        price = bound(price, yieldOracle.currentPrice() + yieldOracle.maxPriceIncrease() + 1, type(uint256).max);

        vm.expectRevert("Price out of bounds");
        yieldOracle.updatePrice(price);
    }

    function testFuzz_RevertWhen_PriceIsBelowPrevious(uint256 price) public skipEpochs(10) {
        price = bound(price, MIN_PRICE, yieldOracle.currentPrice() - 1);

        vm.expectRevert(stdError.arithmeticError);
        yieldOracle.updatePrice(price);
    }

    function testFuzz_PriceInRange(uint256 price) public {
        price = bound(price, yieldOracle.currentPrice(), yieldOracle.currentPrice() + yieldOracle.maxPriceIncrease());

        uint256 currentPriceBefore = yieldOracle.currentPrice();
        yieldOracle.updatePrice(price);
        assertEq(yieldOracle.currentPrice(), currentPriceBefore, "updatePrice does not change currentPrice");
        assertEq(yieldOracle.nextPrice(), price, "updatePrice sets nextPrice");
    }

    function test_RevertIf_SenderIsntOracle() public {
        uint256 price = yieldOracle.currentPrice() + 1;

        vm.expectRevert("Restricted to oracle only");
        vm.prank(makeAddr("nobody"));
        yieldOracle.updatePrice(price);
    }

    function test_RevertIf_NotEnoughTimePassed() public {
        uint256 price = yieldOracle.currentPrice() + 1;
        yieldOracle.updatePrice(price);

        vm.expectRevert("Insufficient update delay");
        yieldOracle.updatePrice(price);
    }

    function test_CommitsPriceAfterCommitDelay() public {
        uint256 price0 = yieldOracle.currentPrice();
        yieldOracle.updatePrice(price0 + 1);
        assertLe(yieldOracle.previousPrice(), yieldOracle.currentPrice(), "invariant");
        assertEq(yieldOracle.currentPrice(), price0, "updatePrice does not change currentPrice");
        assertEq(yieldOracle.nextPrice(), price0 + 1, "updatePrice sets nextPrice");

        // "forget" to commit price before the next update window starts
        skip(yieldOracle.updateDelay() + 1);
        assertNotEq(yieldOracle.nextPrice(), NO_PRICE, "nextPrice should be set");

        // We expect this to revert, despite the invariant that currentPrice <= nextPrice,
        // however here nextPrice is not yet committed even though the commitDelay has passed
        vm.expectRevert(stdError.arithmeticError);
        yieldOracle.updatePrice(price0);

        yieldOracle.updatePrice(price0 + 2);
        assertEq(yieldOracle.previousPrice(), price0, "updatePrice commits pending nextPrice");
        assertEq(yieldOracle.currentPrice(), price0 + 1, "updatePrice commits pending nextPrice");
        assertEq(yieldOracle.nextPrice(), price0 + 2, "updatePrice sets nextPrice");
    }
}

contract CommitPrice is Test, YieldOracleInvariants {
    function setUp() public {
        yieldOracle = new YieldOracle(address(this), address(this));

        skip(yieldOracle.updateDelay() + 1);
    }

    function test_RevertIf_NoPriceSet() public {
        assertEq(yieldOracle.nextPrice(), NO_PRICE, "nextPrice should not be set");

        vm.expectRevert(stdError.arithmeticError);
        yieldOracle.commitPrice();
    }

    function testFuzz_RevertIf_NotEnoughTimePassed(uint256 delay) public {
        uint256 price = yieldOracle.currentPrice() + 1;
        yieldOracle.updatePrice(price);

        assertEq(yieldOracle.nextPrice(), price, "nextPrice should be set");
        delay = bound(delay, 0, yieldOracle.commitDelay() - 1);

        skip(delay);

        vm.expectRevert("Insufficient commit delay");
        yieldOracle.commitPrice();
    }

    function test_AnybodyCanCommit() public {
        uint256 price = yieldOracle.currentPrice() + 1;
        yieldOracle.updatePrice(price);

        assertEq(yieldOracle.nextPrice(), price, "nextPrice should be set");
        skip(yieldOracle.commitDelay() + 1);

        vm.prank(makeAddr("nobody"));
        yieldOracle.commitPrice();
        assertEq(yieldOracle.currentPrice(), price, "currentPrice should be set");
        assertEq(yieldOracle.nextPrice(), NO_PRICE, "nextPrice should be reset");
    }

    function test_CommitClearsNextPrice() public {
        uint256 price = yieldOracle.currentPrice() + 1;
        yieldOracle.updatePrice(price);

        assertEq(yieldOracle.nextPrice(), price, "nextPrice should be set");
        skip(yieldOracle.commitDelay() + 1);
        yieldOracle.commitPrice();
        assertEq(yieldOracle.nextPrice(), NO_PRICE, "nextPrice should be reset");
    }

    function test_RevertWhen_CommitTwice() public {
        uint256 price = yieldOracle.currentPrice() + 1;
        yieldOracle.updatePrice(price);

        assertEq(yieldOracle.nextPrice(), price, "nextPrice should be set");
        skip(yieldOracle.commitDelay() + 1);
        yieldOracle.commitPrice();
        assertEq(yieldOracle.nextPrice(), NO_PRICE, "nextPrice should be reset");

        vm.expectRevert(stdError.arithmeticError);
        yieldOracle.commitPrice();
    }
}

contract AdminUpdates is Test, YieldOracleInvariants {
    function setUp() public {
        yieldOracle = new YieldOracle(address(this), address(this));

        skip(yieldOracle.updateDelay() + 1);
    }

    function test_ValidResetSequence() public {
        yieldOracle.resetNextPrice();
        yieldOracle.setCurrentPrice(15 ** 18);
        yieldOracle.setPreviousPrice(14 ** 18);

        yieldOracle.setUpdateDelay(10 days);
        yieldOracle.setCommitDelay(1 days);

        yieldOracle.setMaxPriceIncrease(10);
    }
}
