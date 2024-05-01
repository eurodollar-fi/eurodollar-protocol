// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited
pragma solidity ^0.8.21;

import {Test, stdError} from "forge-std/Test.sol";
import {Strings} from "oz/utils/Strings.sol";
import {Math} from "oz/utils/math/Math.sol";
import {Constants} from "./Constants.sol";
import {MIN_PRICE, NO_PRICE, YieldOracle} from "../src/YieldOracle.sol";

abstract contract YieldOracleInvariants is Test, Constants {
    YieldOracle public yieldOracle;

    function invariant_MonotonePrices() external {
        assertGe(
            yieldOracle.currentPrice(),
            yieldOracle.previousPrice(),
            "Current price must never decrease over time"
        );
        if (yieldOracle.nextPrice() > 0) {
            assertGe(
                yieldOracle.nextPrice(),
                yieldOracle.currentPrice(),
                "Next price must never decrease over time"
            );
        }
    }

    function invariant_MinPrice() external {
        assertGe(
            yieldOracle.currentPrice(),
            MIN_PRICE,
            "Prices must always be at least MIN_PRICE"
        );
        assertGe(
            yieldOracle.previousPrice(),
            MIN_PRICE,
            "Prices must always be at least MIN_PRICE"
        );
    }

    function invariant_NoFreeLunch() external {
        uint256 someEud = 1.41247819372198e25;
        uint256 someEui = yieldOracle.fromEudToEui(someEud);

        assertLe(
            yieldOracle.fromEuiToEud(someEui),
            someEud,
            "Converting back and forth should never incease balance"
        );
    }

    function invariant_PriceIncrease() external {
        assertGt(
            yieldOracle.maxPriceIncrease(),
            0,
            "Price increase should be greater than 0"
        );
    }

    function invariant_Delay() external {
        assertGt(
            yieldOracle.updateDelay(),
            0,
            "Update delay should be greater than 0"
        );
        assertGt(
            yieldOracle.commitDelay(),
            0,
            "Commit delay should be greater than 0"
        );
        assertGt(
            yieldOracle.updateDelay(),
            yieldOracle.commitDelay(),
            "Update delay should be greater than commit delay"
        );
    }
}

contract YieldOracleTest is Test, YieldOracleInvariants {
    function setUp() public {
        yieldOracle = new YieldOracle();
    }

    function testConstructor() public {
        assertTrue(
            yieldOracle.hasRole(yieldOracle.DEFAULT_ADMIN_ROLE(), address(this))
        );
        assertEq(yieldOracle.previousPrice(), MIN_PRICE);
        assertEq(yieldOracle.currentPrice(), MIN_PRICE);
        assertEq(yieldOracle.nextPrice(), NO_PRICE);
        assertEq(yieldOracle.maxPriceIncrease(), 1e17);
        assertEq(yieldOracle.updateDelay(), 1 days);
        assertEq(yieldOracle.commitDelay(), 1 hours);
    }

    function testGrantOracleRole(address account) public {
        yieldOracle.grantRole(yieldOracle.ORACLE_ROLE(), account);
        assertTrue(yieldOracle.hasRole(yieldOracle.ORACLE_ROLE(), account));
    }

    function testUnauthorizedGrantOracleRole(address account) public {
        bytes32 role = yieldOracle.ORACLE_ROLE();

        // Ensure the account is not able to grant the PAUSE role
        bytes32 roleAdmin = yieldOracle.getRoleAdmin(role);
        vm.assume(!yieldOracle.hasRole(roleAdmin, account));

        vm.expectRevert(
            accessControlError(account, yieldOracle.DEFAULT_ADMIN_ROLE())
        );
        vm.prank(account);
        yieldOracle.grantRole(role, account);
    }

    function testAdminUpdateMaxPriceIncrease(uint256 amount) public {
        assertTrue(
            yieldOracle.hasRole(yieldOracle.DEFAULT_ADMIN_ROLE(), address(this))
        );

        yieldOracle.adminUpdateMaxPriceIncrease(amount);
        assertEq(yieldOracle.maxPriceIncrease(), amount);
    }

    function testSetDelay(uint256 delay) public {
        delay = bound(delay, yieldOracle.commitDelay(), type(uint256).max);
        assertTrue(
            yieldOracle.hasRole(yieldOracle.DEFAULT_ADMIN_ROLE(), address(this))
        );

        yieldOracle.adminUpdateDelay(delay);
        assertEq(yieldOracle.updateDelay(), delay);
    }

    function testUpdatePrice(
        address oracle,
        uint256 advanceUpdate,
        uint256 advanceCommit,
        uint256 increase
    ) public {
        advanceUpdate = bound(
            advanceUpdate,
            yieldOracle.updateDelay(),
            30 days
        );
        advanceCommit = bound(
            advanceCommit,
            yieldOracle.commitDelay(),
            yieldOracle.updateDelay() - 1
        );

        uint256 price0 = yieldOracle.currentPrice();
        uint256 price1 = bound(
            increase,
            price0,
            price0 + yieldOracle.maxPriceIncrease()
        );
        uint256 price2 = bound(
            increase,
            price1,
            price1 + yieldOracle.maxPriceIncrease()
        );

        yieldOracle.grantRole(yieldOracle.ORACLE_ROLE(), oracle);

        skip(advanceUpdate);
        vm.prank(oracle);
        yieldOracle.updatePrice(price1);
        assertEqDecimal(yieldOracle.previousPrice(), MIN_PRICE, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price0, 18);
        skip(advanceCommit);
        assertEqDecimal(yieldOracle.previousPrice(), MIN_PRICE, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price0, 18);
        yieldOracle.commitPrice();
        assertEqDecimal(yieldOracle.previousPrice(), price0, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price1, 18);

        skip(advanceUpdate);
        vm.prank(oracle);
        yieldOracle.updatePrice(price2);
        assertEqDecimal(yieldOracle.previousPrice(), price0, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price1, 18);
        skip(advanceCommit);
        assertEqDecimal(yieldOracle.previousPrice(), price0, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price1, 18);
        yieldOracle.commitPrice();
        assertEqDecimal(yieldOracle.previousPrice(), price1, 18);
        assertEqDecimal(yieldOracle.currentPrice(), price2, 18);
    }

    function testUnauthorizedUpdatePrice(address notOracle) public {
        vm.assume(notOracle != address(this));
        assert(!yieldOracle.hasRole(yieldOracle.ORACLE_ROLE(), notOracle));

        vm.expectRevert(
            accessControlError(notOracle, yieldOracle.ORACLE_ROLE())
        );
        vm.prank(notOracle);
        yieldOracle.updatePrice(MIN_PRICE);
    }

    function testNotEnoughTimeBetweenPriceUpdates(
        address oracle,
        uint256 delay
    ) public {
        delay = bound(delay, 0, yieldOracle.updateDelay() - 1);
        yieldOracle.grantRole(yieldOracle.ORACLE_ROLE(), oracle);
        skip(delay);

        vm.expectRevert(bytes("Insufficient update delay"));
        vm.prank(oracle);
        yieldOracle.updatePrice(MIN_PRICE);
    }

    function testPriceUpdateAboveLimit(
        address oracle,
        uint256 increase
    ) public {
        increase = bound(
            increase,
            yieldOracle.maxPriceIncrease() + 1,
            type(uint256).max - yieldOracle.currentPrice()
        );
        uint256 price = yieldOracle.currentPrice() + increase;
        yieldOracle.grantRole(yieldOracle.ORACLE_ROLE(), oracle);
        skip(yieldOracle.updateDelay());

        vm.expectRevert("Price out of bounds");
        vm.prank(oracle);
        yieldOracle.updatePrice(price);
    }

    function testPriceUpdateBelowLimit(address oracle, uint256 price) public {
        price = bound(price, 0, MIN_PRICE - 1);
        yieldOracle.grantRole(yieldOracle.ORACLE_ROLE(), oracle);
        skip(yieldOracle.updateDelay());

        vm.expectRevert(stdError.arithmeticError);
        vm.prank(oracle);
        yieldOracle.updatePrice(price);
    }

    function testAdminSetCurrentPriceBelowLimit(uint256 price) public {
        price = bound(price, 0, MIN_PRICE - 1);

        vm.expectRevert("Price out of bounds");
        yieldOracle.adminUpdateCurrentPrice(price);
    }

    function testAdminSetCurrentPriceBelowOldPrice(uint256 price) public {
        price = bound(price, MIN_PRICE + 1, 1e37); // setting MIN_PRICE+1 to avoid revert for currentPrice < MIN_PRICE
        yieldOracle.adminUpdateCurrentPrice(price); // First set high current price
        yieldOracle.adminUpdatePreviousPrice(price);

        vm.expectRevert("Price out of bounds");
        yieldOracle.adminUpdateCurrentPrice(price - 1);
    }

    function testAdminSetOldPriceBelowLimit(uint256 price) public {
        price = bound(price, 0, MIN_PRICE - 1);

        vm.expectRevert("Price out of bounds");
        yieldOracle.adminUpdatePreviousPrice(price);
    }

    function testFromEudtoEui(
        uint256 amount,
        uint256 oldPrice,
        uint256 currentPrice
    ) public {
        oldPrice = bound(oldPrice, 1e18, 1e37);
        currentPrice = bound(currentPrice, oldPrice, 1e37);
        amount = bound(amount, 1, 1e37);
        yieldOracle.adminUpdateCurrentPrice(currentPrice);
        yieldOracle.adminUpdatePreviousPrice(oldPrice);
        assertEq(
            yieldOracle.fromEudToEui(amount),
            Math.mulDiv(amount, 1e18, currentPrice)
        );
    }

    function testFromEuiToEud(
        uint256 amount,
        uint256 oldPrice,
        uint256 currentPrice
    ) public {
        oldPrice = bound(oldPrice, 1e18, 1e37);
        currentPrice = bound(currentPrice, oldPrice, 1e37);
        amount = bound(amount, 1, 1e37);
        yieldOracle.adminUpdateCurrentPrice(currentPrice);
        yieldOracle.adminUpdatePreviousPrice(oldPrice);
        assertEq(
            yieldOracle.fromEuiToEud(amount),
            Math.mulDiv(amount, oldPrice, 1e18)
        );
    }

    /// forge-config: default.fuzz.runs = 2048
    function test_NumericalStability(uint256 price, uint256 balance) public {
        // Calculate an upperbound for EUI assuming a hourly 10 cent increase hourly
        // for 100 years
        uint256 maxPriceIncrease = 0.1e18;
        uint256 lowerBoundPrice = MIN_PRICE;
        uint256 hourlyFor100Years = (365 days * 100) / 1 hours;
        uint256 upperBoundPrice = lowerBoundPrice +
            maxPriceIncrease *
            hourlyFor100Years;

        price = bound(price, lowerBoundPrice, upperBoundPrice);

        // Use a balance between 0.1 cent and 1000 trillion EUD
        balance = bound(balance, 0.001e18, 1e33);

        yieldOracle.adminUpdateCurrentPrice(price);
        yieldOracle.adminUpdatePreviousPrice(price);

        assertEq(
            yieldOracle.currentPrice(),
            yieldOracle.previousPrice(),
            "Prices must be equal to isolate loss to truncation"
        );

        uint256 eudAmount = yieldOracle.fromEuiToEud(balance);
        uint256 euiAmount = yieldOracle.fromEudToEui(eudAmount);

        assertApproxEqRelDecimal(euiAmount, balance, 0.0000000001e18, 18);
    }
}

function accessControlError(
    address account,
    bytes32 role
) pure returns (bytes memory) {
    return
        abi.encodePacked(
            "AccessControl: account ",
            Strings.toHexString(account),
            " is missing role ",
            Strings.toHexString(uint256(role), 32)
        );
}

contract AccessControl is Test, YieldOracleInvariants {
    address admin;
    address pauser;
    address oracle;
    address nobody;

    function setUp() public {
        yieldOracle = new YieldOracle();

        admin = address(this);
        oracle = makeAddr("oracle");
        yieldOracle.grantRole(yieldOracle.ORACLE_ROLE(), oracle);
        nobody = makeAddr("nobody");
    }

    function test_RevertWhen_RoleIsNobody() public {
        vm.startPrank(nobody);

        vm.expectRevert(accessControlError(nobody, yieldOracle.ORACLE_ROLE()));
        yieldOracle.updatePrice(MIN_PRICE);

        vm.expectRevert(
            accessControlError(nobody, yieldOracle.DEFAULT_ADMIN_ROLE())
        );
        yieldOracle.adminUpdateMaxPriceIncrease(1e17);

        vm.expectRevert(
            accessControlError(nobody, yieldOracle.DEFAULT_ADMIN_ROLE())
        );
        yieldOracle.adminUpdateDelay(1 hours);

        vm.expectRevert(
            accessControlError(nobody, yieldOracle.DEFAULT_ADMIN_ROLE())
        );
        yieldOracle.adminUpdateCurrentPrice(MIN_PRICE);

        vm.expectRevert(
            accessControlError(nobody, yieldOracle.DEFAULT_ADMIN_ROLE())
        );
        yieldOracle.adminUpdatePreviousPrice(MIN_PRICE);

        // Allowed methods
        yieldOracle.fromEuiToEud(MIN_PRICE);
        yieldOracle.fromEudToEui(MIN_PRICE);

        vm.stopPrank();
    }

    function test_RevertWhen_RoleIsAdmin() public {
        assertTrue(
            yieldOracle.hasRole(yieldOracle.DEFAULT_ADMIN_ROLE(), admin)
        );
        vm.startPrank(admin);

        vm.expectRevert(accessControlError(admin, yieldOracle.ORACLE_ROLE()));
        yieldOracle.updatePrice(MIN_PRICE);

        // Allowed methods
        yieldOracle.adminUpdateMaxPriceIncrease(1e17);
        yieldOracle.adminUpdateDelay(1 hours);
        yieldOracle.adminUpdateCurrentPrice(MIN_PRICE);
        yieldOracle.adminUpdatePreviousPrice(MIN_PRICE);
        yieldOracle.fromEuiToEud(MIN_PRICE);
        yieldOracle.fromEudToEui(MIN_PRICE);

        vm.stopPrank();
    }

    function test_RevertWhen_RoleIsOracle() public {
        assertTrue(yieldOracle.hasRole(yieldOracle.ORACLE_ROLE(), oracle));
        vm.startPrank(oracle);

        vm.expectRevert(
            accessControlError(oracle, yieldOracle.DEFAULT_ADMIN_ROLE())
        );
        yieldOracle.adminUpdateMaxPriceIncrease(1e17);

        vm.expectRevert(
            accessControlError(oracle, yieldOracle.DEFAULT_ADMIN_ROLE())
        );
        yieldOracle.adminUpdateDelay(1 hours);

        vm.expectRevert(
            accessControlError(oracle, yieldOracle.DEFAULT_ADMIN_ROLE())
        );
        yieldOracle.adminUpdateCurrentPrice(MIN_PRICE);

        vm.expectRevert(
            accessControlError(oracle, yieldOracle.DEFAULT_ADMIN_ROLE())
        );
        yieldOracle.adminUpdatePreviousPrice(MIN_PRICE);

        // Allowed methods
        skip(yieldOracle.updateDelay()); // make updatePrice a legal operation
        yieldOracle.updatePrice(MIN_PRICE);
        yieldOracle.fromEuiToEud(MIN_PRICE);
        yieldOracle.fromEudToEui(MIN_PRICE);

        vm.stopPrank();
    }
}

contract UpdatePrice is Test, YieldOracleInvariants {
    function setUp() public {
        yieldOracle = new YieldOracle();

        yieldOracle.grantRole(yieldOracle.ORACLE_ROLE(), address(this));

        skip(yieldOracle.updateDelay());
    }

    modifier skipEpochs(uint256 epochs) {
        // simulate 10 epochs
        for (uint256 i = 0; i < epochs; i++) {
            skip(yieldOracle.updateDelay());
            assertTrue(
                yieldOracle.updatePrice(
                    yieldOracle.currentPrice() + yieldOracle.maxPriceIncrease()
                )
            );
            skip(yieldOracle.commitDelay());
            assertTrue(yieldOracle.commitPrice());
        }

        skip(yieldOracle.updateDelay());

        _;
    }

    function testFuzz_RevertWhen_PriceIsBelowLimit(uint256 price) public {
        price = bound(price, 0, MIN_PRICE - 1);

        vm.expectRevert(stdError.arithmeticError);
        yieldOracle.updatePrice(price);
    }

    function testFuzz_RevertWhen_PriceIsAboveLimit(uint256 price) public {
        price = bound(
            price,
            yieldOracle.currentPrice() + yieldOracle.maxPriceIncrease() + 1,
            type(uint256).max
        );

        vm.expectRevert("Price out of bounds");
        yieldOracle.updatePrice(price);
    }

    function testFuzz_RevertWhen_PriceIsBelowPrevious(
        uint256 price
    ) public skipEpochs(10) {
        price = bound(price, MIN_PRICE, yieldOracle.currentPrice() - 1);

        vm.expectRevert(stdError.arithmeticError);
        yieldOracle.updatePrice(price);
    }

    function testFuzz_PriceInRange(uint256 price) public {
        price = bound(
            price,
            yieldOracle.currentPrice(),
            yieldOracle.currentPrice() + yieldOracle.maxPriceIncrease()
        );

        uint256 currentPriceBefore = yieldOracle.currentPrice();
        assertTrue(yieldOracle.updatePrice(price));
        assertEq(
            yieldOracle.currentPrice(),
            currentPriceBefore,
            "updatePrice does not change currentPrice"
        );
        assertEq(yieldOracle.nextPrice(), price, "updatePrice sets nextPrice");
    }

    function test_RevertIf_SenderIsntOracle() public {
        uint256 price = yieldOracle.currentPrice() + 1;

        vm.expectRevert(
            accessControlError(makeAddr("nobody"), yieldOracle.ORACLE_ROLE())
        );
        vm.prank(makeAddr("nobody"));
        yieldOracle.updatePrice(price);
    }

    function test_RevertIf_NotEnoughTimePassed() public {
        uint256 price = yieldOracle.currentPrice() + 1;
        assertTrue(yieldOracle.updatePrice(price));

        vm.expectRevert("Insufficient update delay");
        yieldOracle.updatePrice(price);
    }

    function test_CommitsPriceAfterCommitDelay() public {
        uint256 price0 = yieldOracle.currentPrice();
        assertTrue(yieldOracle.updatePrice(price0 + 1));
        assertLe(
            yieldOracle.previousPrice(),
            yieldOracle.currentPrice(),
            "invariant"
        );
        assertEq(
            yieldOracle.currentPrice(),
            price0,
            "updatePrice does not change currentPrice"
        );
        assertEq(
            yieldOracle.nextPrice(),
            price0 + 1,
            "updatePrice sets nextPrice"
        );

        // "forget" to commit price before the next update window starts
        skip(yieldOracle.updateDelay());
        assertNotEq(
            yieldOracle.nextPrice(),
            NO_PRICE,
            "nextPrice should be set"
        );

        // We expect this to revert, despite the invariant that currentPrice <= nextPrice,
        // however here nextPrice is not yet committed even though the commitDelay has passed
        vm.expectRevert(stdError.arithmeticError);
        (yieldOracle.updatePrice(price0));

        assertTrue(yieldOracle.updatePrice(price0 + 2));
        assertEq(
            yieldOracle.previousPrice(),
            price0,
            "updatePrice commits pending nextPrice"
        );
        assertEq(
            yieldOracle.currentPrice(),
            price0 + 1,
            "updatePrice commits pending nextPrice"
        );
        assertEq(
            yieldOracle.nextPrice(),
            price0 + 2,
            "updatePrice sets nextPrice"
        );
    }
}

contract CommitPrice is Test, YieldOracleInvariants {
    function setUp() public {
        yieldOracle = new YieldOracle();

        yieldOracle.grantRole(yieldOracle.ORACLE_ROLE(), address(this));

        skip(yieldOracle.updateDelay());
    }

    function test_RevertIf_NoPriceSet() public {
        assertEq(
            yieldOracle.nextPrice(),
            NO_PRICE,
            "nextPrice should not be set"
        );

        vm.expectRevert(stdError.arithmeticError);
        yieldOracle.commitPrice();
    }

    function testFuzz_RevertIf_NotEnoughTimePassed(uint256 delay) public {
        uint256 price = yieldOracle.currentPrice() + 1;
        assertTrue(yieldOracle.updatePrice(price));

        assertEq(yieldOracle.nextPrice(), price, "nextPrice should be set");
        delay = bound(delay, 0, yieldOracle.commitDelay() - 1);

        skip(delay);

        vm.expectRevert("Insufficient commit delay");
        yieldOracle.commitPrice();
    }

    function test_AnybodyCanCommit() public {
        uint256 price = yieldOracle.currentPrice() + 1;
        assertTrue(yieldOracle.updatePrice(price));

        assertEq(yieldOracle.nextPrice(), price, "nextPrice should be set");
        skip(yieldOracle.commitDelay());

        vm.prank(makeAddr("nobody"));
        assertTrue(yieldOracle.commitPrice());
        assertEq(
            yieldOracle.currentPrice(),
            price,
            "currentPrice should be set"
        );
        assertEq(
            yieldOracle.nextPrice(),
            NO_PRICE,
            "nextPrice should be reset"
        );
    }

    function test_CommitClearsNextPrice() public {
        uint256 price = yieldOracle.currentPrice() + 1;
        assertTrue(yieldOracle.updatePrice(price));

        assertEq(yieldOracle.nextPrice(), price, "nextPrice should be set");
        skip(yieldOracle.commitDelay());
        assertTrue(yieldOracle.commitPrice());
        assertEq(
            yieldOracle.nextPrice(),
            NO_PRICE,
            "nextPrice should be reset"
        );
    }

    function test_RevertWhen_CommitTwice() public {
        uint256 price = yieldOracle.currentPrice() + 1;
        assertTrue(yieldOracle.updatePrice(price));

        assertEq(yieldOracle.nextPrice(), price, "nextPrice should be set");
        skip(yieldOracle.commitDelay());
        assertTrue(yieldOracle.commitPrice());
        assertEq(
            yieldOracle.nextPrice(),
            NO_PRICE,
            "nextPrice should be reset"
        );

        vm.expectRevert(stdError.arithmeticError);
        yieldOracle.commitPrice();
    }
}

contract AdminUpdates is Test, YieldOracleInvariants {
    function setUp() public {
        yieldOracle = new YieldOracle();

        yieldOracle.grantRole(yieldOracle.ORACLE_ROLE(), address(this));

        skip(yieldOracle.updateDelay());
    }

    function test_ValidResetSequence() public {
        yieldOracle.adminResetNextPrice();
        yieldOracle.adminUpdateCurrentPrice(15 ** 18);
        yieldOracle.adminUpdatePreviousPrice(14 ** 18);

        yieldOracle.adminUpdateDelay(10 days);
        yieldOracle.adminCommitDelay(1 days);

        yieldOracle.adminUpdateMaxPriceIncrease(10);
    }
}
