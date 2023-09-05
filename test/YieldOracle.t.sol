// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {YieldOracle} from "../src/YieldOracle.sol";

contract YieldOracleTest is Test
{

    YieldOracle public yieldOracle;
    bytes32 DEFAULT_ADMIN_ROLE = 0x00;

    function setUp() public {
        yieldOracle = new YieldOracle();
    }

    function testConstructor() public {
        YieldOracle newOracle = new YieldOracle();
        assertEq(newOracle.hasRole(DEFAULT_ADMIN_ROLE, address(this)), true);
        assertEq(newOracle.oldPrice(), 1e18);
        assertEq(newOracle.currentPrice(), 1e18);
    }

    function testPause(address pauser) public {
        yieldOracle.grantRole(keccak256("PAUSE_ROLE"), pauser);
        vm.prank(pauser);
        yieldOracle.pause();
        assertEq(yieldOracle.paused(), true);
    }

    function testUnpause(address pauser) public {
        yieldOracle.grantRole(keccak256("PAUSE_ROLE"), pauser);
        vm.prank(pauser);
        yieldOracle.pause();
        assertEq(yieldOracle.paused(), true);
        vm.prank(pauser);
        yieldOracle.unpause();
        assertEq(yieldOracle.paused(), false);
    }

    function testGrantPauseRole(address account) public {
        yieldOracle.grantRole(keccak256("PAUSE_ROLE"), account);
        assert(yieldOracle.hasRole(keccak256("PAUSE_ROLE"), account));
    }

    function testGrantOracleRole(address account) public {
        yieldOracle.grantRole(keccak256("ORACLE_ROLE"), account);
        assert(yieldOracle.hasRole(keccak256("ORACLE_ROLE"), account));
    }

    function testFailUnauthorizedGrantPauseRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        yieldOracle.grantRole(keccak256("PAUSE_ROLE"), account);
    }

    function testFailUnauthorizedGrantOracleRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        yieldOracle.grantRole(keccak256("ORACLE_ROLE"), account);
    }

    function testSetMaxPriceIncrease(uint256 amount) public {
        yieldOracle.grantRole(DEFAULT_ADMIN_ROLE, address(this));
        yieldOracle.setMaxPriceIncrease(amount);
        assertEq(yieldOracle.maxPriceIncrease(), amount);
    }

    function testSetDelay(uint256 amount) public {
        yieldOracle.grantRole(DEFAULT_ADMIN_ROLE, address(this));
        yieldOracle.setDelay(amount);
        assertEq(yieldOracle.delay(), amount);
    }

    function testUpdatePrice(address oracle) public {
        yieldOracle.grantRole(keccak256("ORACLE_ROLE"), oracle);
        vm.warp(3601); // roll forward 1 hour + 1 second to update price
        vm.prank(oracle);
        yieldOracle.updatePrice(110e16);
        assertEq(yieldOracle.currentPrice(), 110e16);
        vm.warp(7202); // roll forward 1 hour + 1 second to update price
        vm.prank(oracle);
        yieldOracle.updatePrice(120e16);
        assertEq(yieldOracle.currentPrice(), 120e16);
    }

    function testFailUnauthorizedUpdatePrice(address oracle) public {
        vm.prank(oracle);
        yieldOracle.updatePrice(110e16);
    }

    function testFailNotEnoughTimeBetweenPriceUpdates(address oracle) public {
        yieldOracle.grantRole(keccak256("ORACLE_ROLE"), oracle);
        vm.prank(oracle);
        yieldOracle.updatePrice(110e16);
    }

    function testFailPriceUpdateAboveLimit(address oracle) public {
        yieldOracle.grantRole(keccak256("ORACLE_ROLE"), oracle);
        vm.warp(3601); // roll forward 1 hour + 1 second to update price
        vm.prank(oracle);
        yieldOracle.updatePrice(12e17);
    }

    function testFromEudtoEui() public {
        yieldOracle.adminUpdateCurrentPrice(125e16); // 1.25e18
        uint256 amount = 1e18;     // 1.00e18 
        assertEq(yieldOracle.fromEudToEui(amount), 8e17); // 1.00/1.25=0.8
    }

    function testFromEuiToEud() public {
        yieldOracle.adminUpdateOldPrice(125e16); // 1.25e18
        uint256 amount = 1e18;     // 1.00e18 
        assertEq(yieldOracle.fromEuiToEud(amount), 125e16); // 1.00*1.25=1.25
    }
}