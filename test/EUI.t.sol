// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "oz/proxy/ERC1967/ERC1967Proxy.sol";
import {IEUD} from "../interfaces/IEUD.sol";
import {IYieldOracle} from "../interfaces/IYieldOracle.sol";
import {EUI} from "../src/EUI.sol";
import {EUD} from "../src/EUD.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {Constants} from "./Constants.sol";
import "oz/utils/math/Math.sol";
import "forge-std/console.sol";

contract EUITest is Test, Constants
{
    using Math for uint256;

    EUI public eui;
    EUD public eud;
    YieldOracle public yieldOracle;
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");


    function setUp() public {
        // Setup EUD
        eud = new EUD();
        eud.initialize();

        // Setup YieldOracle
        yieldOracle = new YieldOracle();
        yieldOracle.adminUpdateCurrentPrice(1e18);
        yieldOracle.adminUpdateOldPrice(1e18);

        // Setup EUI
        eui = new EUI();
        eui.initialize(address(eud), address(yieldOracle));

        // Grant Roles
        eud.grantRole(MINT_ROLE, address(this));
        eud.grantRole(MINT_ROLE, address(eui));
        eud.grantRole(BURN_ROLE, address(this));
        eud.grantRole(BURN_ROLE, address(eui));
        eui.grantRole(MINT_ROLE, address(this));
        eui.grantRole(BURN_ROLE, address(this));
        eui.grantRole(ALLOW_ROLE, address(this));
        eui.grantRole(PAUSE_ROLE, address(this));
        eui.grantRole(FREEZE_ROLE, address(this));
        eui.addToAllowlist(address(eui));
        eui.addToAllowlist(address(this));
    }

    function testInitialize() public {
        EUI eui = new EUI();
        eui.initialize(address(eud), address(yieldOracle));
        assertEq(eui.hasRole(0x00, address(this)), true);
        assertEq(eui.symbol(), "EUI");
        assertEq(eui.name(), "EuroDollar Invest");
        assertEq(eui.decimals(), 18);
    }

    function testMintEui(uint256 amount) public {
        eui.mintEUI(address(this), amount);
        assertEq(eui.balanceOf(address(this)), amount);
    }

    function testBurnEui(uint256 amount) public {
        eui.mintEUI(address(this), amount);
        eui.burnEUI(address(this), amount);
        assertEq(eui.balanceOf(address(this)), 0);
    }

    function testFailMintEuiNotAuthorized(address account, uint256 amount) public {
        vm.assume(account != address(this) && account != address(0));
        vm.prank(account);
        eui.mintEUI(account, amount);
    }

    function testFailBurnEuiNotAuthorized(address account, uint256 amount) public {
        vm.assume(account != address(this) && account != address(0));
        eui.mintEUI(account, amount);
        vm.prank(account);
        eui.burnEUI(account, amount);
        assertEq(eui.balanceOf(address(this)), 0);
    }

    function testGrantMintRole(address account) public {
        eui.grantRole(MINT_ROLE, account);
        assert(eui.hasRole(MINT_ROLE, account));
    }

    function testGrantBurnRole(address account) public {
        eui.grantRole(BURN_ROLE, account);
        assert(eui.hasRole(BURN_ROLE, account));
    }

    function testGrantPauseRole(address account) public {
        eui.grantRole(PAUSE_ROLE, account);
        assert(eui.hasRole(PAUSE_ROLE, account));
    }

    function testGrantAdminRole(address account) public {
        eui.grantRole(DEFAULT_ADMIN_ROLE, account);
        assert(eui.hasRole(DEFAULT_ADMIN_ROLE, account));
    }

     function testFailUnauthorizedGrantRoles(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(DEFAULT_ADMIN_ROLE, account);
    }

    function testFailUnauthorizedGrantMintRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(MINT_ROLE, account);
    }

    function testFailUnauthorizedGrantBurnRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(BURN_ROLE, account);
    }

    function testFailUnauthorizedGrantPauseRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(PAUSE_ROLE, account);
    }

    function testFailUnauthorizedGrantFreezeRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(FREEZE_ROLE, account);
    }

    function testFailUnauthorizedGrantAllowlistRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(ALLOW_ROLE, account);
    }

    function testPause(address pauser) public {
        eui.grantRole(PAUSE_ROLE, pauser);
        vm.prank(pauser);
        eui.pause();
        assertEq(eui.paused(), true);
    }

    function testUnpause(address pauser) public {
        eui.grantRole(PAUSE_ROLE, pauser);
        vm.prank(pauser);
        eui.pause();
        assertEq(eui.paused(), true);
        vm.prank(pauser);
        eui.unpause();
        assertEq(eui.paused(), false);
    }

    function testFailUnathorizedPause(address pauser) public {
        vm.assume(pauser != address(this));
        vm.prank(pauser);
        eui.pause();
        assertEq(eui.paused(), false);
    }

    function testFailUnathorizedUnpause(address pauser) public {
        vm.assume(pauser != address(this));
        eui.grantRole(PAUSE_ROLE, address(this));
        eui.pause();
        vm.prank(pauser);
        eui.unpause();
        assertEq(eui.paused(), false);
    }

    function testTransferEui(address account, uint256 amount) public {
        vm.assume(account != address(0) && account != address(this));
        eui.addToAllowlist(account);
        eui.mintEUI(address(this), amount);
        eui.transfer(account, amount);
        assertEq(eui.balanceOf(account), amount);
        vm.prank(account);
        eui.transfer(address(this), amount);
        assertEq(eui.balanceOf(address(this)), amount);
    }

    function testAddToAllowlist(address account) public {
        vm.assume(account != address(this));
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
    }

    function testAddManyToAllowlist(address account1, address account2, address account3) public {
        address[] memory accounts = new address[](3);
        accounts[0] = account1;
        accounts[1] = account2;
        accounts[2] = account3;
        eui.addManyToAllowlist(accounts);
        for (uint256 i = 0; i < accounts.length; i++) {
            assert(eui.allowlist(accounts[i]));
        }
    }

    function testRemoveFromAllowlist(address account) public {
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
        eui.removeFromAllowlist(account);
        assert(!eui.allowlist(account));
    }

    function testRemoveManyFromAllowlist(address account1, address account2, address account3) public {
        address[] memory accounts = new address[](3);
        accounts[0] = account1;
        accounts[1] = account2;
        accounts[2] = account3;
        eui.addManyToAllowlist(accounts);
        for (uint256 i = 0; i < accounts.length; i++) {
            assert(eui.allowlist(accounts[i]));
        }
        eui.removeManyFromAllowlist(accounts);
        for (uint256 i = 0; i < accounts.length; i++) {
            assert(!eui.allowlist(accounts[i]));
        }
    }

    function testFailAddToAllowlistNotAuthorized(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
    }

    function testFailRemoveFromAllowlistNotAuthorized(address account) public {
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
        vm.prank(address(0));
        eui.removeFromAllowlist(account);
        assert(!eui.allowlist(account));
    }

    function testFreeze(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0) && account2 != address(0));
        eui.addToAllowlist(account1);
        eui.addToAllowlist(account2);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        eui.freeze(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
        assertEq(eui.frozenBalances(account1), amount);
    }

    function testFailUnauthorizedFreeze(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0) && account2 != address(0));
        eui.addToAllowlist(account1);
        eui.addToAllowlist(account2);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        vm.prank(account1);
        eui.freeze(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
        assertEq(eui.frozenBalances(account1), amount);
    }

    function testRelease(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0) && account2 != address(0));
        eui.addToAllowlist(account1);
        eui.addToAllowlist(account2);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        eui.freeze(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
        assertEq(eui.frozenBalances(account1), amount);
        eui.release(account2, account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        assertEq(eui.frozenBalances(account2), 0);
    }

    function testFailUnauthorizedRelease(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0) && account2 != address(0));
        eui.addToAllowlist(account1);
        eui.addToAllowlist(account2);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        eui.freeze(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
        assertEq(eui.frozenBalances(account1), amount);
        vm.prank(account1);
        eui.release(account2, account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        assertEq(eui.frozenBalances(account2), 0);
    }

    function testReclaim(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0) && account2 != address(0));
        eui.addToAllowlist(account1);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        eui.reclaim(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
    }

    function testFailUnauthorizedReclaim(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0));
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        vm.prank(account2);
        eui.reclaim(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
        vm.prank(account2);
        eui.transfer(address(this), amount);
        assertEq(eui.balanceOf(address(this)), amount);
    }

    function testApproveEui(address account, uint256 amount) public {
        vm.assume(account != address(0) && account != address(this));
        eui.addToAllowlist(account);
        eui.mintEUI(account, amount);
        assertEq(eui.balanceOf(account), amount);
        vm.prank(account);
        eui.approve(address(this), amount);
        assertEq(eui.allowance(account, address(this)), amount);
    }

    function testIncreaseAllowance(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0) && account2 != address(0));
        eui.addToAllowlist(account1);
        eui.addToAllowlist(account2);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        vm.prank(account1);
        eui.increaseAllowance(account2, amount);
        assertEq(eui.allowance(account1, account2), amount);
    }

    function testDecreaseAllowance(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0) && account2 != address(0));
        eui.addToAllowlist(account1);
        eui.addToAllowlist(account2);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        vm.startPrank(account1);
        eui.increaseAllowance(account2, amount);
        assertEq(eui.allowance(account1, account2), amount);
        eui.decreaseAllowance(account2, amount);
        vm.stopPrank();
        assertEq(eui.allowance(account1, account2), 0);
    }

    function testPermit(uint8 privateKey, address receiver, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey != 0);
        vm.assume(receiver != address(0));
        address owner = vm.addr(privateKey);

        eui.addToAllowlist(receiver);
        eui.addToAllowlist(owner);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    eui.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline);
        eui.permit(owner, receiver, amount, deadline, v, r, s);

        assertEq(eui.allowance(owner, receiver), amount);
        assertEq(eui.nonces(owner), 1);
    }

    function testFailPermitTooLate(uint8 privateKey, address receiver, uint256 amount, uint256 deadline) public {
        deadline = bound(deadline, 0, UINT256_MAX-1);
        vm.assume(privateKey != 0);
        vm.assume(receiver != address(0));
        address owner = vm.addr(privateKey);

        eui.addToAllowlist(receiver);
        eui.addToAllowlist(owner);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    eui.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline+1);
        eui.permit(owner, receiver, amount, deadline, v, r, s);

        assertEq(eui.allowance(owner, receiver), amount);
        assertEq(eui.nonces(owner), 1);
    }

    function testFailUnauthorizedPermit(uint8 privateKey1, uint8 privateKey2, address receiver, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey1 != 0 && privateKey2 != 0);
        vm.assume(privateKey1 != privateKey2);
        vm.assume(receiver != address(0));
        address owner = vm.addr(privateKey1);
    
        eui.addToAllowlist(receiver);
        eui.addToAllowlist(owner);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey2,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    eui.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline);
        eui.permit(owner, receiver, amount, deadline, v, r, s);
    }
    //TODO fix this test
    function testAuthorizeUpgrade(address newImplementation) public {
        EUI eui = new EUI();
        ERC1967Proxy proxy = new ERC1967Proxy(address(eui), abi.encodeWithSelector(EUI(address(0)).initialize.selector, eud, yieldOracle));
        address(proxy).call(abi.encodeWithSignature("grantRole(bytes32,address)", DEFAULT_ADMIN_ROLE, address(this)));
        address(proxy).call(abi.encodeWithSignature("upgradeTo(address)", DEFAULT_ADMIN_ROLE, newImplementation));
    }

    function testFlipToEui(address owner, address receiver, uint256 amount, uint256 price) public {
        // Bounds
        amount = bound(amount, 0, 1e39);
        price = bound(price, 1, 1e39);
        
        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Set Roles
        eui.addToAllowlist(owner);
        eui.addToAllowlist(receiver);
        yieldOracle.adminUpdateCurrentPrice(price); // Current Price

        // Test
        eud.mint(owner, amount);
        assertEq(eud.balanceOf(owner), amount);
        vm.startPrank(owner);
        eud.approve(address(eui), amount);
        eui.flipToEUI(owner, receiver, amount);
        vm.stopPrank();
        assertEq(eui.balanceOf(receiver), amount.mulDiv(1e18, price, Math.Rounding.Down));
    }

    function testFlipToEud(address owner, address receiver, uint256 amount, uint256 price) public {
        // Bounds
        amount = bound(amount, 0, 1e39);
        price = bound(price, 1, 1e39);

        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Setup
        eui.addToAllowlist(owner);
        eui.addToAllowlist(receiver);
        yieldOracle.adminUpdateOldPrice(price);

        // Test
        eui.mintEUI(owner, amount);
        assertEq(eui.balanceOf(owner), amount);
        vm.startPrank(owner);
        eui.approve(address(eui), amount);
        eui.flipToEUD(owner, receiver, amount);
        vm.stopPrank();
        assertEq(eud.balanceOf(receiver), amount.mulDiv(price, 1e18, Math.Rounding.Down));
    }

    function testFailFlipToEuiNotAuthorized(address owner, address receiver, uint256 amount, uint256 price) public {
        // Bounds
        amount = bound(amount, 1, 1e39);
        price = bound(price, 1, 1e39);
        
        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Set Roles
        eui.addToAllowlist(owner);
        eui.addToAllowlist(receiver);
        yieldOracle.adminUpdateCurrentPrice(price); // Current Price

        // Test
        eud.mint(owner, amount);
        assertEq(eud.balanceOf(owner), amount);
        vm.startPrank(owner);
        // eud.approve(address(eui), amount); NO APPROVAL
        eui.flipToEUI(owner, receiver, amount);
        vm.stopPrank();
        assertEq(eui.balanceOf(receiver), amount.mulDiv(1e18, price, Math.Rounding.Down));
    }

    function testFailFlipToEudNotAuthorized(address owner, address receiver, uint256 amount, uint256 price) public {
        // Bounds
        amount = bound(amount, 1, 1e39); // amount > 1, if 0, no approval needed, and test will succeed.
        price = bound(price, 1, 1e39);

        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Setup
        eui.addToAllowlist(owner);
        eui.addToAllowlist(receiver);
        yieldOracle.adminUpdateOldPrice(price);

        // Test
        eui.mintEUI(owner, amount);
        assertEq(eui.balanceOf(owner), amount);
        vm.startPrank(owner);
        // eui.approve(address(eui), amount); NO APPROVAL
        eui.flipToEUD(owner, receiver, amount);
        vm.stopPrank();
        //assertEq(eud.balanceOf(receiver), amount.mulDiv(price, 1e18, Math.Rounding.Down));
    }

    function testSetYieldOracle(address newYieldOracle) public {
        eui.grantRole(keccak256("ADMIN_ROLE"), address(this));
        eui.setYieldOracle(newYieldOracle);
        assertEq(address(eui.yieldOracle()), newYieldOracle);
    }

    function testFailSetYieldOracleUnauthorized(address newYieldOracle) public {
        vm.prank(address(0));
        eui.setYieldOracle(newYieldOracle);
        assertEq(address(eui.yieldOracle()), newYieldOracle);
    }

    function testTotalAssets(uint256 amount) public {
        vm.assume(amount != 0);
        amount = bound(amount, 0, 1e39);
        eui.mintEUI(address(this), amount);
        assertEq(eui.totalAssets(), yieldOracle.fromEuiToEud(amount));
    }

    function testConvertToShares(uint256 amount) public {
        eui.mintEUI(address(this), amount);
        assertEq(eui.convertToShares(amount), amount.mulDiv(1e18, eui.yieldOracle().currentPrice(), Math.Rounding.Down));
    }

    function testConvertToAssets(uint256 amount) public {
        amount = bound(amount, 0, 1e39);
        eui.mintEUI(address(this), amount);
        assertEq(eui.convertToAssets(amount), amount.mulDiv(eui.yieldOracle().oldPrice(), 1e18, Math.Rounding.Down));
    }

    function testMaxDeposit(address account) public {
        assertEq(eui.maxDeposit(account), UINT256_MAX);
    }

    function testPreviewDeposit(uint256 amount) public {
        amount = bound(amount, 0, 1e39);
        assertEq(eui.previewDeposit(amount), amount.mulDiv(1e18, eui.yieldOracle().currentPrice(), Math.Rounding.Down));
    }

    function testDeposit(address owner, address receiver, uint256 amount, uint256 price) public {
        //Bounds
        amount = bound(amount, 0, 1e39);
        price = bound(price, 1, 1e39);

        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Setup
        eui.addToAllowlist(owner);
        eui.addToAllowlist(receiver);
        yieldOracle.adminUpdateCurrentPrice(price); // Current Price

        // Test
        eud.mint(owner, amount);
        assertEq(eud.balanceOf(owner), amount);
        vm.startPrank(owner);
        eud.approve(address(eui), amount);
        eui.deposit(amount, receiver);
        vm.stopPrank();
        assertEq(eui.balanceOf(receiver), amount.mulDiv(1e18, price, Math.Rounding.Down));
    }

    function testMaxMint(address account) public {
        assertEq(eui.maxMint(account), UINT256_MAX);
    }

    function testPreviewMint(uint256 amount) public {
        amount = bound(amount, 0, 1e39);
        assertEq(eui.previewMint(amount), amount.mulDiv(eui.yieldOracle().oldPrice(), 1e18, Math.Rounding.Down));
    }

    function testMint(address owner, address receiver, uint256 amount, uint256 price) public {
        //Bounds
        amount = bound(amount, 0, 1e39);
        price = bound(price, 1, 1e39);

        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Setup
        eui.addToAllowlist(owner);
        eui.addToAllowlist(receiver);
        eui.addToAllowlist(address(eui));
        yieldOracle.adminUpdateCurrentPrice(price);

        // Test
        uint256 eudAmount = yieldOracle.fromEuiToEud(amount);
        eud.mint(owner, eudAmount);
        assertEq(eud.balanceOf(owner), eudAmount);
        vm.startPrank(owner);
        eud.approve(address(eui), eudAmount);
        eui.mint(amount, receiver);
        vm.stopPrank();
        assertEq(eui.balanceOf(receiver), amount.mulDiv(1e18, price, Math.Rounding.Down));
    }

    function testMaxWithdraw(address account, uint256 amount, uint256 price) public {
        amount = bound(amount, 0, 1e39);
        price = bound(price, 1, 1e39);
        yieldOracle.adminUpdateOldPrice(price);
        vm.assume(account != address(0));
        eui.addToAllowlist(account);
        eui.mintEUI(account, amount);
        assertEq(eui.maxWithdraw(account), amount.mulDiv(price, 1e18, Math.Rounding.Down));
    }

    function testPreviewWithdraw(uint256 amount) public {
        amount = bound(amount, 0, 1e39);
        assertEq(eui.previewWithdraw(amount), amount.mulDiv(1e18, yieldOracle.currentPrice(), Math.Rounding.Down));
    }

    function testWithdraw(address owner, address receiver, uint256 amount, uint256 price) public {
        // Bounds
        amount = bound(amount, 0, 1e39);
        price = bound(price, 1, 1e39);

        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Setup
        eui.addToAllowlist(owner);
        eui.addToAllowlist(receiver);
        yieldOracle.adminUpdateOldPrice(price);

        // Test
        eui.mintEUI(owner, amount);
        assertEq(eui.balanceOf(owner), amount);
        vm.startPrank(owner);
        eui.approve(address(eui), amount);
        uint256 eudAmount = yieldOracle.fromEuiToEud(amount);
        eui.withdraw(eudAmount, receiver, owner);
        vm.stopPrank();
        assertEq(eud.balanceOf(receiver), eudAmount);  
    }

    function testMaxRedeem(address account, uint256 amount) public {
        vm.assume(account != address(0));
        eui.addToAllowlist(account);
        eui.mintEUI(account, amount);
        uint256 euiBalance = eui.balanceOf(account);
        assertEq(eui.maxRedeem(account), euiBalance);
    }

    function testPreviewRedeem(uint256 amount) public {
        amount = bound(amount, 0, 1e39);
        assertEq(eui.previewRedeem(amount), amount.mulDiv(eui.yieldOracle().oldPrice(), 1e18, Math.Rounding.Down));
    }

    function testRedeem(address owner, address receiver, uint256 amount, uint256 price) public {
        // Bounds
        amount = bound(amount, 0, 1e39);
        price = bound(price, 1, 1e39);

        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Setup
        eui.addToAllowlist(owner);
        eui.addToAllowlist(receiver);
        yieldOracle.adminUpdateOldPrice(price);

        // Test
        eui.mintEUI(owner, amount);
        assertEq(eui.balanceOf(owner), amount);
        vm.startPrank(owner);
        eui.approve(address(eui), amount);
        eui.redeem(amount, receiver, owner);
        vm.stopPrank();
        assertEq(eud.balanceOf(receiver), amount.mulDiv(price, 1e18, Math.Rounding.Down));    
    }
}