pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "oz/proxy/ERC1967/ERC1967Proxy.sol";
import {IEUD} from "../interfaces/IEUD.sol";
import {IYieldOracle} from "../interfaces/IYieldOracle.sol";
import {EUI} from "../src/EUI.sol";

contract EUITest is Test
{
    EUI public eui;
    address public eud;
    address public yieldOracle;
    bytes32 public DEFAULT_ADMIN_ROLE = 0x00;

    function setUp() public {
        eui = new EUI();
        eui.initialize(eud, yieldOracle);
    }

    function testMintEui(uint256 amount) public {
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(address(this));
        eui.mintEUI(address(this), amount);
        assertEq(eui.balanceOf(address(this)), amount);
    }

    function testBurnEui(uint256 amount) public {
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("BURN_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(address(this));
        eui.mintEUI(address(this), amount);
        eui.burnEUI(address(this), amount);
        assertEq(eui.balanceOf(address(this)), 0);
    }

    function testFailMintEuiNotAuthorized(uint256 amount) public {
        eui.mintEUI(address(this), amount);
        vm.expectRevert("AccessControl: account");
    }

    function testFailBurnEuiNotAuthorized(uint256 amount) public {
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.mintEUI(address(this), amount);
        eui.burnEUI(address(this), amount);
        assertEq(eui.balanceOf(address(this)), 0);
    }

    function testGrantMintRole(address account) public {
        eui.grantRole(keccak256("MINT_ROLE"), account);
        assert(eui.hasRole(keccak256("MINT_ROLE"), account));
    }

    function testGrantBurnRole(address account) public {
        eui.grantRole(keccak256("BURN_ROLE"), account);
        assert(eui.hasRole(keccak256("BURN_ROLE"), account));
    }

    function testGrantPauseRole(address account) public {
        eui.grantRole(keccak256("PAUSE_ROLE"), account);
        assert(eui.hasRole(keccak256("PAUSE_ROLE"), account));
    }

    function testGrantAdminRole(address account) public {
        eui.grantRole(DEFAULT_ADMIN_ROLE, account);
        assert(eui.hasRole(DEFAULT_ADMIN_ROLE, account));
    }

    function testTransferEui(address account, uint256 amount) public {
        vm.assume(account != address(0));
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(address(this));
        eui.addToAllowlist(account);
        eui.mintEUI(address(this), amount);
        eui.transfer(account, amount);
        assertEq(eui.balanceOf(account), amount);
        vm.prank(account);
        eui.transfer(address(this), amount);
        assertEq(eui.balanceOf(address(this)), amount);
    }

    function testAddToAllowlist(address account) public {
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
    }

    function testRemoveFromAllowlist(address account) public {
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
        eui.removeFromAllowlist(account);
        assert(!eui.allowlist(account));
    }

    function testFailAddToAllowlistNotAuthorized(address account) public {
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
    }

    function testFailRemoveFromAllowlistNotAuthorized(address account) public {
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
        vm.prank(address(0));
        eui.removeFromAllowlist(account);
        assert(!eui.allowlist(account));
    }

    function testFailUnauthorizedGrantRoles(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(DEFAULT_ADMIN_ROLE, account);
    }

    function testFailUnauthorizedGrantMintRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(keccak256("MINT_ROLE"), account);
    }

    function testFailUnauthorizedGrantBurnRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(keccak256("BURN_ROLE"), account);
    }

    function testFailUnauthorizedGrantPauseRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(keccak256("PAUSE_ROLE"), account);
    }

    function testFailUnauthorizedGrantFreezeRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(keccak256("FREEZE_ROLE"), account);
    }

    function testFailUnauthorizedGrantAllowlistRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), account);
    }

    function testForcedTransfer(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0) && account2 != address(0));
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account1);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        eui.forcedTransfer(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
    }

    function testFailUnauthorizedForcedTransfer(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0));
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        vm.prank(account2);
        eui.forcedTransfer(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
        vm.prank(account2);
        eui.transfer(address(this), amount);
        assertEq(eui.balanceOf(address(this)), amount);
    }

    function testApproveEui(address account, uint256 amount) public {
        vm.assume(account != address(0));
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(address(this));
        eui.addToAllowlist(account);
        eui.mintEUI(account, amount);
        assertEq(eui.balanceOf(account), amount);
        vm.prank(account);
        eui.approve(address(this), amount);
        assertEq(eui.allowance(account, address(this)), amount);
    }

    function testIncreaseAllowance(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0) && account2 != address(0) && account1 != account2);
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account1);
        eui.addToAllowlist(account2);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        vm.prank(account1);
        eui.increaseAllowance(account2, amount);
        assertEq(eui.allowance(account1, account2), amount);
    }

    function testDecreaseAllowance(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0) && account2 != address(0) && account1 != account2);
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
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
}