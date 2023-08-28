pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "oz/proxy/ERC1967/ERC1967Proxy.sol";
import {EUD} from "../src/EUD.sol";

contract EUDTest is Test
{
    EUD public eud;
    bytes32 DEFAULT_ADMIN_ROLE = 0x00;

    function setUp() public {
        eud = new EUD();
        eud.initialize();
    }

    function testMintEud(uint256 amount) public {
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.mint(address(this), amount);
        assertEq(eud.balanceOf(address(this)), amount);
    }

    function testBurnEud(uint256 amount) public {
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.grantRole(keccak256("BURN_ROLE"), address(this));
        eud.mint(address(this), amount);
        eud.burn(address(this), amount);
        assertEq(eud.balanceOf(address(this)), 0);
    }

    function testFailMintEudNotAuthorized(uint256 amount) public {
        eud.mint(address(this), amount);
        vm.expectRevert("AccessControl: account");
    }

    function testFailBurnEudNotAuthorized(uint256 amount) public {
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.mint(address(this), amount);
        eud.burn(address(this), amount);
        assertEq(eud.balanceOf(address(this)), 0);
    }

    function testGrantMintRole(address account) public {
        eud.grantRole(keccak256("MINT_ROLE"), account);
        assert(eud.hasRole(keccak256("MINT_ROLE"), account));
    }

    function testGrantBurnRole(address account) public {
        eud.grantRole(keccak256("BURN_ROLE"), account);
        assert(eud.hasRole(keccak256("BURN_ROLE"), account));
    }

    function testGrantPauseRole(address account) public {
        eud.grantRole(keccak256("PAUSE_ROLE"), account);
        assert(eud.hasRole(keccak256("PAUSE_ROLE"), account));
    }

    function testGrantAdminRole(address account) public {
        eud.grantRole(DEFAULT_ADMIN_ROLE, account);
        assert(eud.hasRole(DEFAULT_ADMIN_ROLE, account));
    }

    function testTransferEud(address account, uint256 amount) public {
        vm.assume(account != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.mint(address(this), amount);
        eud.transfer(account, amount);
        assertEq(eud.balanceOf(account), amount);
        vm.prank(account);
        eud.transfer(address(this), amount);
        assertEq(eud.balanceOf(address(this)), amount);
    }

    function testAddToBlocklist(address account) public {
        eud.grantRole(keccak256("BLOCKLIST_ROLE"), address(this));
        eud.addToBlocklist(account);
        assert(eud.blocklist(account));
    }

    function testRemoveFromBlocklist(address account) public {
        eud.grantRole(keccak256("BLOCKLIST_ROLE"), address(this));
        eud.addToBlocklist(account);
        assert(eud.blocklist(account));
        eud.removeFromBlocklist(account);
        assert(!eud.blocklist(account));
    }

    function testFailAddToBlocklistNotAuthorized(address account) public {
        eud.addToBlocklist(account);
        assert(eud.blocklist(account));
    }

    function testFailRemoveFromBlocklistNotAuthorized(address account) public {
        eud.grantRole(keccak256("BLOCKLIST_ROLE"), address(this));
        eud.addToBlocklist(account);
        assert(eud.blocklist(account));
        vm.prank(address(0));
        eud.removeFromBlocklist(account);
        assert(!eud.blocklist(account));
    }

    function testFailUnauthorizedGrantRoles(address account) public {
        vm.assume(account != address(this));
        bytes32 DEFAULT_ADMIN_ROLE = 0x00;
        vm.prank(account);
        eud.grantRole(DEFAULT_ADMIN_ROLE, account);
    }

    function testFailUnauthorizedGrantMintRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eud.grantRole(keccak256("MINT_ROLE"), account);
    }

    function testFailUnauthorizedGrantBurnRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eud.grantRole(keccak256("BURN_ROLE"), account);
    }

    function testFailUnauthorizedGrantPauseRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eud.grantRole(keccak256("PAUSE_ROLE"), account);
    }

    function testFailUnauthorizedGrantFreezeRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eud.grantRole(keccak256("FREEZE_ROLE"), account);
    }

    function testFailUnauthorizedGrantBlocklistRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        eud.grantRole(keccak256("BLOCKLIST_ROLE"), account);
    }

    function testFreeze(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0));
        vm.assume(account2 != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eud.mint(account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        eud.freeze(account1, account2, amount);
        assertEq(eud.balanceOf(account2), amount);
        assertEq(eud.frozenBalances(account1), amount);
    }

    function testRelease(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0));
        vm.assume(account2 != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eud.mint(account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        eud.freeze(account1, account2, amount);
        assertEq(eud.balanceOf(account2), amount);
        assertEq(eud.frozenBalances(account1), amount);
        eud.release(account2, account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        assertEq(eud.frozenBalances(account2), 0);
    }

    function testForcedTransfer(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0));
        vm.assume(account2 != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eud.mint(account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        eud.forcedTransfer(account1, account2, amount);
        assertEq(eud.balanceOf(account2), amount);
        vm.prank(account2);
        eud.transfer(address(this), amount);
        assertEq(eud.balanceOf(address(this)), amount);
    }

    function testFailUnauthorizedForcedTransfer(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.mint(account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        vm.prank(account2);
        eud.forcedTransfer(account1, account2, amount);
        assertEq(eud.balanceOf(account2), amount);
        vm.prank(account2);
        eud.transfer(address(this), amount);
        assertEq(eud.balanceOf(address(this)), amount);
    }

    function testApproveEud(address account, uint256 amount) public {
        vm.assume(account != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.mint(account, amount);
        assertEq(eud.balanceOf(account), amount);
        vm.prank(account);
        eud.approve(address(this), amount);
        assertEq(eud.allowance(account, address(this)), amount);
    }

    function testIncreaseAllowance(address account, uint256 amount) public {
        vm.assume(account != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.mint(account, amount);
        assertEq(eud.balanceOf(account), amount);
        vm.prank(account);
        eud.increaseAllowance(address(this), amount);
        assertEq(eud.allowance(account, address(this)), amount);
    }

    function testDecreaseAllowance(address account, uint256 amount) public {
        vm.assume(account != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.mint(account, amount);
        assertEq(eud.balanceOf(account), amount);
        vm.startPrank(account);
        eud.increaseAllowance(address(this), amount);
        assertEq(eud.allowance(account, address(this)), amount);
        eud.decreaseAllowance(address(this), amount);
        vm.stopPrank();
        assertEq(eud.allowance(account, address(this)), 0);
    }

    function testInitialize() public {
        assertEq(eud.hasRole(0x00, address(this)), true);
        assertEq(eud.symbol(), "EUD");
        assertEq(eud.name(), "EuroDollar");
        assertEq(eud.decimals(), 18);
    }
}