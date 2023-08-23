pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/EUD.sol";

contract EUDTest is Test
{
    EUD public eud;

    function setUp() public {
        eud = new EUD();
        eud.initialize(address(this));
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
        eud.grantRole(keccak256("DEFAULT_ADMIN_ROLE"), account);
        assert(eud.hasRole(keccak256("DEFAULT_ADMIN_ROLE"), account));
    }

    function testTransferEud(address account, uint256 amount) public {
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

    function testFailUnauthorizedGrantMintRole(address account) public {
        vm.prank(address(0));
        eud.grantRole(keccak256("MINT_ROLE"), account);
    }

}