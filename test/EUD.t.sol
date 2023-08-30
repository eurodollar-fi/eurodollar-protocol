pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "oz/proxy/ERC1967/ERC1967Proxy.sol";
import {EUD} from "../src/EUD.sol";

contract EUDTest is Test
{
    EUD public eud;
    bytes32 DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function setUp() public {
        eud = new EUD();
        eud.initialize();
    }

    function testInitialize() public {
        EUD eudNew = new EUD();
        eudNew.initialize();
        assertEq(eudNew.hasRole(0x00, address(this)), true);
        assertEq(eudNew.symbol(), "EUD");
        assertEq(eudNew.name(), "EuroDollar");
        assertEq(eudNew.decimals(), 18);
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

    function testPause(address pauser) public {
        eud.grantRole(keccak256("PAUSE_ROLE"), pauser);
        vm.prank(pauser);
        eud.pause();
        assertEq(eud.paused(), true);
    }

    function testFailUnauthorizedGrantRoles(address account) public {
        vm.assume(account != address(this));
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

    function testUnpause(address pauser) public {
        eud.grantRole(keccak256("PAUSE_ROLE"), pauser);
        vm.prank(pauser);
        eud.pause();
        assertEq(eud.paused(), true);
        vm.prank(pauser);
        eud.unpause();
        assertEq(eud.paused(), false);
    }

    function testFailUnathorizedPause(address pauser) public {
        vm.assume(pauser != address(this));
        vm.prank(pauser);
        eud.pause();
        assertEq(eud.paused(), false);
    }

    function testFailUnathorizedUnpause(address pauser) public {
        vm.assume(pauser != address(this));
        eud.grantRole(keccak256("PAUSE_ROLE"), address(this));
        eud.pause();
        vm.prank(pauser);
        eud.unpause();
        assertEq(eud.paused(), false);
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

    function testAddManyToBlocklist(address account1, address account2, address account3) public {
        vm.assume(account1 != account2 && account2 != account3 && account1 != account3);
        vm.assume(account1 != address(0) && account2 != address(0) && account3 != address(0));
        address[] memory accounts = new address[](3);
        accounts[0] = account1;
        accounts[1] = account2;
        accounts[2] = account3;
        eud.grantRole(keccak256("BLOCKLIST_ROLE"), address(this));
        eud.addManyToBlocklist(accounts);
        for (uint256 i = 0; i < accounts.length; i++) {
            assert(eud.blocklist(accounts[i]));
        }
    }

    function testRemoveFromBlocklist(address account) public {
        eud.grantRole(keccak256("BLOCKLIST_ROLE"), address(this));
        eud.addToBlocklist(account);
        assert(eud.blocklist(account));
        eud.removeFromBlocklist(account);
        assert(!eud.blocklist(account));
    }

    function testRemoveManyFromBlocklist(address account1, address account2, address account3) public {
        vm.assume(account1 != account2 && account2 != account3 && account1 != account3);
        vm.assume(account1 != address(0) && account2 != address(0) && account3 != address(0));
        address[] memory accounts = new address[](3);
        accounts[0] = account1;
        accounts[1] = account2;
        accounts[2] = account3;
        eud.grantRole(keccak256("BLOCKLIST_ROLE"), address(this));
        eud.addManyToBlocklist(accounts);
        for (uint256 i = 0; i < accounts.length; i++) {
            assert(eud.blocklist(accounts[i]));
        }
        eud.removeManyFromBlocklist(accounts);
        for (uint256 i = 0; i < accounts.length; i++) {
            assert(!eud.blocklist(accounts[i]));
        }
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

    function testFailAlreadyAddedToBlocklist(address account) public {
        eud.grantRole(keccak256("BLOCKLIST_ROLE"), address(this));
        eud.addToBlocklist(account);
        assert(eud.blocklist(account));
        eud.addToBlocklist(account);
        assert(eud.blocklist(account));
    }

    function testFailAlreadyRemovedFromBlocklist(address account) public {
        eud.grantRole(keccak256("BLOCKLIST_ROLE"), address(this));
        eud.addToBlocklist(account);
        assert(eud.blocklist(account));
        eud.removeFromBlocklist(account);
        assert(!eud.blocklist(account));
        eud.removeFromBlocklist(account);
        assert(!eud.blocklist(account));
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

    function testFailUnauthorizedFreeze(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0));
        vm.assume(account2 != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
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

    function testFailUnauthorizedRelease(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0));
        vm.assume(account2 != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eud.mint(account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        eud.freeze(account1, account2, amount);
        assertEq(eud.balanceOf(account2), amount);
        assertEq(eud.frozenBalances(account1), amount);
        vm.prank(account1);
        eud.release(account2, account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        assertEq(eud.frozenBalances(account2), 0);
    }

    function testFailReleaseTooManyTokens(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0));
        vm.assume(account2 != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eud.mint(account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        eud.freeze(account1, account2, amount);
        assertEq(eud.balanceOf(account2), amount);
        assertEq(eud.frozenBalances(account1), amount);
        eud.release(account2, account1, amount+1);
        assertEq(eud.balanceOf(account1), amount+1);
        assertEq(eud.frozenBalances(account2), 0);
    }

    function testReclaim(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0));
        vm.assume(account2 != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eud.mint(account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        eud.reclaim(account1, account2, amount);
        assertEq(eud.balanceOf(account2), amount);
        vm.prank(account2);
        eud.transfer(address(this), amount);
        assertEq(eud.balanceOf(address(this)), amount);
    }

    function testFailUnauthorizedReclaim(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0));
        eud.grantRole(keccak256("MINT_ROLE"), address(this));
        eud.mint(account1, amount);
        assertEq(eud.balanceOf(account1), amount);
        vm.prank(account2);
        eud.reclaim(account1, account2, amount);
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

    function testPermit(uint8 privateKey, address receiver, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey != 0);
        vm.assume(receiver != address(0));
        address owner = vm.addr(privateKey);
        vm.assume(owner != receiver);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    eud.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline);
        eud.permit(owner, receiver, amount, deadline, v, r, s);

        assertEq(eud.allowance(owner, receiver), amount);
        assertEq(eud.nonces(owner), 1);
    }

    function testFailPermitTooLate(uint8 privateKey, address receiver, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey != 0);
        vm.assume(deadline < UINT256_MAX);
        vm.assume(receiver != address(0));
        address owner = vm.addr(privateKey);
        vm.assume(owner != receiver);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    eud.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline+1);
        eud.permit(owner, receiver, amount, deadline, v, r, s);

        assertEq(eud.allowance(owner, receiver), amount);
        assertEq(eud.nonces(owner), 1);
    }

    function testFailUnauthorizedPermit(uint8 privateKey1, uint8 privateKey2, address receiver, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey1 != 0 && privateKey2 != 0);
        vm.assume(privateKey1 != privateKey2);
        vm.assume(receiver != address(0));
        address owner = vm.addr(privateKey1);
        vm.assume(owner != receiver);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey2,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    eud.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline);
        eud.permit(owner, receiver, amount, deadline, v, r, s);
    }

    //TODO: Fix this test.
    function testAuthorizeUpgrade(address newImplementation) public {
        EUD eudNew = new EUD();
        ERC1967Proxy proxy = new ERC1967Proxy(address(eudNew), abi.encodeWithSelector(EUD(address(0)).initialize.selector));
        address(proxy).call(abi.encodeWithSignature("grantRole(bytes32,address)", DEFAULT_ADMIN_ROLE, address(this)));
        address(proxy).call(abi.encodeWithSignature("upgradeTo(address)", DEFAULT_ADMIN_ROLE, newImplementation));
    }
}