pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "oz/proxy/ERC1967/ERC1967Proxy.sol";
import {IEUD} from "../interfaces/IEUD.sol";
import {IYieldOracle} from "../interfaces/IYieldOracle.sol";
import {EUI} from "../src/EUI.sol";
import {EUD} from "../src/EUD.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import "oz/utils/math/Math.sol";

contract EUITest is Test
{
    using Math for uint256;

    EUI public eui;
    address public eud;
    address public yieldOracle;
    bytes32 public DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function setUp() public {
        eui = new EUI();
        eui.initialize(eud, yieldOracle);
    }

    function testInitialize() public {
        EUI euiNew = new EUI();
        euiNew.initialize(eud, yieldOracle);
        assertEq(euiNew.hasRole(0x00, address(this)), true);
        assertEq(euiNew.symbol(), "EUI");
        assertEq(euiNew.name(), "EuroDollar Invest");
        assertEq(euiNew.decimals(), 18);
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

    function testPause(address pauser) public {
        eui.grantRole(keccak256("PAUSE_ROLE"), pauser);
        vm.prank(pauser);
        eui.pause();
        assertEq(eui.paused(), true);
    }

    function testUnpause(address pauser) public {
        eui.grantRole(keccak256("PAUSE_ROLE"), pauser);
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
        eui.grantRole(keccak256("PAUSE_ROLE"), address(this));
        eui.pause();
        vm.prank(pauser);
        eui.unpause();
        assertEq(eui.paused(), false);
    }

    function testTransferEui(address account, uint256 amount) public {
        vm.assume(account != address(0) && account != address(this));
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

    function testAddManyToAllowlist(address account1, address account2, address account3) public {
        vm.assume(account1 != account2 && account2 != account3 && account1 != account3);
        vm.assume(account1 != address(0) && account2 != address(0) && account3 != address(0));
        address[] memory accounts = new address[](3);
        accounts[0] = account1;
        accounts[1] = account2;
        accounts[2] = account3;
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addManyToAllowlist(accounts);
        for (uint256 i = 0; i < accounts.length; i++) {
            assert(eui.allowlist(accounts[i]));
        }
    }

    function testRemoveFromAllowlist(address account) public {
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
        eui.removeFromAllowlist(account);
        assert(!eui.allowlist(account));
    }

    function testRemoveManyFromAllowlist(address account1, address account2, address account3) public {
        vm.assume(account1 != account2 && account2 != account3 && account1 != account3);
        vm.assume(account1 != address(0) && account2 != address(0) && account3 != address(0));
        address[] memory accounts = new address[](3);
        accounts[0] = account1;
        accounts[1] = account2;
        accounts[2] = account3;
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
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

    function testFailAlreadyAddedToAllowlist(address account) public {
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
    }

    function testFailAlreadyRemovedFromAllowlist(address account) public {
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account);
        assert(eui.allowlist(account));
        eui.removeFromAllowlist(account);
        assert(!eui.allowlist(account));
        eui.removeFromAllowlist(account);
        assert(!eui.allowlist(account));
    }

    function testFreeze(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0) && account2 != address(0) && account1 != account2);
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account1);
        eui.addToAllowlist(account2);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        eui.freeze(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
        assertEq(eui.frozenBalances(account1), amount);
    }

    function testFailUnauthorizedFreeze(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0) && account2 != address(0) && account1 != account2);
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account1);
        eui.addToAllowlist(account2);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        eui.freeze(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
        assertEq(eui.frozenBalances(account1), amount);
    }

    function testRelease(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(this) && account1 != address(0) && account2 != address(0) && account1 != account2);
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
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
        vm.assume(account1 != address(this) && account1 != address(0) && account2 != address(0) && account1 != account2);
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
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
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
        eui.grantRole(keccak256("FREEZE_ROLE"), address(this));
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        eui.addToAllowlist(account1);
        eui.mintEUI(account1, amount);
        assertEq(eui.balanceOf(account1), amount);
        eui.reclaim(account1, account2, amount);
        assertEq(eui.balanceOf(account2), amount);
    }

    function testFailUnauthorizedReclaim(address account1, address account2, uint256 amount) public {
        vm.assume(account1 != address(0));
        eui.grantRole(keccak256("MINT_ROLE"), address(this));
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

    function testPermit(uint8 privateKey, address receiver, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey != 0);
        vm.assume(receiver != address(0));
        address owner = vm.addr(privateKey);
        vm.assume(owner != receiver);

        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
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
        vm.assume(privateKey != 0);
        vm.assume(deadline < UINT256_MAX);
        vm.assume(receiver != address(0));
        address owner = vm.addr(privateKey);

        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
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
    
        eui.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
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
        EUI euiNew = new EUI();
        ERC1967Proxy proxy = new ERC1967Proxy(address(euiNew), abi.encodeWithSelector(EUI(address(0)).initialize.selector, eud, yieldOracle));
        address(proxy).call(abi.encodeWithSignature("grantRole(bytes32,address)", DEFAULT_ADMIN_ROLE, address(this)));
        address(proxy).call(abi.encodeWithSignature("upgradeTo(address)", DEFAULT_ADMIN_ROLE, newImplementation));
    }

    function testFlipToEui(address owner, address receiver, uint256 amount, uint256 price) public {
        
        // Assumes
        vm.assume(amount < 1e39);
        vm.assume(price != 0 && price < 1e39);
        vm.assume(owner != address(0) && receiver != address(0) && owner != receiver);
        vm.assume(owner != address(this) && receiver != address(this));
        vm.assume(amount != 0);

        // Setup
        EUD eudNew = new EUD();
        eudNew.initialize();

        YieldOracle yieldOracleNew = new YieldOracle();
        yieldOracleNew.adminUpdateCurrentPrice(price);

        EUI euiNew = new EUI();
        euiNew.initialize(address(eudNew), address(yieldOracleNew));

        // Set Roles
        eudNew.grantRole(keccak256("MINT_ROLE"), address(this));
        eudNew.grantRole(keccak256("MINT_ROLE"), address(euiNew));
        eudNew.grantRole(keccak256("BURN_ROLE"), address(euiNew));
        euiNew.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        euiNew.addToAllowlist(owner);
        euiNew.addToAllowlist(receiver);
        euiNew.addToAllowlist(address(eudNew));

        // Test
        eudNew.mint(owner, amount);
        assertEq(eudNew.balanceOf(owner), amount);
        vm.startPrank(owner);
        eudNew.approve(address(euiNew), amount);
        euiNew.flipToEUI(owner, receiver, amount);
        vm.stopPrank();
        assertEq(euiNew.balanceOf(receiver), amount.mulDiv(1e18, price, Math.Rounding.Down));
    }

    function testFlipToEud(address owner, address receiver, uint256 amount, uint256 price) public {
        // Assumes
        vm.assume(amount < 1e39);
        vm.assume(price < 1e39);
        vm.assume(owner != address(0) && receiver != address(0) && owner != receiver);
        vm.assume(owner != address(this) && receiver != address(this));

        // Setup
        EUD eudNew = new EUD();
        eudNew.initialize();
        YieldOracle yieldOracleNew = new YieldOracle();
        yieldOracleNew.adminUpdateOldPrice(price);
        EUI euiNew = new EUI();
        euiNew.initialize(address(eudNew), address(yieldOracleNew));

        // Set Roles
        euiNew.grantRole(keccak256("MINT_ROLE"), address(this));
        eudNew.grantRole(keccak256("MINT_ROLE"), address(euiNew));
        eudNew.grantRole(keccak256("BURN_ROLE"), address(euiNew));
        euiNew.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        euiNew.addToAllowlist(owner);
        euiNew.addToAllowlist(receiver);
        euiNew.addToAllowlist(address(euiNew));

        // Test
        euiNew.mintEUI(owner, amount);
        assertEq(euiNew.balanceOf(owner), amount);
        vm.startPrank(owner);
        euiNew.approve(address(euiNew), amount);
        euiNew.flipToEUD(owner, receiver, amount);
        vm.stopPrank();
        assertEq(eudNew.balanceOf(receiver), amount.mulDiv(price, 1e18, Math.Rounding.Down));
    }

    function testFailFlipToEuiNotAuthorized(address owner, address receiver, uint256 amount, uint256 price) public {
        // Assumes
        vm.assume(amount < 1e39);
        vm.assume(price < 1e39);
        vm.assume(owner != address(0) && receiver != address(0) && owner != receiver);
        vm.assume(owner != address(this) && receiver != address(this));
        vm.assume(amount != 0);

        // Setup
        EUD eudNew = new EUD();
        eudNew.initialize();
        YieldOracle yieldOracleNew = new YieldOracle();
        yieldOracleNew.adminUpdateCurrentPrice(price);
        EUI euiNew = new EUI();
        euiNew.initialize(address(eudNew), address(yieldOracleNew));

        // Set Roles
        eudNew.grantRole(keccak256("MINT_ROLE"), address(this));
        eudNew.grantRole(keccak256("MINT_ROLE"), address(euiNew));
        eudNew.grantRole(keccak256("BURN_ROLE"), address(euiNew));
        euiNew.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        euiNew.addToAllowlist(owner);
        euiNew.addToAllowlist(receiver);
        euiNew.addToAllowlist(address(eudNew));

        // Test
        eudNew.mint(owner, amount);
        assertEq(eudNew.balanceOf(owner), amount);
        eudNew.approve(address(euiNew), amount);
        euiNew.flipToEUI(owner, receiver, amount);
        assertEq(euiNew.balanceOf(receiver), amount.mulDiv(1e18, price, Math.Rounding.Down));
    }

    function testFailFlipToEudNotAuthorized(address owner, address receiver, uint256 amount, uint256 price) public {
        // Assumes
        vm.assume(amount < 1e39);
        vm.assume(price < 1e39);
        vm.assume(owner != address(0) && receiver != address(0) && owner != receiver);
        vm.assume(owner != address(this) && receiver != address(this));

        // Setup
        EUD eudNew = new EUD();
        eudNew.initialize();
        YieldOracle yieldOracleNew = new YieldOracle();
        yieldOracleNew.adminUpdateOldPrice(price);
        EUI euiNew = new EUI();
        euiNew.initialize(address(eudNew), address(yieldOracleNew));

        // Set Roles
        euiNew.grantRole(keccak256("MINT_ROLE"), address(this));
        eudNew.grantRole(keccak256("MINT_ROLE"), address(euiNew));
        eudNew.grantRole(keccak256("BURN_ROLE"), address(euiNew));
        euiNew.grantRole(keccak256("ALLOWLIST_ROLE"), address(this));
        euiNew.addToAllowlist(owner);
        euiNew.addToAllowlist(receiver);
        euiNew.addToAllowlist(address(euiNew));

        // Test
        euiNew.mintEUI(owner, amount);
        assertEq(euiNew.balanceOf(owner), amount);
        euiNew.approve(address(euiNew), amount);
        euiNew.flipToEUD(owner, receiver, amount);
        assertEq(eudNew.balanceOf(receiver), amount.mulDiv(price, 1e18, Math.Rounding.Down));
    }

}