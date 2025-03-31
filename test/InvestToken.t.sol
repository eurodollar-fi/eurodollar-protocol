// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IUSDE} from "../src/interfaces/IUSDE.sol";
import {IYieldOracle} from "../src/interfaces/IYieldOracle.sol";
import {InvestToken} from "../src/InvestToken.sol";
import {USDE} from "../src/USDE.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {Constants} from "./Constants.sol";
import {IValidator} from "../src/interfaces/IValidator.sol";

// Simple validator contract implementation for testing
contract TestValidator {
    function isValidStrict(address, address) external pure returns (bool) {
        return true;
    }
    
    function isValid(address, address) external pure returns (bool) {
        return true;
    }
    
    function isBlacklisted(address) external pure returns (bool) {
        return false;
    }
}

contract EuroDollarSetup is Test {
    YieldOracle public yieldOracle;
    USDE public usde;
    InvestToken public investToken;
    TestValidator public validator;

    address public owner;

    function setUp() public virtual {
        owner = address(this);

        // Setup validator
        validator = new TestValidator();

        // Setup YieldOracle
        yieldOracle = new YieldOracle(owner, owner);

        // Setup USDE with validator
        USDE usdeImplementation = new USDE(IValidator(address(validator)));
        ERC1967Proxy usdeProxy = new ERC1967Proxy(
            address(usdeImplementation), 
            abi.encodeCall(USDE.initialize, (owner))
        );
        usde = USDE(address(usdeProxy));

        // Setup InvestToken
        address investTokenImplementation = address(new InvestToken(IValidator(address(validator)), IUSDE(address(usde))));
        ERC1967Proxy investTokenProxy = new ERC1967Proxy(
            investTokenImplementation, 
            abi.encodeCall(InvestToken.initialize, ("EuroDollar Invest Token", "EUI", owner, IYieldOracle(address(yieldOracle))))
        );
        investToken = InvestToken(address(investTokenProxy));

        // Setup roles
        usde.grantRole(usde.INVEST_TOKEN_ROLE(), address(investToken));
        usde.grantRole(usde.MINT_ROLE(), address(investToken));
        usde.grantRole(usde.BURN_ROLE(), address(investToken));
        usde.grantRole(usde.MINT_ROLE(), owner);
        usde.grantRole(usde.BURN_ROLE(), owner);
    }
}

contract InvestTokenTest is Test, EuroDollarSetup, Constants {
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    
    bytes32 constant BURN_REQUEST_TYPEHASH =
        keccak256("BurnRequest(address from,uint256 amount,uint256 nonce,uint256 deadline)");

    function setUp() public override {
        super.setUp();

        // Grant roles
        usde.grantRole(MINT_ROLE, address(this));
        usde.grantRole(MINT_ROLE, address(investToken));
        usde.grantRole(BURN_ROLE, address(this));
        usde.grantRole(BURN_ROLE, address(investToken));
        investToken.grantRole(MINT_ROLE, address(this));
        investToken.grantRole(BURN_ROLE, address(this));
        investToken.grantRole(RESCUER_ROLE, address(this));
        investToken.grantRole(PAUSER_ROLE, address(this));
        investToken.grantRole(UPGRADER_ROLE, address(this));
        
        // Set oracle prices for testing
        yieldOracle.setCurrentPrice(1e18);  // 1.0
        yieldOracle.setPreviousPrice(1e18); // 1.0
    }

    function testInitialize() public view {
        assertEq(investToken.hasRole(0x00, address(this)), true);
        assertEq(investToken.symbol(), "EUI");
        assertEq(investToken.name(), "EuroDollar Invest Token");
        assertEq(investToken.decimals(), 18);
    }

    function testInitializeNewProxy() public {
        InvestToken newInvestTokenImplementation = new InvestToken(IValidator(address(validator)), IUSDE(address(usde)));
        ERC1967Proxy newInvestTokenProxy = new ERC1967Proxy(
            address(newInvestTokenImplementation), 
            abi.encodeCall(InvestToken.initialize, ("EuroDollar Invest Token", "EUI", owner, IYieldOracle(address(yieldOracle))))
        );
        InvestToken newInvestToken = InvestToken(address(newInvestTokenProxy));
        assertEq(newInvestToken.hasRole(0x00, address(this)), true);
        assertEq(newInvestToken.symbol(), "EUI");
        assertEq(newInvestToken.name(), "EuroDollar Invest Token");
        assertEq(newInvestToken.decimals(), 18);
    }

    function testMint(uint256 amount) public {
        // Bound amount to avoid overflow
        amount = bound(amount, 1, 1000000 * 10**18);
        
        investToken.mint(address(this), amount);
        assertEq(investToken.balanceOf(address(this)), amount);
    }

    function test_RevertWhen_MintNotAuthorized(address account, uint256 amount) public {
        // Skip test with zero address or test contract
        vm.assume(account != address(this) && account != address(0));
        amount = bound(amount, 1, 1000000 * 10**18);
        
        vm.prank(account);
        vm.expectRevert();
        investToken.mint(account, amount);
    }

    function testBurnWithSignature(uint8 privateKey, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey != 0);
        amount = bound(amount, 1, 1000000 * 10**18);
        deadline = bound(deadline, block.timestamp, type(uint256).max - 1);
        
        address from = vm.addr(privateKey);
        vm.assume(from != address(0));
        
        // First mint tokens to the account
        investToken.mint(from, amount);
        assertEq(investToken.balanceOf(from), amount);
        
        // Get current nonce
        uint256 nonce = investToken.burnNonces(from);
        
        // Generate signature for burn
        bytes32 structHash = keccak256(
            abi.encode(BURN_REQUEST_TYPEHASH, from, amount, nonce, deadline)
        );
        
        bytes32 digest = _hashTypedDataV4(structHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Burn with signature
        investToken.burn(from, amount, deadline, signature);
        
        // Verify tokens are burned
        assertEq(investToken.balanceOf(from), 0);
        // Verify nonce is incremented
        assertEq(investToken.burnNonces(from), nonce + 1);
    }
    
    function test_RevertWhen_BurnWithInvalidSignature(uint8 privateKey1, uint8 privateKey2, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey1 != 0 && privateKey2 != 0);
        vm.assume(privateKey1 != privateKey2);
        amount = bound(amount, 1, 1000000 * 10**18);
        deadline = bound(deadline, block.timestamp, type(uint256).max - 1);
        
        address from = vm.addr(privateKey1);
        vm.assume(from != address(0));
        
        // First mint tokens to the account
        investToken.mint(from, amount);
        assertEq(investToken.balanceOf(from), amount);
        
        // Get current nonce
        uint256 nonce = investToken.burnNonces(from);
        
        // Generate signature with wrong private key
        bytes32 structHash = keccak256(
            abi.encode(BURN_REQUEST_TYPEHASH, from, amount, nonce, deadline)
        );
        
        bytes32 digest = _hashTypedDataV4(structHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey2, digest); // Wrong signer
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Burn should fail with invalid signature
        vm.expectRevert("Invalid signature");
        investToken.burn(from, amount, deadline, signature);
    }
    
    function test_RevertWhen_BurnAfterDeadline(uint8 privateKey, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey != 0);
        amount = bound(amount, 1, 1000000 * 10**18);
        deadline = bound(deadline, block.timestamp, type(uint256).max - 1);
        
        address from = vm.addr(privateKey);
        vm.assume(from != address(0));
        
        // First mint tokens to the account
        investToken.mint(from, amount);
        assertEq(investToken.balanceOf(from), amount);
        
        // Get current nonce
        uint256 nonce = investToken.burnNonces(from);
        
        // Generate signature
        bytes32 structHash = keccak256(
            abi.encode(BURN_REQUEST_TYPEHASH, from, amount, nonce, deadline)
        );
        
        bytes32 digest = _hashTypedDataV4(structHash);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Set time after deadline
        vm.warp(deadline + 1);
        
        // Burn should fail with expired signature
        vm.expectRevert("Signature expired");
        investToken.burn(from, amount, deadline, signature);
    }
    
    function testRecover(address from, address to, uint256 amount) public {
        vm.assume(from != address(0) && to != address(0));
        amount = bound(amount, 1, 1000000 * 10**18);
        
        // First mint tokens to the from address
        investToken.mint(from, amount);
        assertEq(investToken.balanceOf(from), amount);
        
        // Recover tokens
        investToken.recover(from, to, amount);
        
        // Verify balances
        assertEq(investToken.balanceOf(from), 0);
        assertEq(investToken.balanceOf(to), amount);
    }
    
    function test_RevertWhen_RecoverNotAuthorized(address from, address to, uint256 amount, address notRescuer) public {
        vm.assume(from != address(0) && to != address(0));
        vm.assume(notRescuer != address(0) && notRescuer != address(this));
        amount = bound(amount, 1, 1000000 * 10**18);
        
        // First mint tokens to the from address
        investToken.mint(from, amount);
        
        // Attempt recover as unauthorized account
        vm.prank(notRescuer);
        vm.expectRevert();
        investToken.recover(from, to, amount);
    }

    function testGrantRole(address account, bytes32 role) public {
        vm.assume(account != address(0));
        
        investToken.grantRole(role, account);
        assertTrue(investToken.hasRole(role, account));
    }

    function test_RevertWhen_UnauthorizedGrantRole(address account, bytes32 role, address notAdmin) public {
        vm.assume(account != address(0));
        vm.assume(notAdmin != address(0) && notAdmin != address(this));
        
        vm.prank(notAdmin);
        vm.expectRevert();
        investToken.grantRole(role, account);
    }

    function testPause(address pauser) public {
        vm.assume(pauser != address(0));
        investToken.grantRole(PAUSER_ROLE, pauser);
        vm.prank(pauser);
        investToken.pause();
        assertEq(investToken.paused(), true);
    }

    function testUnpause(address pauser) public {
        vm.assume(pauser != address(0));
        investToken.grantRole(PAUSER_ROLE, pauser);
        vm.prank(pauser);
        investToken.pause();
        assertEq(investToken.paused(), true);
        vm.prank(pauser);
        investToken.unpause();
        assertEq(investToken.paused(), false);
    }

    function test_RevertWhen_UnathorizedPause(address pauser) public {
        vm.assume(pauser != address(this) && pauser != address(0));
        vm.prank(pauser);
        vm.expectRevert();
        investToken.pause();
        assertEq(investToken.paused(), false);
    }

    function test_RevertWhen_UnathorizedUnpause(address pauser) public {
        vm.assume(pauser != address(this) && pauser != address(0));
        investToken.grantRole(PAUSER_ROLE, address(this));
        investToken.pause();
        vm.prank(pauser);
        vm.expectRevert();
        investToken.unpause();
        assertEq(investToken.paused(), true);
    }

    function testTransferEui(address account, uint256 amount) public {
        vm.assume(account != address(0) && account != address(this));
        amount = bound(amount, 1, 1000000 * 10**18);
        
        investToken.mint(address(this), amount);
        investToken.transfer(account, amount);
        assertEq(investToken.balanceOf(account), amount);
        vm.prank(account);
        investToken.transfer(address(this), amount);
        assertEq(investToken.balanceOf(address(this)), amount);
    }

    function testPermit(uint8 privateKey, address receiver, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey != 0);
        vm.assume(receiver != address(0));
        amount = bound(amount, 1, 1000000 * 10**18);
        deadline = bound(deadline, block.timestamp, type(uint256).max - 1);
        
        address owner = vm.addr(privateKey);
        vm.assume(owner != address(0));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    investToken.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline);
        investToken.permit(owner, receiver, amount, deadline, v, r, s);

        assertEq(investToken.allowance(owner, receiver), amount);
        assertEq(investToken.nonces(owner), 1);
    }

    function test_RevertWhen_PermitTooLate(uint8 privateKey, address receiver, uint256 amount, uint256 deadline) public {
        deadline = bound(deadline, 0, type(uint256).max - 1);
        vm.assume(privateKey != 0);
        vm.assume(receiver != address(0));
        amount = bound(amount, 1, 1000000 * 10**18);
        
        address owner = vm.addr(privateKey);
        vm.assume(owner != address(0));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    investToken.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline + 1);
        vm.expectRevert();  // Expect any revert related to expired deadline
        investToken.permit(owner, receiver, amount, deadline, v, r, s);
    }

    function test_RevertWhen_UnauthorizedPermit(
        uint8 privateKey1,
        uint8 privateKey2,
        address receiver,
        uint256 amount,
        uint256 deadline
    )
        public
    {
        vm.assume(privateKey1 != 0 && privateKey2 != 0);
        vm.assume(privateKey1 != privateKey2);
        vm.assume(receiver != address(0));
        amount = bound(amount, 1, 1000000 * 10**18);
        deadline = bound(deadline, block.timestamp, type(uint256).max - 1);
        
        address owner = vm.addr(privateKey1);
        vm.assume(owner != address(0));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey2, // Wrong signer
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    investToken.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline);
        vm.expectRevert();  // Expect any revert related to invalid signature
        investToken.permit(owner, receiver, amount, deadline, v, r, s);
    }

    function testChangeYieldOracle(address newYieldOracle) public {
        vm.assume(newYieldOracle != address(0));
        investToken.changeYieldOracle(IYieldOracle(newYieldOracle));
        assertEq(address(investToken.yieldOracle()), newYieldOracle);
    }

    function test_RevertWhen_ChangeYieldOracleUnauthorized(address newYieldOracle, address notAdmin) public {
        vm.assume(newYieldOracle != address(0));
        vm.assume(notAdmin != address(this) && notAdmin != address(0));
        vm.prank(notAdmin);
        vm.expectRevert();
        investToken.changeYieldOracle(IYieldOracle(newYieldOracle));
    }

    function testAsset() view public {
        assertEq(investToken.asset(), address(usde));
    }

    function testTotalAssets(uint256 amount) public {
        vm.assume(amount != 0);
        amount = bound(amount, 1, 1e39);
        investToken.mint(address(this), amount);
        assertEq(investToken.totalAssets(), convertToAssets(amount));
    }
    
    function convertToAssets(uint256 shares) internal view returns (uint256) {
        return yieldOracle.sharesToAssets(shares);
    }
    
    function convertToShares(uint256 assets) internal view returns (uint256) {
        return yieldOracle.assetsToShares(assets);
    }

    function testConvertToShares(uint256 amount, uint256 previousPrice, uint256 currentPrice) public {
        previousPrice = bound(previousPrice, 1e18, 1e37);
        currentPrice = bound(currentPrice, previousPrice, 1e37);
        amount = bound(amount, 1, 1e37);
        yieldOracle.setCurrentPrice(currentPrice);
        yieldOracle.setPreviousPrice(previousPrice);
        usde.mint(address(this), amount);
        assertEq(investToken.convertToShares(amount), yieldOracle.assetsToShares(amount));
    }

    function testConvertToAssets(uint256 amount, uint256 previousPrice, uint256 currentPrice) public {
        previousPrice = bound(previousPrice, 1e18, 1e37);
        currentPrice = bound(currentPrice, previousPrice, 1e37);
        amount = bound(amount, 1, 1e37);
        yieldOracle.setCurrentPrice(currentPrice);
        yieldOracle.setPreviousPrice(previousPrice);
        investToken.mint(address(this), amount);
        assertEq(investToken.convertToAssets(amount), yieldOracle.sharesToAssets(amount));
    }

    function testMaxDeposit(address account) public view {
        assertEq(investToken.maxDeposit(account), type(uint256).max);
    }

    function testMaxDepositPaused(address account) public {
        investToken.pause();
        assertEq(investToken.maxDeposit(account), 0);
    }

    function testPreviewDeposit(uint256 amount, uint256 previousPrice, uint256 currentPrice) public {
        previousPrice = bound(previousPrice, 1e18, 1e37);
        currentPrice = bound(currentPrice, previousPrice, 1e37);
        yieldOracle.setCurrentPrice(currentPrice);
        yieldOracle.setPreviousPrice(previousPrice);
        amount = bound(amount, 1, 1e39);
        assertEq(investToken.previewDeposit(amount), investToken.convertToShares(amount));
    }

    function testDeposit(address receiver, uint256 amount) public {
        // Bounds
        amount = bound(amount, 1, 1e39);

        // Assumes
        vm.assume(receiver != address(0));

        // Setup to ensure the test passes
        uint256 currentPrice = 1e18; // 1.0
        yieldOracle.setCurrentPrice(currentPrice);
        yieldOracle.setPreviousPrice(currentPrice);

        // Test
        usde.mint(address(this), amount);
        assertEq(usde.balanceOf(address(this)), amount);
        
        uint256 expectedShares = investToken.convertToShares(amount);
        uint256 receivedShares = investToken.deposit(amount, receiver);
        
        assertEq(receivedShares, expectedShares);
        assertEq(investToken.balanceOf(receiver), expectedShares);
    }

    function test_RevertWhen_DepositWhilePaused(address receiver, uint256 amount) public {
        // Bounds
        amount = bound(amount, 1, 1e39);

        // Assumes
        vm.assume(receiver != address(0));

        // Setup
        usde.mint(address(this), amount);
        
        // Pause the contract
        investToken.pause();
        
        // Test for custom error EnforcedPause()
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        investToken.deposit(amount, receiver);
    }

    function testMaxRedeem(address account, uint256 amount) public {
        vm.assume(account != address(0));
        investToken.mint(account, amount);
        uint256 euiBalance = investToken.balanceOf(account);
        assertEq(investToken.maxRedeem(account), euiBalance);
    }

    function testMaxRedeemPaused(address account, uint256 amount) public {
        vm.assume(account != address(0));
        investToken.mint(account, amount);
        investToken.pause();
        assertEq(investToken.maxRedeem(account), 0);
    }

    function testPreviewRedeem(uint256 amount, uint256 previousPrice, uint256 currentPrice) public {
        previousPrice = bound(previousPrice, 1e18, 1e37);
        currentPrice = bound(currentPrice, previousPrice, 1e37);
        yieldOracle.setCurrentPrice(currentPrice);
        yieldOracle.setPreviousPrice(previousPrice);
        amount = bound(amount, 1, 1e39);
        assertEq(investToken.previewRedeem(amount), investToken.convertToAssets(amount));
    }

    function testRedeem(address owner, address receiver, uint256 amount) public {
        // Bounds
        amount = bound(amount, 1, 1e39);

        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Setup
        uint256 price = 1e18; // 1.0 for simplicity
        yieldOracle.setCurrentPrice(price);
        yieldOracle.setPreviousPrice(price);

        // Test
        investToken.mint(owner, amount);
        assertEq(investToken.balanceOf(owner), amount);
        vm.startPrank(owner);
        investToken.approve(address(this), amount);
        vm.stopPrank();
        
        uint256 expectedAssets = investToken.convertToAssets(amount);
        uint256 receivedAssets = investToken.redeem(amount, receiver, owner);
        
        assertEq(receivedAssets, expectedAssets);
        assertEq(usde.balanceOf(receiver), expectedAssets);
    }

    function test_RevertWhen_RedeemTooManyShares(address owner, address receiver, uint256 amount) public {
        // Bounds
        amount = bound(amount, 1, 1e39);

        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Setup
        uint256 price = 1e18; // 1.0 for simplicity
        yieldOracle.setPreviousPrice(price);
        yieldOracle.setCurrentPrice(price);

        // Test
        investToken.mint(owner, amount);
        assertEq(investToken.balanceOf(owner), amount);
        vm.startPrank(owner);
        investToken.approve(address(this), amount);
        vm.stopPrank();
        
        // Try to redeem more than available
        vm.expectRevert();
        investToken.redeem(amount + 1, receiver, owner);
    }

    function test_RevertWhen_RedeemWhilePaused(address owner, address receiver, uint256 amount) public {
        // Bounds
        amount = bound(amount, 1, 1e39);

        // Assumes
        vm.assume(owner != address(0) && receiver != address(0));

        // Setup 
        uint256 price = 1e18; // 1.0 for simplicity
        yieldOracle.setPreviousPrice(price);
        yieldOracle.setCurrentPrice(price);

        // Test
        investToken.mint(owner, amount);
        assertEq(investToken.balanceOf(owner), amount);
        vm.startPrank(owner);
        investToken.approve(address(this), amount);
        vm.stopPrank();
        
        // Pause contract
        investToken.pause();
        
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        investToken.redeem(amount, receiver, owner);
    }

    function invariant_assetIsUsde() external view {
        assertEq(investToken.asset(), address(investToken.usde()));
    }

    function testRenounceRoleFails() public {
        vm.expectRevert();
        investToken.renounceRole(DEFAULT_ADMIN_ROLE, address(this));
    }

    // This event is not reachable directly from the original implementation for some reason
    event Upgraded(address indexed implementation);

    function testAuthorizeUpgrade() public {
        InvestTokenv2 newInvestToken = new InvestTokenv2(IValidator(address(validator)), IUSDE(address(usde)));

        vm.expectEmit(address(investToken));
        emit Upgraded(address(newInvestToken));
        investToken.upgradeToAndCall(address(newInvestToken), abi.encodeCall(InvestTokenv2.initializeV2, ()));

        assertEq(investToken.hasRole(investToken.DEFAULT_ADMIN_ROLE(), address(this)), true);
        assertEq(investToken.symbol(), "EUI");
        assertEq(investToken.name(), "EuroDollar Invest Token");
        assertEq(investToken.decimals(), 18);
    }
    
    // Helper function to reproduce EIP712 hashing for testing burn signatures
    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                investToken.DOMAIN_SEPARATOR(),
                structHash
            )
        );
    }
}

contract InvestTokenv2 is InvestToken {
    constructor(IValidator validator, IUSDE usde) InvestToken(validator, usde) {}

    function initializeV2() public reinitializer(2) {}
}

contract Paused is Test, EuroDollarSetup {
    function setUp() public override {
        super.setUp();

        investToken.grantRole(investToken.PAUSER_ROLE(), owner);
        investToken.grantRole(investToken.MINT_ROLE(), owner);
        investToken.grantRole(investToken.BURN_ROLE(), owner);
        investToken.grantRole(investToken.RESCUER_ROLE(), owner);
        
        // Setup for pause tests
        investToken.mint(owner, 1000);
        investToken.pause();
    }

    function invariant_paused() public view {
        assertTrue(investToken.paused(), "InvestToken should be paused");
    }

    function test_CannotTransfer() public {
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        investToken.transfer(address(this), 0);
    }

    function test_CannotTransferFrom() public {
        address any = address(0x123);
        investToken.approve(address(this), 1000);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        investToken.transferFrom(address(this), any, 1000);
    }

    function test_CannotDeposit() public {
        usde.mint(address(this), 100);
        usde.approve(address(investToken), 100);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        investToken.deposit(100, address(this));
    }

    function test_CannotRedeem() public {
        investToken.approve(address(this), 10);
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        investToken.redeem(10, address(this), address(this));
    }
}