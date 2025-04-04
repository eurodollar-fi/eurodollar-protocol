// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {USDE} from "../src/USDE.sol";
import {Constants} from "./Constants.sol";
import {InvestToken} from "../src/InvestToken.sol";
import {IValidator} from "../src/Validator.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {IValidator} from "../src/interfaces/IValidator.sol";

contract USDECoverageTest is Test, IValidator {
    USDE public usde;
    
    // Control variable for the validator response
    bool private _validatorResponse = true;
    
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINT_ROLE = keccak256("MINT_ROLE");
    bytes32 public constant BURN_ROLE = keccak256("BURN_ROLE");
    bytes32 public constant RESCUER_ROLE = keccak256("RESCUER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant INVEST_TOKEN_ROLE = keccak256("INVEST_TOKEN_ROLE");
    
    // Burn request typehash
    bytes32 public constant BURN_REQUEST_TYPEHASH =
        keccak256(
            "BurnRequest(address from,uint256 amount,uint256 nonce,uint256 deadline)"
        );
    
    // Validator function implementation - this is the one USDE actually calls
    function isValid(address, address) external view override returns (bool) {
        return _validatorResponse;
    }
    
    // Implement with the correct signature from the interface
    function isValidStrict(address, address) external view override returns (bool) {
        return true;
    }
    
    function isWhitelisted(address) external view override returns (bool) {
        return true;
    }
    
    function isBlacklisted(address) external view override returns (bool) {
        return false;
    }
    
    // Function to control the validator response
    function setValidatorResponse(bool response) public {
        _validatorResponse = response;
    }
    
    function setUp() public {
        // Make the validator always return true
        _validatorResponse = true;
        
        // Deploy USDE implementation and proxy
        USDE implementation = new USDE(this);
        ERC1967Proxy usdeProxy = new ERC1967Proxy(
            address(implementation), 
            abi.encodeCall(USDE.initialize, (address(this)))
        );
        usde = USDE(address(usdeProxy));
        
        // Grant necessary roles
        usde.grantRole(MINT_ROLE, address(this));
        usde.grantRole(BURN_ROLE, address(this));
        usde.grantRole(RESCUER_ROLE, address(this));
        usde.grantRole(UPGRADER_ROLE, address(this));
        usde.grantRole(PAUSER_ROLE, address(this));
        usde.grantRole(INVEST_TOKEN_ROLE, address(this));
    }
    
    // Test constructor with zero address validator
    function testConstructorZeroAddressValidator() public {
        vm.expectRevert("Validator cannot be zero address");
        new USDE(IValidator(address(0)));
    }
    
    // Test initialize with zero address owner
    function testInitializeZeroAddressOwner() public {
        // Deploy a new implementation
        USDE implementation = new USDE(this);
        
        // Create the initialization data with zero address
        bytes memory initData = abi.encodeCall(USDE.initialize, (address(0)));
        
        // When creating the proxy with zero address initialization, it should revert
        vm.expectRevert("Owner cannot be zero address");
        new ERC1967Proxy(address(implementation), initData);
    }
    
    // Test _update with validator rejection
    function testUpdateValidatorRejects() public {
        // Mint some tokens to test with
        usde.mint(address(this), 1000);
        
        // Set validator to reject transfers
        _validatorResponse = false;
        
        // Try to transfer tokens, should revert
        vm.expectRevert("account blocked");
        usde.transfer(address(1), 100);
        
        // Reset validator response for other tests
        _validatorResponse = true;
    }
    
    // Test burn with signature
    function testBurnWithSignature(uint8 privateKey, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey != 0);
        vm.assume(amount > 0 && amount < 1000000 * 10**18);
        deadline = bound(deadline, block.timestamp, block.timestamp + 1 days);
        
        // Get the address from private key
        address signer = vm.addr(privateKey);
        
        // Mint tokens to the signer
        usde.mint(signer, amount);
        
        // Get the current nonce
        uint256 nonce = usde.burnNonces(signer);
        
        // Create the struct hash
        bytes32 structHash = keccak256(
            abi.encode(BURN_REQUEST_TYPEHASH, signer, amount, nonce, deadline)
        );
        
        // Generate the digest
        bytes32 digest = _hashTypedDataV4(structHash);
        
        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Execute the burn with signature
        usde.burn(signer, amount, deadline, signature);
        
        // Check the balance and nonce
        assertEq(usde.balanceOf(signer), 0);
        assertEq(usde.burnNonces(signer), nonce + 1);
    }
    
    // Test burn with expired signature
    function testBurnWithExpiredSignature(uint8 privateKey, uint256 amount) public {
        vm.assume(privateKey != 0);
        vm.assume(amount > 0 && amount < 1000000 * 10**18);
        
        // Set a deadline in the past
        uint256 deadline = block.timestamp - 1;
        
        // Get the address from private key
        address signer = vm.addr(privateKey);
        
        // Mint tokens to the signer
        usde.mint(signer, amount);
        
        // Get the current nonce
        uint256 nonce = usde.burnNonces(signer);
        
        // Create the struct hash
        bytes32 structHash = keccak256(
            abi.encode(BURN_REQUEST_TYPEHASH, signer, amount, nonce, deadline)
        );
        
        // Generate the digest
        bytes32 digest = _hashTypedDataV4(structHash);
        
        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Execute the burn with signature, should revert due to expired deadline
        vm.expectRevert("Signature expired");
        usde.burn(signer, amount, deadline, signature);
    }
    
    // Test burn with invalid signature
    function testBurnWithInvalidSignature(uint8 privateKey1, uint8 privateKey2, uint256 amount, uint256 deadline) public {
        vm.assume(privateKey1 != 0 && privateKey2 != 0);
        vm.assume(privateKey1 != privateKey2);
        vm.assume(amount > 0 && amount < 1000000 * 10**18);
        deadline = bound(deadline, block.timestamp, block.timestamp + 1 days);
        
        // Get the addresses from private keys
        address signer = vm.addr(privateKey1);
        address wrongSigner = vm.addr(privateKey2);
        
        // Mint tokens to the signer
        usde.mint(signer, amount);
        
        // Get the current nonce
        uint256 nonce = usde.burnNonces(signer);
        
        // Create the struct hash
        bytes32 structHash = keccak256(
            abi.encode(BURN_REQUEST_TYPEHASH, signer, amount, nonce, deadline)
        );
        
        // Generate the digest
        bytes32 digest = _hashTypedDataV4(structHash);
        
        // Sign the digest with the wrong private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey2, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Execute the burn with signature, should revert due to invalid signature
        vm.expectRevert("Invalid signature");
        usde.burn(signer, amount, deadline, signature);
    }
    
    // Test recover functionality
    function testRecover(address from, address to, uint256 amount) public {
        vm.assume(from != address(0) && to != address(0));
        vm.assume(from != to);
        vm.assume(amount > 0 && amount < 1000000 * 10**18);
        
        // Mint tokens to the from address
        usde.mint(from, amount);
        
        // Call recover
        usde.recover(from, to, amount);
        
        // Check balances
        assertEq(usde.balanceOf(from), 0);
        assertEq(usde.balanceOf(to), amount);
    }
    
    // Test unauthorized recover
    function testUnauthorizedRecover(address unauthorized, address from, address to, uint256 amount) public {
        vm.assume(unauthorized != address(0) && unauthorized != address(this));
        vm.assume(from != address(0) && to != address(0));
        vm.assume(from != to);
        vm.assume(amount > 0 && amount < 1000000 * 10**18);
        
        // Mint tokens to the from address
        usde.mint(from, amount);
        
        // Try to recover as unauthorized user
        vm.prank(unauthorized);
        vm.expectRevert();
        usde.recover(from, to, amount);
    }
    
    // Test upgrade authorization
    function testAuthorizeUpgrade() public {
        // Deploy a new implementation
        USDE newImplementation = new USDE(this);
        
        // Try to upgrade as an authorized upgrader
        vm.recordLogs();
        usde.upgradeToAndCall(address(newImplementation), "");
        
        // Verify the upgrade event was emitted
        vm.getRecordedLogs();
        // The actual verification is that no revert occurred
    }
    
    // Test unauthorized upgrade
    function testUnauthorizedUpgrade(address unauthorized) public {
        vm.assume(unauthorized != address(0) && unauthorized != address(this));
        
        // Deploy a new implementation
        USDE newImplementation = new USDE(this);
        
        // Try to upgrade as an unauthorized user
        vm.prank(unauthorized);
        vm.expectRevert();
        usde.upgradeToAndCall(address(newImplementation), "");
    }
    
    // Helper function to hash typed data (similar to the contract's internal function)
    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        bytes32 DOMAIN_SEPARATOR = usde.DOMAIN_SEPARATOR();
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }
}

contract USDETest is Test, Constants {
    USDE public usde;

    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function isValid(address from, address to) external view returns (bool) {
        // For testing purposes, accept all addresses as valid, including zero address
        return true;
    }

    function setUp() public {
        USDE implementation = new USDE(IValidator(address(this)));
        ERC1967Proxy usdeProxy = new ERC1967Proxy(address(implementation), abi.encodeCall(USDE.initialize, (address(this))));
        //usde.initialize();
        usde = USDE(address(usdeProxy));
        usde.grantRole(MINT_ROLE, address(this));
        usde.grantRole(INVEST_TOKEN_ROLE, address(this));
        usde.grantRole(BURN_ROLE, address(this));
        usde.grantRole(BLOCK_ROLE, address(this));
        usde.grantRole(PAUSER_ROLE, address(this));
        usde.grantRole(FREEZE_ROLE, address(this));
        usde.grantRole(ALLOW_ROLE, address(this));
    }

    function testInitialize() public {
        assertTrue(usde.hasRole(0x00, address(this)));
        assertEq(usde.symbol(), "USDE");
        assertEq(usde.name(), "EuroDollar");
        assertEq(usde.decimals(), 18);
    }

    function testInitializeNewProxy() public {
        USDE newEudImplementation = new USDE(IValidator(address(this)));
        ERC1967Proxy newEudProxy = new ERC1967Proxy(address(newEudImplementation), abi.encodeCall(USDE.initialize, (address(this))));
        USDE newEud = USDE(address(newEudProxy));
        assertEq(newEud.hasRole(0x00, address(this)), true);
        assertEq(newEud.symbol(), "USDE");
        assertEq(newEud.name(), "EuroDollar");
        assertEq(newEud.decimals(), 18);
    }

    function testMintEud(uint256 amount) public {
        // Bound amount to a reasonable range
        amount = bound(amount, 1, 1000000 * 10**18); // For example, between 1 and 1M tokens
    
        usde.grantRole(MINT_ROLE, address(this));
        usde.mint(address(this), amount);
        assertEq(usde.balanceOf(address(this)), amount);
    }

    function testBurnEud(uint256 amount) public {
        usde.mint(address(this), amount);
        usde.burn(address(this), amount);
        assertEq(usde.balanceOf(address(this)), 0);
    }

    function test_RevertMintEudNotAuthorized(address account, uint256 amount) public {
        vm.assume(account != address(this));
        vm.prank(account);
        vm.expectRevert();
        usde.mint(address(this), amount);
    }

    function test_RevertBurnEudNotAuthorized(address account, uint256 amount) public {
        // Make sure account is not zero address and not this contract
        vm.assume(account != address(0) && account != address(this));

        usde.mint(account, amount);
        vm.prank(account);
        vm.expectRevert();
        usde.burn(account, amount);
        assertEq(usde.balanceOf(address(this)), 0);
    }

    function testGrantMintRole(address account) public {
        usde.grantRole(MINT_ROLE, account);
        assertTrue(usde.hasRole(MINT_ROLE, account));
    }

    function testGrantBurnRole(address account) public {
        usde.grantRole(BURN_ROLE, account);
        assertTrue(usde.hasRole(BURN_ROLE, account));
    }

    function testGrantPauseRole(address account) public {
        usde.grantRole(PAUSER_ROLE, account);
        assertTrue(usde.hasRole(PAUSER_ROLE, account));
    }

    function testGrantAdminRole(address account) public {
        usde.grantRole(DEFAULT_ADMIN_ROLE, account);
        assertTrue(usde.hasRole(DEFAULT_ADMIN_ROLE, account));
    }

    function testPause(address pauser) public {
        usde.grantRole(PAUSER_ROLE, pauser);
        vm.prank(pauser);
        usde.pause();
        assertTrue(usde.paused());
    }

    function test_RevertUnauthorizedGrantRoles(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        vm.expectRevert();
        usde.grantRole(DEFAULT_ADMIN_ROLE, account);
    }

    function test_RevertUnauthorizedGrantMintRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        vm.expectRevert();
        usde.grantRole(MINT_ROLE, account);
    }

    function test_RevertUnauthorizedGrantBurnRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        vm.expectRevert();
        usde.grantRole(BURN_ROLE, account);
    }

    function test_RevertUnauthorizedGrantPauseRole(address account) public {
        vm.assume(account != address(this));
        vm.prank(account);
        vm.expectRevert();
        usde.grantRole(PAUSER_ROLE, account);
    }

    function testUnpause(address pauser) public {
        usde.grantRole(PAUSER_ROLE, pauser);
        vm.prank(pauser);
        usde.pause();
        assertTrue(usde.paused());
        vm.prank(pauser);
        usde.unpause();
        assertEq(usde.paused(), false);
    }

    function test_RevertUnathorizedPause(address pauser) public {
        vm.assume(pauser != address(this));
        vm.prank(pauser);
        vm.expectRevert();
        usde.pause();
    }

    function test_RevertUnathorizedUnpause(address pauser) public {
        vm.assume(pauser != address(this));
        usde.pause();
        vm.prank(pauser);
        vm.expectRevert();
        usde.unpause();
    }

    function testTransferEud(address account, uint256 amount) public {
        vm.assume(account != address(0));
        usde.mint(address(this), amount);
        usde.transfer(account, amount);
        assertEq(usde.balanceOf(account), amount);
        vm.prank(account);
        usde.transfer(address(this), amount);
        assertEq(usde.balanceOf(address(this)), amount);
    }



    function testApproveEud(address account, uint256 amount) public {
        vm.assume(account != address(0));
        usde.mint(account, amount);
        assertEq(usde.balanceOf(account), amount);
        vm.prank(account);
        usde.approve(address(this), amount);
        assertEq(usde.allowance(account, address(this)), amount);
    }

    function testIncreaseAllowance(address account, uint256 amount) public {
        vm.assume(account != address(0));
        usde.mint(account, amount);
        assertEq(usde.balanceOf(account), amount);
        vm.prank(account);
        usde.approve(address(this), amount);
        assertEq(usde.allowance(account, address(this)), amount);
    }

    function testDecreaseAllowance(address account, uint256 amount) public {
        vm.assume(account != address(0));
        usde.mint(account, amount);
        assertEq(usde.balanceOf(account), amount);
        vm.startPrank(account);
        usde.approve(address(this), amount);
        assertEq(usde.allowance(account, address(this)), amount);
        usde.approve(address(this), 0);
        vm.stopPrank();
        assertEq(usde.allowance(account, address(this)), 0);
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
                    usde.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline);
        usde.permit(owner, receiver, amount, deadline, v, r, s);

        assertEq(usde.allowance(owner, receiver), amount);
        assertEq(usde.nonces(owner), 1);
    }

    function test_RevertPermitTooLate(uint8 privateKey, address receiver, uint256 amount, uint256 deadline) public {
        // Use a smaller upper bound for deadline to prevent overflow when adding 1
        deadline = bound(deadline, 0, UINT256_MAX - 1);

        vm.assume(privateKey != 0);
        vm.assume(receiver != address(0));

        address owner = vm.addr(privateKey);
        vm.assume(owner != receiver);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    usde.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );

        vm.warp(deadline + 1);
        vm.expectRevert();
        usde.permit(owner, receiver, amount, deadline, v, r, s);
    }

    function test_RevertUnauthorizedPermit(
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
        address owner = vm.addr(privateKey1);
        vm.assume(owner != receiver);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey2,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    usde.DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, owner, receiver, amount, 0, deadline))
                )
            )
        );
        vm.warp(deadline);
        vm.expectRevert();
        usde.permit(owner, receiver, amount, deadline, v, r, s);
    }

    // This event is not reachable directly from the original implementation for some reason
    event Upgraded(address indexed implementation);
}

contract BalanceOf is Test {
    USDE usde;

    function isValid(address from, address to) external view returns (bool) {
        // For testing purposes, accept all addresses as valid, including zero address
        return true;
    }

    function setUp() public {
        USDE implementation = new USDE(IValidator(address(this)));
        ERC1967Proxy usdeProxy = new ERC1967Proxy(address(implementation), abi.encodeCall(USDE.initialize, (address(this))));
        usde = USDE(address(usdeProxy));

        usde.grantRole(usde.MINT_ROLE(), address(this));
    }

    function test_balanceOf() public {
        assertEq(usde.balanceOf(address(this)), 0);
        usde.mint(address(this), 1000);
        assertEq(usde.balanceOf(address(this)), 1000);
    }

    function test_totalSupply() public {
        assertEq(usde.totalSupply(), 0);
        usde.mint(address(this), 1000);
        assertEq(usde.totalSupply(), 1000);
    }


}


contract Paused is Test {
    USDE usde;

        function isValid(address from, address to) external view returns (bool) {
        // For testing purposes, accept all addresses as valid, including zero address
        return true;
    }

    function setUp() public {
        USDE implementation = new USDE(IValidator(address(this)));
        ERC1967Proxy usdeProxy = new ERC1967Proxy(address(implementation), abi.encodeCall(USDE.initialize, (address(this))));
        usde = USDE(address(usdeProxy));

        usde.grantRole(usde.MINT_ROLE(), address(this));
        usde.grantRole(usde.BURN_ROLE(), address(this));
        usde.grantRole(usde.INVEST_TOKEN_ROLE(), address(this));
        usde.grantRole(usde.PAUSER_ROLE(), address(this));

        usde.mint(address(this), 1000);
        usde.pause();
    }

    function invariant_paused() public {
        assertTrue(usde.paused(), "USDE should be paused");
    }

    function test_CannotTransfer() public {
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        usde.transfer(address(this), 0);
    }

    function test_CannotTransferFrom(address any) public {
        vm.assume(any != address(0)); // Avoid zero address

        // Approve a large allowance for this test
        usde.approve(address(this), 1000);

        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        usde.transferFrom(address(this), any, 1000);
    }

    function test_burn() public {
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        usde.burn(address(this), 10);
    }

    function test_mint() public {
        vm.expectRevert(abi.encodeWithSignature("EnforcedPause()"));
        usde.mint(address(this), 10);
    }
}


