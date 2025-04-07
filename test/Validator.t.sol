// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../src/Validator.sol";
import "forge-std/console.sol";

contract ValidatorCoverageTest is Test {
    Validator public validator;
    address public owner;
    address public whitelister;
    address public blacklister;
    address public user1;
    address public user2;
    address public user3;

    function setUp() public {
        owner = address(this);
        whitelister = address(0x1);
        blacklister = address(0x2);
        user1 = address(0x3);
        user2 = address(0x4);
        user3 = address(0x5);

        validator = new Validator(owner, whitelister, blacklister);
    }

    // Test batch void function - uncovered function
    function testBatchVoid() public {
        // First whitelist some users
        vm.startPrank(whitelister);
        validator.whitelist(user1);
        validator.whitelist(user2);
        
        // Then void them in batch
        address[] memory users = new address[](2);
        users[0] = user1;
        users[1] = user2;
        validator.void(users);
        vm.stopPrank();

        // Check if they've been voided
        assertEq(uint256(validator.accountStatus(user1)), uint256(Validator.Status.VOID));
        assertEq(uint256(validator.accountStatus(user2)), uint256(Validator.Status.VOID));
    }

    // Test isWhitelisted and isBlacklisted functions
    function testIsWhitelistedAndBlacklisted() public {
        // Setup different user statuses
        vm.prank(whitelister);
        validator.whitelist(user1);
        
        vm.prank(blacklister);
        validator.blacklist(user2);
        
        // Test isWhitelisted function
        assertTrue(validator.isWhitelisted(user1));
        assertFalse(validator.isWhitelisted(user2));
        assertFalse(validator.isWhitelisted(user3)); // user3 has no status
        
        // Test isBlacklisted function
        assertFalse(validator.isBlacklisted(user1));
        assertTrue(validator.isBlacklisted(user2));
        assertFalse(validator.isBlacklisted(user3)); // user3 has no status
    }

    // Test minting scenario in isValid
    function testIsValidWithMinting() public {
        address zeroAddress = address(0);
        
        // Blacklist a user
        vm.prank(blacklister);
        validator.blacklist(user1);
        
        // Test minting scenario (from = address(0))
        assertTrue(validator.isValid(zeroAddress, user2)); // to not blacklisted
        assertFalse(validator.isValid(zeroAddress, user1)); // to blacklisted
    }

    // Test minting scenario in isValidStrict
    function testIsValidStrictWithMinting() public {
        address zeroAddress = address(0);
        
        // Whitelist a user
        vm.prank(whitelister);
        validator.whitelist(user1);
        
        // Test minting scenario (from = address(0))
        assertTrue(validator.isValidStrict(zeroAddress, user1)); // to whitelisted
        assertFalse(validator.isValidStrict(zeroAddress, user2)); // to not whitelisted
    }

    // Test burning scenario in isValid
    function testIsValidWithBurning() public {
        address zeroAddress = address(0);
        
        // Blacklist a user
        vm.prank(blacklister);
        validator.blacklist(user1);
        
        // Test burning scenario (to = address(0))
        assertTrue(validator.isValid(user1, zeroAddress)); // from blacklisted, burning is allowed
        assertTrue(validator.isValid(user2, zeroAddress)); // from not blacklisted, burning is allowed
    }

    // Test burning scenario in isValidStrict
    function testIsValidStrictWithBurning() public {
        address zeroAddress = address(0);
        
        // Whitelist a user
        vm.prank(whitelister);
        validator.whitelist(user1);
        
        // Test burning scenario (to = address(0))
        assertTrue(validator.isValidStrict(user1, zeroAddress)); // from whitelisted, burning is allowed
        assertTrue(validator.isValidStrict(user2, zeroAddress)); // from not whitelisted, burning is allowed
    }

    // Test complex scenarios with combinations of blacklisted/whitelisted accounts
    function testComplexValidationScenarios() public {
        // Setup users with different statuses
        vm.prank(whitelister);
        validator.whitelist(user1);
        
        vm.prank(blacklister);
        validator.blacklist(user2);
        
        // Test isValid with different combinations
        assertTrue(validator.isValid(user1, user3)); // whitelisted to no status
        assertFalse(validator.isValid(user1, user2)); // whitelisted to blacklisted
        assertFalse(validator.isValid(user2, user1)); // blacklisted to whitelisted
        assertFalse(validator.isValid(user2, user3)); // blacklisted to no status
        
        // Test isValidStrict with different combinations
        assertFalse(validator.isValidStrict(user1, user3)); // whitelisted to no status
        assertFalse(validator.isValidStrict(user1, user2)); // whitelisted to blacklisted
        assertFalse(validator.isValidStrict(user2, user1)); // blacklisted to whitelisted
        assertFalse(validator.isValidStrict(user3, user3)); // no status to no status
    }

    // Test unauthorized void operations
    function testUnauthorizedVoid() public {
        vm.expectRevert();
        vm.prank(user1);
        validator.void(user2);
        
        address[] memory users = new address[](1);
        users[0] = user2;
        
        vm.expectRevert();
        vm.prank(user1);
        validator.void(users);
    }

    // Test granting and revoking roles
    function testRoleManagement() public {
        // Test granting a new whitelister
        vm.prank(owner);
        validator.grantRole(validator.WHITELISTER_ROLE(), user3);
        assertTrue(validator.hasRole(validator.WHITELISTER_ROLE(), user3));
        
        // Test that the new whitelister can perform whitelisting
        vm.prank(user3);
        validator.whitelist(user1);
        assertTrue(validator.isWhitelisted(user1));
        
        // Test revoking a role
        vm.prank(owner);
        validator.revokeRole(validator.WHITELISTER_ROLE(), user3);
        assertFalse(validator.hasRole(validator.WHITELISTER_ROLE(), user3));
        
        // Test that the revoked whitelister can no longer whitelist
        vm.expectRevert();
        vm.prank(user3);
        validator.whitelist(user2);
    }

    // Test changing a user's status multiple times
    function testStatusTransitions() public {
        // Whitelist -> Blacklist -> Void -> Whitelist again
        vm.prank(whitelister);
        validator.whitelist(user1);
        assertTrue(validator.isWhitelisted(user1));
        
        vm.prank(blacklister);
        validator.blacklist(user1);
        assertTrue(validator.isBlacklisted(user1));
        assertFalse(validator.isWhitelisted(user1));
        
        vm.prank(whitelister);
        validator.void(user1);
        assertFalse(validator.isBlacklisted(user1));
        assertFalse(validator.isWhitelisted(user1));
        
        vm.prank(whitelister);
        validator.whitelist(user1);
        assertTrue(validator.isWhitelisted(user1));
        assertFalse(validator.isBlacklisted(user1));
    }
}