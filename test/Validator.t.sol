// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../src/Validator.sol";
import "forge-std/console.sol";

error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

contract ValidatorTest is Test {
    Validator public validator;
    address public owner;
    address public whitelister;
    address public blacklister;
    address public user1;
    address public user2;

    function setUp() public {
        owner = address(this);
        whitelister = address(0x1);
        blacklister = address(0x2);
        user1 = address(0x3);
        user2 = address(0x4);

        validator = new Validator(owner, whitelister, blacklister);
    }

    function testRoleAssignment() public view {
        assertTrue(validator.hasRole(validator.DEFAULT_ADMIN_ROLE(), owner));
        assertTrue(validator.hasRole(validator.WHITELISTER_ROLE(), whitelister));
        assertTrue(validator.hasRole(validator.BLACKLISTER_ROLE(), blacklister));
    }

    function testWhitelist() public {
        vm.prank(whitelister);
        validator.whitelist(user1);
        assertEq(uint256(validator.accountStatus(user1)), uint256(Validator.Status.WHITELISTED));
    }

    function testBlacklist() public {
        vm.prank(blacklister);
        validator.blacklist(user1);
        assertEq(uint256(validator.accountStatus(user1)), uint256(Validator.Status.BLACKLISTED));
    }

    function testVoid() public {
        vm.startPrank(whitelister);
        validator.whitelist(user1);
        validator.void(user1);
        vm.stopPrank();
        assertEq(uint256(validator.accountStatus(user1)), uint256(Validator.Status.VOID));
    }

    function testBatchWhitelist() public {
        address[] memory users = new address[](2);
        users[0] = user1;
        users[1] = user2;

        vm.prank(whitelister);
        validator.whitelist(users);

        assertEq(uint256(validator.accountStatus(user1)), uint256(Validator.Status.WHITELISTED));
        assertEq(uint256(validator.accountStatus(user2)), uint256(Validator.Status.WHITELISTED));
    }

    function testBatchBlacklist() public {
        address[] memory users = new address[](2);
        users[0] = user1;
        users[1] = user2;

        vm.prank(blacklister);
        validator.blacklist(users);

        assertEq(uint256(validator.accountStatus(user1)), uint256(Validator.Status.BLACKLISTED));
        assertEq(uint256(validator.accountStatus(user2)), uint256(Validator.Status.BLACKLISTED));
    }

    function testIsValid() public {
        vm.prank(blacklister);
        validator.blacklist(user1);

        assertTrue(validator.isValid(user1, address(0)));
        assertFalse(validator.isValid(user1, user2));
        assertFalse(validator.isValid(user2, user1));
    }

    function testIsValidStrict() public {
        vm.startPrank(whitelister);
        validator.whitelist(user1);
        validator.whitelist(user2);
        vm.stopPrank();

        assertTrue(validator.isValidStrict(user1, user2));
        assertFalse(validator.isValidStrict(user1, address(0x5)));
        assertTrue(validator.isValidStrict(address(0x5), address(0)));
    }

    function testUnauthorizedWhitelist() public {
        vm.expectRevert(
            abi.encodeWithSelector(AccessControlUnauthorizedAccount.selector, user1, validator.WHITELISTER_ROLE())
        );
        vm.prank(user1);
        validator.whitelist(user2);
    }

    function testUnauthorizedBlacklist() public {
        vm.expectRevert(
            abi.encodeWithSelector(AccessControlUnauthorizedAccount.selector, user1, validator.BLACKLISTER_ROLE())
        );
        vm.prank(user1);
        validator.blacklist(user2);
    }
}
