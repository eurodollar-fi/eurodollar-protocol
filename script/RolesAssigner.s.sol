// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {Validator} from "../src/Validator.sol";
import {USDE} from "../src/USDE.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {InvestToken} from "../src/InvestToken.sol";

contract RolesAssignment is Script {
    // Contract addresses (loaded from environment)
    address public validatorAddress;
    address public usdeAddress;
    address public oracleAddress;
    address public investTokenAddress;
    
    // Configuration - Change these values before running the script
    struct RoleRecipients {
        address usdeAdmin;
        address usdePauser;
        address usdeMinter;
        address usdeBurner;
        address usdeRescuer;
        address usdeUpgrader;
        
        address investAdmin;
        address investPauser;
        address investMinter;
        address investBurner;
        address investRescuer;
        address investUpgrader;
        
        address validatorAdmin;
        address validatorWhitelister;
        address validatorBlacklister;
        
        address oracleOperator;
    }
    
    // Roles for USDE
    bytes32 public constant USDE_PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant USDE_MINT_ROLE = keccak256("MINT_ROLE");
    bytes32 public constant USDE_BURN_ROLE = keccak256("BURN_ROLE");
    bytes32 public constant USDE_RESCUER_ROLE = keccak256("RESCUER_ROLE");
    bytes32 public constant USDE_UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant USDE_INVEST_TOKEN_ROLE = keccak256("INVEST_TOKEN_ROLE");
    
    // Roles for InvestToken
    bytes32 public constant INVEST_PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant INVEST_MINT_ROLE = keccak256("MINT_ROLE");
    bytes32 public constant INVEST_BURN_ROLE = keccak256("BURN_ROLE");
    bytes32 public constant INVEST_RESCUER_ROLE = keccak256("RESCUER_ROLE");
    bytes32 public constant INVEST_UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    
    // Roles for Validator
    bytes32 public constant VALIDATOR_WHITELISTER_ROLE = keccak256("WHITELISTER_ROLE");
    bytes32 public constant VALIDATOR_BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");

    function run() external {
        // Load addresses from environment variables
        validatorAddress = vm.envAddress("VALIDATOR_ADDRESS");
        usdeAddress = vm.envAddress("USDE_PROXY_ADDRESS");
        oracleAddress = vm.envAddress("ORACLE_ADDRESS");
        investTokenAddress = vm.envAddress("INVEST_TOKEN_PROXY_ADDRESS");
        
        // Get the deployer address from private key
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // -----------------------------------------------------------------------------
        // Configure role recipients - MODIFY THIS SECTION BEFORE RUNNING THE SCRIPT
        // -----------------------------------------------------------------------------
        RoleRecipients memory recipients = RoleRecipients({
            // USDE roles
            usdeAdmin: deployer,            // Admin for USDE
            usdePauser: deployer,           // Can pause USDE
            usdeMinter: deployer,           // Can mint USDE
            usdeBurner: deployer,           // Can burn USDE
            usdeRescuer: deployer,          // Can recover USDE tokens
            usdeUpgrader: deployer,         // Can upgrade USDE contract
            
            // InvestToken roles
            investAdmin: deployer,          // Admin for InvestToken
            investPauser: deployer,         // Can pause InvestToken
            investMinter: deployer,         // Can mint InvestToken
            investBurner: deployer,         // Can burn InvestToken
            investRescuer: deployer,        // Can recover InvestToken
            investUpgrader: deployer,       // Can upgrade InvestToken contract
            
            // Validator roles
            validatorAdmin: deployer,       // Admin for Validator
            validatorWhitelister: deployer, // Can whitelist addresses
            validatorBlacklister: deployer, // Can blacklist addresses
            
            // Oracle role
            oracleOperator: deployer        // Can update oracle data
        });
        // -----------------------------------------------------------------------------
        // END OF CONFIGURATION
        // -----------------------------------------------------------------------------

        // Start the broadcast to record transactions
        vm.startBroadcast(deployerPrivateKey);
        
        console.log("Deployer address: ", deployer);
        console.log("Using contract addresses:");
        console.log("  Validator: ", validatorAddress);
        console.log("  USDE: ", usdeAddress);
        console.log("  YieldOracle: ", oracleAddress);
        console.log("  InvestToken: ", investTokenAddress);
        
        // Setup contract instances
        Validator validator = Validator(validatorAddress);
        USDE usde = USDE(usdeAddress);
        YieldOracle oracle = YieldOracle(oracleAddress);
        InvestToken investToken = InvestToken(investTokenAddress);
        
        // Step 1: Assign USDE roles
        console.log("Assigning USDE roles...");
        usde.grantRole(USDE_PAUSER_ROLE, recipients.usdePauser);
        usde.grantRole(USDE_MINT_ROLE, recipients.usdeMinter);
        usde.grantRole(USDE_BURN_ROLE, recipients.usdeBurner);
        usde.grantRole(USDE_RESCUER_ROLE, recipients.usdeRescuer);
        usde.grantRole(USDE_UPGRADER_ROLE, recipients.usdeUpgrader);
        
        // Grant InvestToken the INVEST_TOKEN_ROLE to burn USDE tokens
        usde.grantRole(USDE_INVEST_TOKEN_ROLE, investTokenAddress);
        console.log("USDE roles assigned successfully");
        
        // Step 2: Assign InvestToken roles
        console.log("Assigning InvestToken roles...");
        investToken.grantRole(INVEST_PAUSER_ROLE, recipients.investPauser);
        investToken.grantRole(INVEST_MINT_ROLE, recipients.investMinter);
        investToken.grantRole(INVEST_BURN_ROLE, recipients.investBurner);
        investToken.grantRole(INVEST_RESCUER_ROLE, recipients.investRescuer);
        investToken.grantRole(INVEST_UPGRADER_ROLE, recipients.investUpgrader);
        console.log("InvestToken roles assigned successfully");
        
        // Step 3: Assign Validator roles
        console.log("Assigning Validator roles...");
        validator.grantRole(VALIDATOR_WHITELISTER_ROLE, recipients.validatorWhitelister);
        validator.grantRole(VALIDATOR_BLACKLISTER_ROLE, recipients.validatorBlacklister);
        console.log("Validator roles assigned successfully");
        
        // Step 4: Set oracle address for YieldOracle
        console.log("Setting oracle address...");
        oracle.setOracle(recipients.oracleOperator);
        console.log("Oracle address set to:", recipients.oracleOperator);
        
        // End the broadcast
        vm.stopBroadcast();
        
        console.log("All roles assigned successfully!");
    }
}