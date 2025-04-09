// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Validator} from "../src/Validator.sol";

contract BlacklistLoader is Script {
    using stdJson for string;

    function run() external {
        // Get private key from environment variables
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        // Load validator contract address from environment variables
        address validatorAddress = vm.envAddress("VALIDATOR_ADDRESS");
        Validator validator = Validator(validatorAddress);
        
        console.log("BlacklistLoader running with deployer:", deployer);
        console.log("Validator contract address:", validatorAddress);
        
        // Load the blacklist file
        string memory filePath = string("./blacklist.json");
        console.log("Loading addresses from:", filePath);
        
        // Parse the JSON file directly as an array
        string memory json = vm.readFile(filePath);
        address[] memory addresses = abi.decode(vm.parseJson(json), (address[]));
        
        // Start transaction and blacklist addresses
        vm.startBroadcast(deployerPrivateKey);
        
        // Check if deployer has blacklister role
        bytes32 blacklisterRole = validator.BLACKLISTER_ROLE();
        if (!validator.hasRole(blacklisterRole, deployer)) {
            console.log("WARNING: Deployer does not have BLACKLISTER_ROLE");
            console.log("Transaction will likely fail");
        }
        
        // Process addresses in batches to avoid gas limits
        uint batchSize = 100;
        for (uint i = 0; i < addresses.length; i += batchSize) {
            uint end = i + batchSize;
            if (end > addresses.length) {
                end = addresses.length;
            }
            
            // Create batch array
            address[] memory batch = new address[](end - i);
            for (uint j = 0; j < end - i; j++) {
                batch[j] = addresses[i + j];
            }
            
            // Blacklist batch
            console.log("Blacklisting batch %d to %d", i, end - 1);
            validator.blacklist(batch);
        }
        
        vm.stopBroadcast();
        console.log("BlacklistLoader completed successfully");
    }
}