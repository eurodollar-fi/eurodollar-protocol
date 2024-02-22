// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {EUD} from "../src/EUD.sol";
import {EUI} from "../src/EUI.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {ERC1967Proxy} from "oz/proxy/ERC1967/ERC1967Proxy.sol";

contract Deploy is Script {

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MINT_ROLE = keccak256("MINT_ROLE");
    bytes32 public constant BURN_ROLE = keccak256("BURN_ROLE");
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant FREEZE_ROLE = keccak256("FREEZE_ROLE");
    bytes32 public constant BLOCK_ROLE = keccak256("BLOCK_ROLE");
    bytes32 public constant ALLOW_ROLE = keccak256("ALLOW_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    function run() external returns (address, address, address) {
        vm.startBroadcast();
        
        // Deploy YieldOracle
        YieldOracle oracle = new YieldOracle();
        console.log("Oracle address:", address(oracle));

        // Deploy EUD Token
        EUD eudImplementation = new EUD();
        console.log("EUD implementation address:");
        console.log(address(eudImplementation));
        
        ERC1967Proxy eudProxy = new ERC1967Proxy(address(eudImplementation), abi.encodeCall(EUD.initialize, ()));
        console.log("EUDProxy address:");
        console.log(address(eudProxy));

        // Deploy EUI Token
        EUI euiImplementation = new EUI(address(eudProxy));
        console.log("EUI implementation address:");
        
        ERC1967Proxy euiProxy =
            new ERC1967Proxy(address(euiImplementation), abi.encodeCall(EUI.initialize, (address(oracle))));
        console.log("EUIProxy address:");
        console.log(address(euiProxy));

        //Setup
        EUD eud = EUD(address(eudProxy));
        EUI eui = EUI(address(euiProxy));

        eud.setEui(address(euiProxy));
        eud.grantRole(MINT_ROLE, msg.sender);
        eud.grantRole(BURN_ROLE, msg.sender);
        eud.grantRole(BLOCK_ROLE, msg.sender);
        eud.grantRole(PAUSE_ROLE, msg.sender);
        eud.grantRole(FREEZE_ROLE, msg.sender);
        eud.grantRole(ALLOW_ROLE, msg.sender);

        eud.grantRole(MINT_ROLE, address(eui));
        eud.grantRole(BURN_ROLE, address(eui));

        eui.grantRole(MINT_ROLE, msg.sender);
        eui.grantRole(BURN_ROLE, msg.sender);
        eui.grantRole(ALLOW_ROLE, msg.sender);
        eui.grantRole(PAUSE_ROLE, msg.sender);
        eui.grantRole(FREEZE_ROLE, msg.sender);

        vm.stopBroadcast();
        return (address(eudProxy), address(euiProxy), address(oracle));
    }
}
