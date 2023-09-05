// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {EUD} from "../src/EUD.sol";
import {EUI} from "../src/EUI.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {ERC1967Proxy} from "oz/proxy/ERC1967/ERC1967Proxy.sol";

contract Deploy is Script {

    bytes32 constant DEFAULT_ADMIN_ROLE = keccak256("DEFAULT_ADMIN_ROLE");

    function run() external returns (address, address, address) {
        address yieldOracle = _deployYieldOracle();
        address eud = _deployEUD();
        address eui = _deployEUI(eud, yieldOracle);
        return (eud, eui, yieldOracle);
    }

    function _deployYieldOracle() internal returns (address) {
        vm.startBroadcast();
        YieldOracle oracle = new YieldOracle();
        vm.stopBroadcast();
        return address(oracle);
    }

    function _deployEUD() internal returns (address) {
        vm.startBroadcast();
        EUD eud = new EUD();
        ERC1967Proxy eudProxy = new ERC1967Proxy(address(eud), abi.encodeWithSelector(EUD(address(0)).initialize.selector));
        address(eudProxy).call(abi.encodeWithSignature("grantRole(bytes32,address)", DEFAULT_ADMIN_ROLE, address(this)));
        
        return address(eudProxy);
    }
    function _deployEUI(address eud, address yieldOracle) internal returns (address) {
        vm.startBroadcast();
        EUI eui = new EUI();
        ERC1967Proxy euiproxy = new ERC1967Proxy(address(eui), abi.encodeWithSelector(EUI(address(0)).initialize.selector, eud, yieldOracle));
        return address(euiproxy);
    }
}