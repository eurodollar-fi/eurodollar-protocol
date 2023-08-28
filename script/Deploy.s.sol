// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {EUD} from "../src/EUD.sol";
import {EUI} from "../src/EUI.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {ERC1967Proxy} from "oz/proxy/ERC1967/ERC1967Proxy.sol";

contract Deploy is Script {

    address public admin = msg.sender;

    function run() external returns (address, address, address) {
        address yieldOracle = deployYieldOracle(admin);
        address eud = deployEUD(admin);
        address eui = deployEUI(admin, eud, yieldOracle);
        return (eud, eui, yieldOracle);
    }

    function deployYieldOracle(address account) public returns (address) {
        vm.startBroadcast();
        YieldOracle oracle = new YieldOracle(account);
        vm.stopBroadcast();
        return address(oracle);
    }

    function deployEUD(address account) public returns (address) {
        vm.startBroadcast();
        EUD eud = new EUD();
        ERC1967Proxy eudproxy = new ERC1967Proxy(address(eud), abi.encodeWithSelector(EUD(address(0)).initialize.selector, account));
        return address(eudproxy);
    }
    function deployEUI(address account, address eud, address yieldOracle) public returns (address) {
        vm.startBroadcast();
        EUI eui = new EUI();
        ERC1967Proxy euiproxy = new ERC1967Proxy(address(eui), abi.encodeWithSelector(EUI(address(0)).initialize.selector, account, eud, yieldOracle));
        return address(euiproxy);
    }
}