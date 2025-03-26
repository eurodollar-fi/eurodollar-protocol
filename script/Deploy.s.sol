// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IValidator} from "../src/interfaces/IValidator.sol";
import {IUSDE} from "../src/interfaces/IUSDE.sol";
import {IYieldOracle} from "../src/interfaces/IYieldOracle.sol";

import {Validator} from "../src/Validator.sol";
import {USDE} from "../src/USDE.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {InvestToken} from "../src/InvestToken.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        address deployer = vm.addr(vm.envUint("PRIVATE_KEY"));


        console.log("Deployer address: ", deployer);

        IValidator validator = deployValidator(deployer, deployer, deployer);
        console.log("Deployed Validator: ", address(validator));

        IUSDE usde = deployUSDE(validator, deployer);
        console.log("Deployed USDE: ", address(usde));

        IYieldOracle yieldOracle = deployYieldOracle(deployer, deployer);
        console.log("Deployed YieldOracle: ", address(yieldOracle));

        address investToken =
            deployInvestToken(validator, usde, "Eurodollar Invest Token", "EUI", deployer, yieldOracle);
        console.log("Deployed InvestToken EUI: ", investToken);

        vm.stopBroadcast();
    }

    function deployValidator(
        address _initialOwner,
        address _whitelister,
        address _blacklister
    )
        public
        returns (IValidator)
    {
        return new Validator(_initialOwner, _whitelister, _blacklister);
    }

    function deployUSDE(IValidator _validator, address _initialOwner) public returns (IUSDE) {
        address implementation = address(new USDE(_validator));
        console.log("USDE implementation: ", implementation);
        address proxy = address(new ERC1967Proxy(implementation, abi.encodeCall(USDE.initialize, (_initialOwner))));
        return IUSDE(proxy);
    }

    function deployInvestToken(
        IValidator _validator,
        IUSDE _usde,
        string memory _name,
        string memory _symbol,
        address _initialOwner,
        IYieldOracle _yieldOracle
    )
        public
        returns (address)
    {
        address implementation = address(new InvestToken(_validator, _usde));
        console.log("InvestToken implementation: ", implementation);
        address proxy = address(
            new ERC1967Proxy(
                implementation, abi.encodeCall(InvestToken.initialize, (_name, _symbol, _initialOwner, _yieldOracle))
            )
        );
        return proxy;
    }

    function deployYieldOracle(
        address _initialOwner,
        address _initialOracle
    )
        public
        returns (IYieldOracle yieldOracle)
    {
        return new YieldOracle(_initialOwner, _initialOracle);
    }
}
