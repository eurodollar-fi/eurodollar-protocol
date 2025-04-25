// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

import "forge-std/StdUtils.sol";
import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IValidator} from "../src/interfaces/IValidator.sol";
import {IUSDE} from "../src/interfaces/IUSDE.sol";
import {IYieldOracle} from "../src/interfaces/IYieldOracle.sol";

import {Validator} from "../src/Validator.sol";
import {USDE} from "../src/USDE.sol";
import {YieldOracle} from "../src/YieldOracle.sol";
import {InvestToken} from "../src/InvestToken.sol";

contract Deploy is Script {
    using Strings for uint256;
    using Strings for address;

    // CREATE2 salts - can be any value, but must be consistent for deterministic deployments
    bytes32 constant VALIDATOR_SALT = bytes32(uint256(6));
    bytes32 constant USDE_IMPLEMENTATION_SALT = bytes32(uint256(7));
    bytes32 constant USDE_PROXY_SALT = bytes32(uint256(8));
    bytes32 constant ORACLE_SALT = bytes32(uint256(9));
    bytes32 constant INVEST_IMPLEMENTATION_SALT = bytes32(uint256(10));
    bytes32 constant INVEST_PROXY_SALT = bytes32(uint256(11));

    function run() external {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        address deployer = vm.addr(vm.envUint("PRIVATE_KEY"));
        
        // Get current network name
        string memory network = vm.envOr("NETWORK", string("development"));

        console.log("Deployer address: ", deployer);

        // Deploy Validator
        IValidator validator = deployValidator(deployer, deployer, deployer);
        console.log("Deployed Validator: ", address(validator));

        // Deploy USDE
        IUSDE usde = deployUSDE(validator, deployer);
        console.log("Deployed USDE: ", address(usde));
        address usdeImpl = computePredictedAddress(USDE_IMPLEMENTATION_SALT);
        console.log("USDE implementation: ", usdeImpl);

        // Deploy YieldOracle
        IYieldOracle yieldOracle = deployYieldOracle(deployer, deployer);
        console.log("Deployed YieldOracle: ", address(yieldOracle));

        // Deploy InvestToken
        address investToken =
            deployInvestToken(validator, usde, "Eurodollar Invest Token", "EUI", deployer, yieldOracle);
        console.log("Deployed InvestToken EUI: ", investToken);
        address investImpl = computePredictedAddress(INVEST_IMPLEMENTATION_SALT);
        console.log("InvestToken implementation: ", investImpl);

        // Build a simple JSON string directly
        string memory json = string(abi.encodePacked(
            '{',
            '"network":"', network, '",',
            '"deployer":"', deployer.toHexString(), '",',
            '"deploymentTime":', uint256(block.timestamp).toString(), ',',
            '"contracts":{',
                '"validator":"', address(validator).toHexString(), '",',
                '"usde":{',
                    '"proxy":"', address(usde).toHexString(), '",',
                    '"implementation":"', usdeImpl.toHexString(), '"',
                '},',
                '"yieldOracle":"', address(yieldOracle).toHexString(), '",',
                '"investToken":{',
                    '"proxy":"', investToken.toHexString(), '",',
                    '"implementation":"', investImpl.toHexString(), '"',
                '}',
            '}',
            '}'
        ));

        string memory deploymentFileName = string.concat("./broadcast/", network, "-deployment.json");
        vm.writeFile(deploymentFileName, json);
        console.log("Deployment information saved to:", deploymentFileName);

        vm.stopBroadcast();
    }
    
    function computePredictedAddress(bytes32 salt) internal view returns (address) {
        bytes32 bytecodeHash;
        
        if (salt == USDE_IMPLEMENTATION_SALT) {
            bytecodeHash = keccak256(
                abi.encodePacked(
                    type(USDE).creationCode,
                    abi.encode(IValidator(address(0)))
                )
            );
        } else if (salt == INVEST_IMPLEMENTATION_SALT) {
            bytecodeHash = keccak256(
                abi.encodePacked(
                    type(InvestToken).creationCode,
                    abi.encode(IValidator(address(0)), IUSDE(address(0)))
                )
            );
        } else {
            return address(0);
        }
        
        return vm.computeCreate2Address(salt, bytecodeHash);
    }

    function deployWithCreate2(bytes memory creationCode, bytes32 salt) internal returns (address deployed) {
        bytes32 bytecodeHash = keccak256(creationCode);
        address predictedAddress = vm.computeCreate2Address(salt, bytecodeHash);
        console.log("Predicted address:", predictedAddress);

        assembly {
            deployed := create2(0, add(creationCode, 0x20), mload(creationCode), salt)
            if iszero(deployed) { revert(0, 0) }
        }

        require(deployed == predictedAddress, "Address mismatch");
        return deployed;
    }

    function deployValidator(
        address _initialOwner,
        address _whitelister,
        address _blacklister
    )
        public
        returns (IValidator)
    {
        bytes memory creationCode = abi.encodePacked(
            type(Validator).creationCode,
            abi.encode(_initialOwner, _whitelister, _blacklister)
        );
        
        address deployed = deployWithCreate2(creationCode, VALIDATOR_SALT);
        return IValidator(deployed);
    }

    function deployUSDE(IValidator _validator, address _initialOwner) public returns (IUSDE) {
        // Deploy implementation with CREATE2
        bytes memory implCreationCode = abi.encodePacked(
            type(USDE).creationCode,
            abi.encode(_validator)
        );
        
        address implementation = deployWithCreate2(implCreationCode, USDE_IMPLEMENTATION_SALT);
        console.log("USDE implementation: ", implementation);

        // Deploy proxy with CREATE2
        bytes memory proxyCreationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(implementation, abi.encodeCall(USDE.initialize, (_initialOwner)))
        );
        
        address proxy = deployWithCreate2(proxyCreationCode, USDE_PROXY_SALT);
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
        // Deploy implementation with CREATE2
        bytes memory implCreationCode = abi.encodePacked(
            type(InvestToken).creationCode,
            abi.encode(_validator, _usde)
        );
        
        address implementation = deployWithCreate2(implCreationCode, INVEST_IMPLEMENTATION_SALT);
        console.log("InvestToken implementation: ", implementation);

        // Deploy proxy with CREATE2
        bytes memory proxyCreationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(
                implementation, 
                abi.encodeCall(InvestToken.initialize, (_name, _symbol, _initialOwner, _yieldOracle))
            )
        );
        
        address proxy = deployWithCreate2(proxyCreationCode, INVEST_PROXY_SALT);
        return proxy;
    }

    function deployYieldOracle(
        address _initialOwner,
        address _initialOracle
    )
        public
        returns (IYieldOracle yieldOracle)
    {
        bytes memory creationCode = abi.encodePacked(
            type(YieldOracle).creationCode,
            abi.encode(_initialOwner, _initialOracle)
        );
        
        address deployed = deployWithCreate2(creationCode, ORACLE_SALT);
        return IYieldOracle(deployed);
    }
}