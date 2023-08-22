// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;
import "openzeppelin-contracts/contracts/access/AccessControl.sol";
import "openzeppelin-contracts/contracts/security/Pausable.sol";
import "openzeppelin-contracts/contracts/utils/math/Math.sol";
import "../interfaces/IEUD.sol";
import "../interfaces/IEUI.sol";
import "../interfaces/IYieldOracle.sol";


/**
 * @author  Fenris
 * @title   TokenFlipper
 * @dev     A contract that implements a token flipper for swapping between EuroInvest (EUI) and EuroDollar (EUD) tokens.
 * @dev     The contract allows users to flip their tokens between EUI and EUD with respect to the current yield oracle's price.
 * @dev     Only authorized accounts with specific roles are allowed to interact with the contract for access control.
 * @dev     The contract is pausable to prevent certain functionalities in emergency situations.
 */

contract TokenFlipper is Pausable, AccessControl {
    using Math for uint256;
    // event
    event FlippedToEUD(
        address indexed account,
        uint256 euiAmount,
        uint256 eudAmount
    );
    event FlippedToEUI(
        address indexed account,
        uint256 eudAmount,
        uint256 euiAmount
    );
    IEUD public eud;
    IEUI public eui;
    IYieldOracle public yieldOracle;

    // Roles
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant MINT_ROLE = keccak256("MINT_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant BURN_ROLE = keccak256("BURN_ROLE");
    bytes32 public constant BLOCKLIST_ROLE = keccak256("BLOCKLIST_ROLE");
    bytes32 public constant FREEZER_ROLE = keccak256("FREEZER_ROLE");
    bytes32 public constant WITHDRAW_ROLE = keccak256("WITHDRAW_ROLE");

    /**
     * @notice  This modifier make sure the only address can call the function is eui contract
     * @dev     modifier to check if the msg.sender is eui
     */
    modifier onlyEUI() {
        require(
            msg.sender == address(eui),
            "Only EUI contract is allowed, you are "
        );
        _;
    }

    /**
     * @notice  The constructor sets up the contract with the specified contract addresses and access control.
     * @dev     Constructor to initialize the TokenFlipper contract.
     * @param   yieldOracleAddress The address of the yield oracle contract used for pricing.
     * @param   account The address of the EuroDollarAccessControl contract for role-based access control.
     */
    constructor(
        address yieldOracleAddress, address account
    ) Pausable() {
        yieldOracle = IYieldOracle(yieldOracleAddress);
        _grantRole(DEFAULT_ADMIN_ROLE, account);
    }

    // Pausable
    /**
     * @notice  This function can only be called by an account with the `PAUSE_ROLE`.
     * @notice  It pauses certain functionalities of the contract, preventing certain actions.
     * @notice  Once paused, certain operations may not be available until the contract is unpaused.
     * @dev     Pauses the contract functionality.
     */
    function pause() public onlyRole(PAUSE_ROLE) {
        _pause();
    }

    /**
     * @notice  This function can only be called by an account with the `PAUSE_ROLE`.
     * @notice  It resumes certain functionalities of the contract that were previously paused.
     * @notice  Once unpaused, the contract regains its full functionality.
     * @dev     Unpauses the contract functionality.
     */
    function unpause() public onlyRole(PAUSE_ROLE) {
        _unpause();
    }

    /**
     * @notice  This function is accessible only to accounts with the `ADMIN_ROLE`.
     * @dev     Function to update the address of the oracle source contract (YieldOracle).
     * @param   yieldOracleAddress  The new address of the YieldOracle contract.
     */
    function updateOracleSource(
        address yieldOracleAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        yieldOracle = IYieldOracle(yieldOracleAddress);
    }

    /**
     * @notice  This function is accessible only to accounts with the `ADMIN_ROLE`.
     * @dev     Function to set the address of the EUD (EuroDollar) contract.
     * @param   eudAddress  The address of the EuroDollar (EUD) contract.
     */
    function setEUD(address eudAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        eud = IEUD(eudAddress);
    }

    /**
     * @notice  This function is accessible only to accounts with the `ADMIN_ROLE`.
     * @dev     Function to set the address of the EUI (EuroInvest) contract.
     * @param   euiAddress  The address of the EuroInvest (EUI) contract.
     */
    function setEUI(address euiAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        eui = IEUI(euiAddress);
    }

    /**
     * @notice  This function is a read-only function and does not modify any state in the contract.
     * @dev     Function to calculate the equivalent amount of EUI tokens for a given amount of EUD tokens.
     * @param   eudAmount  The amount of EUD tokens for which the equivalent EUI tokens need to be calculated.
     * @return  uint256  The equivalent amount of EUI tokens based on the current price from the yield oracle.
     */
    function fromEudToEui(uint256 eudAmount) public view returns (uint256) {
        uint256 currentPrice = yieldOracle.currentPrice();
        return
            eudAmount.mulDiv(
                10 ** eui.decimals(),
                currentPrice,
                Math.Rounding.Down
            );
    }

    /**
     * @notice  This function is a read-only function and does not modify any state in the contract.
     * @dev     Function to calculate the equivalent amount of EUD tokens for a given amount of EUI tokens.
     * @param   euiAmount  The amount of EUI tokens for which the equivalent EUD tokens need to be calculated.
     * @return  uint256  The equivalent amount of EUD tokens based on the previous epoch price from the yield oracle.
     */
    function fromEuiToEud(uint256 euiAmount) public view returns (uint256) {
        uint256 currentPrice = yieldOracle.oldPrice();
        return
            euiAmount.mulDiv(
                currentPrice,
                10 ** eui.decimals(),
                Math.Rounding.Down
            );
    }

    /**
     * @notice  This function can only be called from within the contract and is used to perform EUD to EUI token conversion.
     * @dev     Internal function to convert EUD tokens to EUI tokens.
     * @param   amount  The amount of EUD tokens to be converted to EUI tokens.
     * @param   receiver  The address to receive the minted EUI tokens.
     * @param   owner  The address from which the EUD tokens will be burned.
     * @return  uint256  The equivalent amount of EUI tokens based on the current epoch price from the yield oracle.
     */
    function flipToEUI(
        address owner,
        address receiver,
        uint256 amount
    ) external whenNotPaused returns (uint256) {
        uint256 euiMintAmount = fromEudToEui(amount);
        require(eud.transferFrom(owner, address(this), amount), "EUD transfer failed");
        eud.burn(address(this), amount);
        eui.mint(receiver, euiMintAmount);
        return euiMintAmount;
    }

    /**
     * @notice  This function can only be called from within the contract and is used to perform EUI to EUD token conversion.
     * @dev     Internal function to convert EUI tokens to EUD tokens.
     * @param   amount  The amount of EUI tokens to be converted to EUD tokens.
     * @param   receiver  The address to receive the minted EUD tokens.
     * @param   owner  The address from which the EUI tokens will be burned.
     * @return  uint256  The equivalent amount of EUD tokens based on the previous epoch price from the yield oracle.
     */
    function flipToEUD(
        address owner,
        address receiver,
        uint256 amount
    ) external whenNotPaused returns (uint256) {
        uint256 eudMintAmount = fromEuiToEud(amount);
        require(eui.transferFrom(owner, address(this), amount), "EUI transfer failed");
        eui.burn(address(this), amount);
        eud.mint(receiver, eudMintAmount);
        return eudMintAmount;
    }
}
