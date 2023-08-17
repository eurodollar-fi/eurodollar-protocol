// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "openzeppelin-contracts-upgradeable/security/PausableUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import "openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./Allowlist.sol";
import "./RoleControl.sol";
import "./EUIVault.sol";

/**
 * @author  Fenris
 * @title   An ERC20 contract named EuroInvest
 * @dev     Inherits the OpenZepplin ERC20Upgradeable implentation
 * @notice  Serves as a sercurity token
 */
contract EUI is
    Initializable,
    ERC20Upgradeable,
    EUIVault,
    PausableUpgradeable,
    RoleControl,
    ERC20PermitUpgradeable,
    UUPSUpgradeable,
    Allowlist
{
    mapping(address => uint256) private _frozenBalances;

    /**
     * @notice  The function using this modifier will only execute if the account is allowed.
     * @notice  If the account is not allowed, the transaction will be reverted with the error message "Account is not allowed".
     * @dev     Modifier to check if the given account is allowed.
     * @param   account  The address to be checked for allowlisting.
     */
    modifier verified(address account) {
        require(
            allowlist[account] == true,
            "Account is not on Allowlist"
        );
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    /**
     * @dev Constructor function to disable initializers.
     * @notice This constructor is automatically executed when the contract is deployed.
     * @notice It disables initializers to prevent further modification of contract state after deployment.
     * @notice Only essential setup should be done within this constructor.
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice  This function is called only once during the contract deployment process.
     * @notice  It sets up the EUI token and associated contracts with essential features and permissions.
     * @notice  The contracts' addresses for blocklisting, allowlisting, access control are provided as parameters.
     * @dev     Initialization function to set up the EuroInvest (EUI) token contract.
     * @param   accessControlAddress  The address of the Access Control contract.
     * @param   eudAddress  The address of the EuroDollar (EUD) token contract.
     * @param   tokenFlipperAddress  The address of the token flipper contract.
     */
    function initialize(
        address accessControlAddress,
        address eudAddress,
        address tokenFlipperAddress
    ) public initializer {
        __ERC20_init("EuroDollar Invest", "EUI");
        __EUIVault_init(eudAddress, tokenFlipperAddress);
        __Pausable_init();
        __RoleControl_init(accessControlAddress);
        __ERC20Permit_init("EuroDollar Invest");
        __UUPSUpgradeable_init();
    }

    // ERC20 Pausable
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

    // Supply Management
    /**
     * @notice  This function can only be called by an account with the `MINT_ROLE`.
     * @notice  It mints new tokens and assigns them to the specified recipient's account.
     * @notice  The recipient's account must not be blocklisted and must be verified.
     * @dev     Mints new tokens and adds them to the specified account.
     * @param   to  The address to receive the newly minted tokens.
     * @param   amount  The amount of tokens to mint and add to the account.
     */
    function mint(
        address to,
        uint256 amount
    ) public onlyRole(MINT_ROLE) verified(to) {
        _mint(to, amount);
    }

    /**
     * @notice  This function can only be called by an account with the `BURN_ROLE`.
     * @notice  It removes the specified amount of tokens from the `from` account.
     * @notice  Burning tokens effectively reduces the total supply of the token.
     * @dev     Burns a specific amount of tokens from the specified account.
     * @param   from  The address from which tokens will be burned.
     * @param   amount  The amount of tokens to be burned.
     */
    function burn(address from, uint256 amount) public onlyRole(BURN_ROLE) {
        _burn(from, amount);
    }

    // ERC20 Base
    /**
     * @notice  This function is an internal override and is automatically called before token transfers.
     * @notice  It ensures that token transfers are only allowed when the contract is not paused.
     * @notice  This function is used to implement additional checks or logic before token transfers.
     * @dev     Hook function called before any token transfer occurs(check paused or not).
     * @param   from  The address from which tokens are transferred.
     * @param   to  The address to which tokens are transferred.
     * @param   amount  The amount of tokens being transferred.
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override whenNotPaused {
        super._beforeTokenTransfer(from, to, amount);
    }

    /**
     * @notice  This function overrides both ERC20Upgradeable `transfer` and IERC20Upgradeable `transfer` functions.
     * @notice  It ensures that token transfers are allowed for verified accounts and not allowed for blocklisted accounts.
     * @notice  The function returns `true` if the transfer is successful; otherwise, it reverts with an error.
     * @dev     Transfers a specific amount of tokens to the specified address.
     * @param   to  The address to which tokens will be transferred.
     * @param   amount  The amount of tokens to be transferred.
     * @return  bool  A boolean value indicating whether the transfer was successful.
     */
    function transfer(
        address to,
        uint256 amount
    )
        public
        override(ERC20Upgradeable, IERC20Upgradeable)
        verified(msg.sender)
        verified(to)
        returns (bool)
    {
        super.transfer(to, amount);
    }

    /**
     * @notice  This function overrides both ERC20Upgradeable `approve` and IERC20Upgradeable `approve` functions.
     * @notice  It ensures that approval is allowed for verified accounts and not allowed for blocklisted accounts.
     * @notice  The function returns `true` if the approval is successful; otherwise, it reverts with an error.
     * @dev     Sets the allowance for a spender to spend tokens on behalf of the owner.
     * @param   spender  The address of the spender being allowed to spend tokens.
     * @param   amount  The maximum amount of tokens the spender is allowed to spend.
     * @return  bool  A boolean value indicating whether the approval was successful.
     */
    function approve(
        address spender,
        uint256 amount
    )
        public
        override(ERC20Upgradeable, IERC20Upgradeable)
        verified(msg.sender)
        verified(spender)
        returns (bool)
    {
        super.approve(spender, amount);
    }

    /**
     * @notice  This function overrides both ERC20Upgradeable `transferFrom` and IERC20Upgradeable `transferFrom` functions.
     * @notice  It ensures that token transfers are allowed for verified accounts and not allowed for blocklisted accounts.
     * @notice  The function returns `true` if the transfer is successful; otherwise, it reverts with an error.
     * @dev     Transfers tokens from one address to another using the allowance mechanism.
     * @param   from    The address from which tokens are transferred.
     * @param   to      The address to which tokens are transferred.
     * @param   amount  The amount of tokens to be transferred.
     * @return  bool    A boolean value indicating whether the transfer was successful.
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    )
        public
        override(ERC20Upgradeable, IERC20Upgradeable)
        verified(from)
        verified(to)
        returns (bool)
    {
        super.transferFrom(from, to, amount);
    }

    /**
     * @notice  This function overrides both ERC20Upgradeable `increaseAllowance` and IERC20Upgradeable `increaseAllowance` functions.
     * @notice  It ensures that increasing the allowance is allowed for verified accounts and not allowed for blocklisted accounts.
     * @notice  The function returns `true` if the allowance increase is successful; otherwise, it reverts with an error.
     * @dev     Increases the allowance for a spender to spend tokens on behalf of the owner.
     * @param   spender The address of the spender whose allowance is being increased.
     * @param   addedValue The additional amount of tokens the spender is allowed to spend.
     * @return  bool A boolean value indicating whether the allowance increase was successful.
     */
    function increaseAllowance(
        address spender,
        uint256 addedValue
    )
        public
        override
        verified(msg.sender)
        verified(spender)
        returns (bool)
    {
        super.increaseAllowance(spender, addedValue);
    }

    /**
     * @notice  This function overrides both ERC20Upgradeable `decreaseAllowance` and IERC20Upgradeable `decreaseAllowance` functions.
     * @notice  It ensures that decreasing the allowance is allowed for verified accounts and not allowed for blocklisted accounts.
     * @notice  The function returns `true` if the allowance decrease is successful; otherwise, it reverts with an error.
     * @dev     Decreases the allowance for a spender to spend tokens on behalf of the owner.
     * @param   spender The address of the spender whose allowance is being decreased.
     * @param   subtractedValue The amount by which the spender's allowance will be decreased.
     * @return  bool    A boolean value indicating whether the allowance decrease was successful.
     */
    function decreaseAllowance(
        address spender,
        uint256 subtractedValue
    )
        public
        override
        verified(msg.sender)
        verified(spender)
        returns (bool)
    {
        super.decreaseAllowance(spender, subtractedValue);
    }

    // ERC1967
    /**
     * @notice  This function is called internally to authorize an upgrade.
     * @notice  Only accounts with the `UPGRADER_ROLE` can call this function.
     * @notice  This function is used to control access to contract upgrades.
     * @notice  The function does not perform any other action other than checking the role.
     * @dev     Internal function to authorize an upgrade to a new implementation.
     * @param   newImplementation  The address of the new implementation contract.
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @notice  This function overrides the ERC20Permit `permit` function.
     * @notice  It allows a spender to spend tokens on behalf of the owner using a permit signature.
     * @notice  The function performs checks to ensure that the owner and spender are not blocklisted.
     * @dev     Allows an approved spender to spend tokens on behalf of the owner using a permit signature.
     * @param   owner  The address of the token owner.
     * @param   spender  The address of the approved spender.
     * @param   value  The amount of tokens the spender is allowed to spend.
     * @param   deadline  The timestamp until which the permit is valid.
     * @param   v  The recovery byte of the permit signature.
     * @param   r  The first 32 bytes of the permit signature.
     * @param   s  The second 32 bytes of the permit signature.
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        public
        override
        verified(owner)
        verified(spender)
    {
        super.permit(owner, spender, value, deadline, v, r, s);
    }

    function frozenBalanceOf(address account) public view returns (uint256) {
        return _frozenBalances[account];
    }

    function freeze(
        address from,
        address to,
        uint256 amount
    ) external onlyRole(FREEZER_ROLE) {
        _transfer(from, to, amount);
        _frozenBalances[from] += amount;
    }

    function release(
        address from,
        address to,
        uint256 amount
    ) external onlyRole(FREEZER_ROLE) {
        require(
            _frozenBalances[to] >= amount,
            "Release amount exceeds balance"
        );
        _frozenBalances[to] -= amount;
        _transfer(from, to, amount);
    }
}
