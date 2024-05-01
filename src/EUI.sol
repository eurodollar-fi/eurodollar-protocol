// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2023 Rhinefield Technologies Limited

pragma solidity ^0.8.21;

import {Initializable} from "oz-up/proxy/utils/Initializable.sol";
import {PausableUpgradeable} from "oz-up/security/PausableUpgradeable.sol";
import {ERC20PermitUpgradeable} from "oz-up/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {UUPSUpgradeable} from "oz-up/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "oz-up/access/AccessControlUpgradeable.sol";
import {IYieldOracle} from "./interfaces/IYieldOracle.sol";
import {IEUD} from "./interfaces/IEUD.sol";

/**
 * @author Rhinefield Technologies Limited
 * @title EUI - Eurodollar Invest Token
 */
contract EUI is
    Initializable,
    PausableUpgradeable,
    ERC20PermitUpgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    // @notice YieldOracle contract used to provide EUD/EUI pricing.
    IYieldOracle public yieldOracle;
    // @notice EUD token contract.
    IEUD public immutable eud;
    // @notice Allowlist contains addresses that are allowed to send or receive tokens.
    mapping(address => bool) public allowlist;
    // @notice Mapping of frozen balances that cannot be transferred.
    mapping(address => uint256) public frozenBalances;

    // Roles
    bytes32 public constant PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 public constant MINT_ROLE = keccak256("MINT_ROLE");
    bytes32 public constant BURN_ROLE = keccak256("BURN_ROLE");
    bytes32 public constant ALLOW_ROLE = keccak256("ALLOW_ROLE");
    bytes32 public constant FREEZE_ROLE = keccak256("FREEZE_ROLE");

    /**
     * @dev Modifier to check if an account is allowed to transact.
     * @param account The address of the account to check.
     */
    modifier onlyAllowed(address account) {
        require(allowlist[account], "Account is not on Allowlist");
        _;
    }

    // Events
    event AddedToAllowlist(address indexed account);
    event RemovedFromAllowlist(address indexed account);
    event Freeze(address indexed from, address indexed to, uint256 amount);
    event Release(address indexed from, address indexed to, uint256 amount);
    event Reclaim(address indexed from, address indexed to, uint256 amount);
    event Deposit(
        address indexed sender,
        address indexed owner,
        uint256 assets,
        uint256 shares
    );
    event Withdraw(
        address indexed sender,
        address indexed receiver,
        address indexed owner,
        uint256 assets,
        uint256 shares
    );

    /**
     * @notice Disables initializers for implementation contract.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address eudAddress) {
        eud = IEUD(eudAddress);
        _disableInitializers();
    }

    /**
     * @notice  Initializes EUI token and permissions.
     * @notice  This function is called only once during the contract deployment process.
     */
    function initialize(address yieldOracleAddress) public initializer {
        __ERC20_init("EuroDollar Invest", "EUI");
        __Pausable_init();
        __ERC20Permit_init("EuroDollar Invest");
        __UUPSUpgradeable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        yieldOracle = IYieldOracle(yieldOracleAddress);
    }

    /// ---------- ERC20 FUNCTIONS ---------- ///
    /**
     * @notice Transfers tokens from msg.sender to a specified recipient.
     * @notice The sender and receiver account must be on the allow list.
     * @param to The address to transfer tokens to.
     * @param amount The amount of tokens to transfer.
     * @return A boolean value indicating whether the transfer was successful.
     */
    function transfer(
        address to,
        uint256 amount
    )
        public
        override
        onlyAllowed(msg.sender)
        onlyAllowed(to)
        whenNotPaused
        returns (bool)
    {
        return super.transfer(to, amount);
    }
    /**
     * @notice Transfers tokens from one address to another if approval is granted.
     * @notice The sender and receiver account must be on the allow list.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param amount The amount of tokens to be transferred.
     * @return A boolean that indicates if the operation was successful.
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    )
        public
        override
        onlyAllowed(from)
        onlyAllowed(to)
        whenNotPaused
        returns (bool)
    {
        return super.transferFrom(from, to, amount);
    }

    /// ---------- SUPPLY MANAGEMENT FUNCTIONS ---------- ///
    /**
     * @notice  Mints new tokens and adds them to the specified account.
     * @notice  This function can only be called by an account with the `MINT_ROLE`.
     * @notice  The recipient's account must not be on the blocklist.
     * @param   to  The address to receive the newly minted tokens.
     * @param   amount  The amount of tokens to mint to the account.
     */
    function mintEUI(
        address to,
        uint256 amount
    ) public whenNotPaused onlyRole(MINT_ROLE) onlyAllowed(to) {
        _mint(to, amount);
    }

    /**
     * @notice  Burns a specific amount of tokens from a specified account.
     * @notice  This function can only be called by an account with the `BURN_ROLE`.
     * @param   from  The address from which tokens will be burned.
     * @param   amount  The amount of tokens to be burned.
     */
    function burnEUI(
        address from,
        uint256 amount
    ) public whenNotPaused onlyRole(BURN_ROLE) {
        _burn(from, amount);
    }

    /// ---------- ERC4626 FUNCTIONS ---------- ///
    /**
     * @notice Returns the address of the asset contract.
     */
    function asset() external view returns (address) {
        return address(eud);
    }

    /**
     * @notice Returns the total amount assets (EUD) held in the vault.
     * @return uint256 The total amount of assets held in the vault.
     */
    function totalAssets() external view returns (uint256) {
        return convertToAssets(totalSupply());
    }

    /**
     * @notice Converts the specified amount of assets (EUD) into shares (EUI) using the current price.
     * @param assets  The amount of assets (EUD) to convert into shares (EUI).
     * @return uint256  The equivalent amount of shares (EUI).
     */
    function convertToShares(uint256 assets) public view returns (uint256) {
        return yieldOracle.fromEudToEui(assets);
    }

    /**
     * @notice Converts the specified amount of shares (EUI) into assets (EUD) using the current price.
     * @param   shares  The amount of shares (EUI) to convert into assets (EUD).
     * @return  uint256  The equivalent amount of assets (EUD) based on the current exchange rate.
     */
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return yieldOracle.fromEuiToEud(shares);
    }

    // Deposit
    /**
     * @notice Returns The maximum amount of assets (EUD) that can be deposited.
     * @return uint256 The maximum amount of assets (EUD) that can be deposited.
     */
    function maxDeposit(address) public view returns (uint256) {
        if (paused()) {
            return 0;
        }
        return type(uint256).max;
    }

    /**
     * @notice Previews the number of shares (EUI) that would be obtained by depositing the specified amount of assets (EUD).
     * @param assets The amount of assets (EUD) to be deposited.
     * @return uint256 The number of shares (EUI) that would be obtained by depositing the specified amount of assets (EUD).
     */
    function previewDeposit(uint256 assets) public view returns (uint256) {
        return convertToShares(assets);
    }

    /**
     * @notice Deposits the specified amount of assets (EUD) to receive the corresponding number of shares (EUI).
     * @param assets The amount of assets (EUD) to be deposited.
     * @param receiver The address that will receive the shares (EUI).
     * @return shares The number of shares (EUI) received.
     */
    function deposit(
        uint256 assets,
        address receiver
    ) public onlyAllowed(receiver) whenNotPaused returns (uint256 shares) {
        shares = convertToShares(assets);
        eud.investBurn(msg.sender, assets);
        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    /**
     * @notice  Converts the specified amount of EUD tokens to EUI tokens using the current price.
     * @param   assets  The amount of EUD tokens to be converted to EUI tokens.
     * @param   receiver  The address to receive the minted EUI tokens.
     * @param   owner  The address from which the EUD tokens will be burned.
     * @return  shares  Amount of EUI tokens minted.
     */
    function deposit(
        uint256 assets,
        address receiver,
        address owner
    ) public onlyAllowed(receiver) whenNotPaused returns (uint256 shares) {
        shares = convertToShares(assets);
        eud.investBurn(owner, msg.sender, assets);
        _mint(receiver, shares);

        emit Deposit(owner, receiver, assets, shares);
    }

    // Mint
    /**
     * @notice Returns The maximum amount of shares (EUI) that can be minted for a user.
     * @return uint256 The maximum amount of shares (EUI) that can be minted for a user.
     */
    function maxMint(address) public view returns (uint256) {
        if (paused()) {
            return 0;
        }
        return type(uint256).max;
    }

    /**
     * @notice Previews the amount of assets (EUD) that must be deposited to mint the specified number of shares (EUI).
     * @param shares Amount of shares (EUI).
     * @return uint256 The amount of assets (EUD) that must be deposited to mint the specified number of shares (EUI).
     */
    function previewMint(uint256 shares) public view returns (uint256) {
        return convertToAssets(shares);
    }

    /**
     * @notice Deposits the neccesary amount of assets (EUD) to mint the specified amount of assets (EUI) to the receiver's address.
     * @param shares The number of shares (EUI) to mint.
     * @param receiver The address of the receiver who will receive the shares (EUI).
     * @return assets The amount of assets (EUD) minted deposited to mint the specified number of shares (EUI).
     */
    function mint(
        uint256 shares,
        address receiver
    ) public onlyAllowed(receiver) whenNotPaused returns (uint256 assets) {
        assets = convertToAssets(shares);
        eud.investBurn(msg.sender, assets);
        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    // Withdraw
    /**
     * @notice Returns the maximum amount of assets (EUD) that the specified owner can withdraw based on their share (EUI) balance.
     * @param owner The address of the owner whose maximum withdrawal amount is queried.
     * @return uint256 The maximum amount of assets (EUD) that the owner can withdraw based on their share (EUI) balance.
     */
    function maxWithdraw(address owner) public view returns (uint256) {
        if (paused()) {
            return 0;
        }
        return convertToAssets(this.balanceOf(owner));
    }

    /**
     * @notice Previews the amount of shares (EUI) that will be redeemed when the specified amount of assets (EUD) is withdrawn.
     * @param assets The amount of assets (EUD) to be withdrawn.
     * @return uint256 The preview amount of shares (EUI) that will be redeemed for the given amount of assets (EUD).
     */
    function previewWithdraw(uint256 assets) public view returns (uint256) {
        return convertToShares(assets);
    }

    /**
     * @notice Redeem the necessary amount of shares (EUI) from the vault to receieve specified amount of assets (EUD).
     * @param assets The amount of assets (EUD) to be withdrawn.
     * @param receiver The address that will receive the assets (EUD) upon withdrawal.
     * @param owner The address holding the shares (EUI) to be redeemed.
     * @return shares The amount of shares (EUI) to be withdrawn.
     */
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public onlyAllowed(owner) whenNotPaused returns (uint256 shares) {
        shares = convertToShares(assets);
        if (owner != msg.sender) _spendAllowance(owner, msg.sender, shares);
        _burn(owner, shares);
        eud.investMint(receiver, assets);

        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    // Redeem
    /**
     * @notice Returns the maximum amount of shares (EUI) that can be redeemed for assets (EUD) by the owner of the shares.
     * @param owner The address holding the shares (EUI) to be redeemed.
     * @return uint256 The maximum amount of shares (EUI) that can be redeemed by the owner.
     */
    function maxRedeem(address owner) public view returns (uint256) {
        if (paused()) {
            return 0;
        }
        return this.balanceOf(owner);
    }

    /**
     * @notice Returns the amount of assets (EUD) that would be received by redeeming the specified amount of shares (EUI).
     * @param shares The amount of shares (EUI) to be redeemed for assets (EUD).
     * @return uint256 The amount of assets (EUD) that would be received by redeeming the specified amount of shares (EUI).
     */
    function previewRedeem(uint256 shares) public view returns (uint256) {
        return convertToAssets(shares);
    }

    /**
     * @notice Redeems the specified amount of shares (EUI) for assets (EUD) to the specified receiver.
     * @param shares The amount of shares (EUI) to be redeemed.
     * @param receiver The address that will receive the assets (EUD).
     * @param owner The address of the account that owns the shares (EUI) being redeemed.
     * @return assets The amount of assets (EUD) that have been received.
     */
    function redeem(
        uint256 shares,
        address receiver,
        address owner
    ) public onlyAllowed(owner) whenNotPaused returns (uint256 assets) {
        if (owner != msg.sender) _spendAllowance(owner, msg.sender, shares);
        assets = convertToAssets(shares);
        _burn(owner, shares);
        eud.investMint(receiver, assets);

        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    /// ---------- TOKEN MANAGEMENT FUNCTIONS ---------- ///
    /**
     * @notice Sets the yield oracle contract address.
     * @notice Can only be called by accounts with DEFAULT_ADMIN_ROLE.
     * @param yieldOracleAddress The address of the yield oracle contract.
     */
    function setYieldOracle(address yieldOracleAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        yieldOracle = IYieldOracle(yieldOracleAddress);
    }

    /**
     * @notice  This function can only be called by an account with the `PAUSE_ROLE`.
     * @notice  Once paused, certain operations are unavailable until the contract is unpaused.
     */
    function pause() public onlyRole(PAUSE_ROLE) {
        _pause();
    }

    /**
     * @notice  This function can only be called by an account with the `PAUSE_ROLE`.
     * @notice  It resumes certain functionalities of the contract that were previously paused.
     */
    function unpause() public onlyRole(PAUSE_ROLE) {
        _unpause();
    }

    /**
     * @notice Freezes a specified amount of tokens from a specified address.
     * @notice Only callable by accounts with the `FREEZE_ROLE`.
     * @notice The `to` address will be a contract address that will hold the frozen tokens.
     * @param from The address to freeze tokens from.
     * @param to The address to transfer the frozen tokens to.
     * @param amount The amount of tokens to freeze.
     * @return A boolean value indicating whether the operation succeeded.
     */
    function freeze(
        address from,
        address to,
        uint256 amount
    )
        external
        onlyAllowed(to)
        onlyRole(FREEZE_ROLE)
        returns (bool)
    {
        _transfer(from, to, amount);
        unchecked {
            frozenBalances[from] += amount;
        }
        emit Freeze(from, to, amount);
        return true;
    }

    /**
     * @notice Release a specified amount of frozen tokens.
     * @notice Only callable by accounts with the `FREEZE_ROLE`.
     * @param from The address that currently holds the frozen tokens.
     * @param to The address that will receive the released tokens.
     * @param amount The amount of tokens to release.
     * @return A boolean indicating whether the release was successful.
     */
    function release(
        address from,
        address to,
        uint256 amount
    )
        external
        onlyAllowed(to)
        onlyRole(FREEZE_ROLE)
        returns (bool)
    {
        require(frozenBalances[to] >= amount, "Release amount exceeds balance");
        unchecked {
            frozenBalances[to] -= amount;
        }
        _transfer(from, to, amount);
        emit Release(from, to, amount);
        return true;
    }

    /**
     * @notice Reclaims tokens from one address and mints them to another address.
     * @notice Only callable by accounts with the `FREEZE_ROLE`.
     * @notice Can be used in the event of lost user access to tokens.
     * @param from The address of the account to reclaim tokens from.
     * @param to The address of the account to mint tokens to.
     * @param amount The amount of tokens to reclaim and mint.
     * @return A boolean value indicating whether the operation succeeded.
     */
    function reclaim(
        address from,
        address to,
        uint256 amount
    )
        external
        onlyAllowed(to)
        onlyRole(FREEZE_ROLE)
        returns (bool)
    {
        _burn(from, amount);
        _mint(to, amount);
        emit Reclaim(from, to, amount);
        return true;
    }

    /**
     * @notice Add multiple addresses to the allow list.
     * @notice Only callable by accounts with the `ALLOW_ROLE`.
     * @param accounts The addresses to be added to the allow list.
     */
    function addToAllowlist(address[] calldata accounts) external onlyRole(ALLOW_ROLE) {
        for (uint256 i; i < accounts.length; i++) {
            _addToAllowlist(accounts[i]);
        }
    }

    /**
     * @notice Add a single address to the allow list.
     * @notice Only callable by accounts with the `ALLOW_ROLE`.
     * @param account The address to be added to the allow list.
     */
    function addToAllowlist(address account) external onlyRole(ALLOW_ROLE) {
        _addToAllowlist(account);
    }

    /**
     * @notice  Remove multiple addresses from the allow list.
     * @notice  Only callable by accounts with the `ALLOW_ROLE`.
     * @param   accounts The addresses to be removed from the allow list.
     */
    function removeFromAllowlist(address[] calldata accounts) external onlyRole(ALLOW_ROLE) {
        for (uint256 i; i < accounts.length; i++) {
            _removeFromAllowlist(accounts[i]);
        }
    }

    /**
     * @notice  Remove a single address from the allow list.
     * @notice  Only callable by accounts with the `ALLOW_ROLE`.
     * @param   account The address to be removed from the allow list.
     */
    function removeFromAllowlist(address account) external onlyRole(ALLOW_ROLE) {
        _removeFromAllowlist(account);
    }

    /**
     * @dev Adds an account to the allowl ist.
     * @param account The address to be added to the allowlist.
     */
    function _addToAllowlist(address account) internal {
        allowlist[account] = true;
        emit AddedToAllowlist(account);
    }

    /**
     * @dev Removes an account from the allow list.
     * @param account The address to remove from the allow list.
     */
    function _removeFromAllowlist(address account) internal {
        allowlist[account] = false;
        emit RemovedFromAllowlist(account);
    }

    // ERC1967 Upgrade Function
    /**
     * @notice  Internal function to authorize a contract upgrade.
     * @notice  Only accounts with the `DEFAULT_ADMIN_ROLE` can call this function.
     * @param   newImplementation  The address of the new implementation contract.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
