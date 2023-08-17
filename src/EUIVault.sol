// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "openzeppelin-contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import "openzeppelin-contracts-upgradeable/interfaces/IERC4626Upgradeable.sol";
import "../interfaces/IEUD.sol";
import "../interfaces/IYieldOracle.sol";
import "../interfaces/ITokenFlipper.sol";

/**
 * @author  Fenris
 * @title   EUIVault
 * @dev     The EUIVault abstract contract represents a vault that holds EUI (EuroInvest) shares and corresponds to a specific asset, EUD (EuroDollar).
 * @notice  It is used for handling theconversion between EUD assets and EUI shares.
 */

abstract contract EUIVault is
    Initializable,
    ERC20Upgradeable,
    IERC4626Upgradeable
{
    // Asset: EUD
    // Shares: EUI
    address public asset;
    ITokenFlipper private _tokenFlipper;

    /**
     * @notice  Initializes the contract with the address of the EUD asset contract and the address of the ITokenFlipper contract for conversion between EUD and EUI tokens.
     * @dev     This function should only be called during contract initialization.
     * @param   assetAddress  The address of the EUD asset contract.
     * @param   tokenFlipperAddress  The address of the ITokenFlipper contract.
     */
    function __EUIVault_init(
        address assetAddress,
        address tokenFlipperAddress
    ) internal onlyInitializing {
        asset = assetAddress;
        _tokenFlipper = ITokenFlipper(tokenFlipperAddress);
    }

    /**
     * @notice  This function provides the total assets currently held in the vault, which are calculated by converting the total supply of shares (EUI) into assets (EUD) using the current exchange rate.
     * @dev     Returns the total assets held in the vault, converted from the total supply of shares (EUI).
     * @return  uint256  The total assets held in the vault.
     */
    function totalAssets() external view virtual returns (uint256) {
        return _convertToAssets(totalSupply());
    }

    /**
     * @notice  This function allows you to convert a given amount of assets (EUD) into shares (EUI) using the current exchange rate between EUD and EUI.
     * @dev     Converts the specified amount of assets (EUD) into shares (EUI) using the current exchange rate.
     * @param   assets  The amount of assets (EUD) to convert into shares (EUI).
     * @return  uint256  The equivalent amount of shares (EUI) based on the current exchange rate.
     */
    function convertToShares(
        uint256 assets
    ) public view virtual returns (uint256) {
        return _convertToShares(assets);
    }

    /**
     * @notice  This function allows you to convert a given amount of shares (EUI) into assets (EUD) using the current exchange rate between EUI and EUD.
     * @dev     Converts the specified amount of shares (EUI) into assets (EUD) using the current exchange rate.
     * @param   shares  The amount of shares (EUI) to convert into assets (EUD).
     * @return  uint256  The equivalent amount of assets (EUD) based on the current exchange rate.
     */
    function convertToAssets(
        uint256 shares
    ) public view virtual returns (uint256) {
        return _convertToAssets(shares);
    }

    // Deposit
    /**
     * @notice  This function returns the maximum amount of assets (EUD) that can be deposited by the specified receiver.
     * @notice  The maximum deposit amount is equal to the maximum value representable by uint256, allowing for a very large deposit if needed.
     * @dev     Returns the maximum amount of assets (EUD) that can be deposited by the specified receiver.
     * @param   receiver  The address of the receiver for whom the maximum deposit amount is calculated.
     * @return  uint256  The maximum amount of assets (EUD) that can be deposited by the specified receiver, which is equal to the maximum value representable by uint256.
     */
    function maxDeposit(
        address receiver
    ) public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /**
     * @notice  This function allows the user to preview the number of shares (EUI) that would be obtained by depositing the specified amount of assets (EUD).
     * @notice  It does not actually perform the deposit and is used for informational purposes only.
     * @dev     Previews the number of shares (EUI) that would be obtained by depositing the specified amount of assets (EUD).
     * @param   assets  The amount of assets (EUD) to be deposited.
     * @return  uint256  The number of shares (EUI) that would be obtained by depositing the specified amount of assets (EUD).
     */
    function previewDeposit(
        uint256 assets
    ) public view virtual returns (uint256) {
        return _convertToShares(assets);
    }

    /**
     * @notice  This function allows the user to deposit the specified amount of assets (EUD) and receive the corresponding number of shares (EUI) in return.
     * @notice  The maximum allowed deposit amount is limited by the `maxDeposit` function for the specified receiver.
     * @notice  If the deposit amount exceeds the maximum allowed, the function will revert with an error message.
     * @dev     Deposits the specified amount of assets (EUD) to receive the corresponding number of shares (EUI).
     * @param   assets  The amount of assets (EUD) to be deposited.
     * @param   receiver  The address that will receive the shares (EUI).
     * @return  uint256  The number of shares (EUI) received after depositing the specified amount of assets (EUD).
     */
    function deposit(
        uint256 assets,
        address receiver
    ) public virtual returns (uint256) {
        require(
            assets <= maxDeposit(receiver),
            "ERC4626: deposit more than max"
        );
        uint256 shares = _tokenFlipper.flipToEUI(msg.sender, receiver, assets);
        emit Deposit(msg.sender, receiver, assets, shares);
        return shares;
    }

    // Mint
    /**
     * @notice  This function allows the user to determine the maximum amount of assets (EUD) that can be minted as shares (EUI) for the specified receiver.
     * @notice  The maximum mintable amount is equal to the maximum possible value of a uint256 type.
     * @dev     Returns the maximum amount of assets (EUD) that can be minted as shares (EUI) for the specified receiver.
     * @param   receiver  receiver The address for which to calculate the maximum mintable amount of assets (EUD).
     * @return  uint256  The maximum amount of assets (EUD) that can be minted as shares (EUI) for the specified receiver.
     */
    function maxMint(address receiver) public view virtual returns (uint256) {
        return type(uint256).max;
    }

    /**
     * @notice  This function allows the user to preview the amount of assets (EUD) that will be minted for the specified number of shares (EUI).
     * @notice  It performs the conversion from shares to assets using the internal _convertToAssets function.
     * @dev     Previews the amount of assets (EUD) that will be minted for the specified number of shares (EUI).
     * @param   shares  The number of shares (EUI) to preview the minted assets (EUD) for.
     * @return  uint256  The amount of assets (EUD) that will be minted for the specified number of shares (EUI).
     */
    function previewMint(uint256 shares) public view virtual returns (uint256) {
        return _convertToAssets(shares);
    }

    /**
     * @notice  This function allows the user to mint the specified number of shares (EUI) and receive the corresponding amount of assets (EUD).
     * @notice  It performs the conversion from shares to assets using the internal _tokenFlipper.flipToEUD function.
     * @notice  The minted assets will be transferred to the receiver's address.
     * @dev     Pulls the specified number of shares (EUI) and mints the corresponding amount of assets (EUD) to the receiver's address.
     * @param   shares  The number of shares (EUI) to pull.
     * @param   receiver  The address of the receiver who will receive the minted assets (EUD).
     * @return  uint256  The amount of assets (EUD) minted for the specified number of shares (EUI).
     */
    function mint(
        uint256 shares,
        address receiver
    ) public virtual returns (uint256) {
        require(shares <= maxMint(receiver), "ERC4626: mint more than max");
        uint256 assets = _tokenFlipper.flipToEUD(msg.sender, receiver, shares);
        return assets;
    }

    // Withdraw

    /**
     * @notice  This function allows the owner to check the maximum amount of assets (EUD) they can withdraw from the vault based on their EUI balance.
     * @notice  The maximum withdrawal amount is calculated by converting the owner's EUI balance to assets (EUD) using the internal _convertToAssets function.
     * @dev     Returns the maximum amount of assets (EUD) that the specified owner can withdraw based on their EUI balance.
     * @param   owner  The address of the owner whose maximum withdrawal amount is queried.
     * @return  uint256  The maximum amount of assets (EUD) that the owner can withdraw based on their EUI balance.
     */
    function maxWithdraw(address owner) public view virtual returns (uint256) {
        return _convertToAssets(balanceOf(owner));
    }

    /**
     * @notice  This function allows users to preview the amount of shares (EUI) that will be redeemed when they withdraw the specified amount of assets (EUD) from the vault.
     * @notice  The preview amount is calculated by converting the given amount of assets (EUD) to shares (EUI) using the internal _convertToShares function.
     * @dev     Returns the preview amount of shares (EUI) that will be redeemed when the specified amount of assets (EUD) is withdrawn.
     * @param   assets  The amount of assets (EUD) to be withdrawn.
     * @return  uint256  The preview amount of shares (EUI) that will be redeemed for the given amount of assets (EUD).
     */
    function previewWithdraw(
        uint256 assets
    ) public view virtual returns (uint256) {
        return _convertToShares(assets);
    }

    /**
     * @notice  This function allows the owner of the vault to withdraw the specified amount of assets (EUD) from the vault and receive the equivalent amount of shares (EUI) in return.
     * @notice  The function checks if the withdrawal amount is not greater than the maximum allowed for the owner.
     * @notice  If the sender is not the owner, it spends the required allowance to withdraw the shares on behalf of the owner.
     * @notice  Finally, it calls the internal _tokenFlipper's flipToEUD function to perform the share-to-assets conversion and transfers the withdrawn assets (EUD) to the owner.
     * @dev     Allows the owner of the vault to withdraw the specified amount of assets (EUD) from the vault and receive the equivalent amount of shares (EUI) in return.
     * @param   assets  The amount of assets (EUD) to be withdrawn.
     * @param   receiver  The address that will receive the shares (EUI) upon withdrawal.
     * @param   owner  The owner's address, who is the owner of the vault and will receive the withdrawn assets (EUD).
     * @return  uint256  The amount of shares (EUI) redeemed for the given amount of assets (EUD).
     */
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public virtual returns (uint256) {
        require(
            assets <= maxWithdraw(owner),
            "ERC4626: withdraw more than max"
        );

        uint256 sharesAmount = _convertToShares(assets);
        if (owner != msg.sender) {
            _spendAllowance(owner, msg.sender, sharesAmount);
        }
        _tokenFlipper.flipToEUD(owner, receiver, sharesAmount);
        return sharesAmount;
    }

    // Redeem

    /**
     * @notice  This function returns the maximum amount of shares (EUI) that can be redeemed for assets (EUD) by the owner of the vault.
     * @notice  The maximum amount is equal to the balance of shares (EUI) owned by the owner.
     * @dev     Returns the maximum amount of shares (EUI) that can be redeemed for assets (EUD) by the owner of the vault.
     * @param   owner  The owner's address, who is the owner of the vault and can redeem shares (EUI) for assets (EUD).
     * @return  uint256  The maximum amount of shares (EUI) that can be redeemed by the owner.
     */
    function maxRedeem(address owner) public view virtual returns (uint256) {
        return balanceOf(owner);
    }

    /**
     * @notice  This function calculates the amount of assets (EUD) that would be pulled by redeeming the specified amount of shares (EUI).
     * @notice  It converts the shares (EUI) to assets (EUD) using the current conversion rate.
     * @dev     Returns the amount of assets (EUD) that would be pulled by redeeming the specified amount of shares (EUI).
     * @param   shares  The amount of shares (EUI) to be redeemed for assets (EUD).
     * @return  uint256  The amount of assets (EUD) that would be pulled by redeeming the specified amount of shares (EUI).
     */
    function previewRedeem(
        uint256 shares
    ) public view virtual returns (uint256) {
        return _convertToAssets(shares);
    }

    /**
     * @notice  This function redeems the specified amount of shares(EUI) and transfers the shares to the specified receiver.
     * @notice  If the `owner` is different from the `msg.sender`, an allowance is required to spend the assets (EUD) on behalf of the owner.
     * @notice  The amount of assets (EUD) to be redeemed is calculated based on the given number of shares (EUI) using the current conversion rate.
     * @dev     Redeems the specified amount of shares (EUI) and transfers the shares to the specified receiver.
     * @param   shares  The amount of shares (EUI) to be redeemed.
     * @param   receiver  The address that will receive the redeemed shares (EUI).
     * @param   owner  The address of the account that owns the assets (EUD) being redeemed.
     * @return  uint256  The amount of assets (EUD) that have been pulled.
     */
    function redeem(
        uint256 shares,
        address receiver,
        address owner
    ) public virtual returns (uint256) {
        require(shares <= maxRedeem(owner), "ERC4626: redeem more than max");
        uint256 assetsAmount = _convertToAssets(shares);
        if (owner != msg.sender) {
            _spendAllowance(owner, msg.sender, shares);
        }
        _tokenFlipper.flipToEUI(owner, receiver, assetsAmount);
        return assetsAmount;
    }

    /**
     * @notice  This internal function converts the specified amount of assets (EUD) into shares (EUI) using the current conversion rate obtained from the `_tokenFlipper` contract.
     * @notice  The conversion rate is calculated based on the current epoch price of EUD-to-EUI.
     * @notice  The result is the equivalent amount of shares (EUI) for the given amount of assets (EUD).
     * @dev     Converts the specified amount of assets (EUD) into shares (EUI) using the current conversion rate.
     * @param   assets  The amount of assets (EUD) to be converted into shares (EUI).
     * @return  uint256  The equivalent amount of shares (EUI) based on the given amount of assets (EUD).
     */
    function _convertToShares(
        uint256 assets
    ) internal view virtual returns (uint256) {
        return _tokenFlipper.fromEudToEui(assets);
    }

    /**
     * @notice  This internal function converts the specified amount of shares (EUI) into assets (EUD) using the current conversion rate obtained from the `_tokenFlipper` contract.
     * @notice  The conversion rate is calculated based on the previous epoch price of EUD-to-EUI.
     * @notice  The result is the equivalent amount of assets (EUD) for the given amount of shares (EUI).
     * @dev     Converts the specified amount of shares (EUI) into assets (EUD) using the current conversion rate.
     * @param   shares  The amount of shares (EUI) to be converted into assets (EUD).
     * @return  uint256  The equivalent amount of assets (EUD) based on the given amount of shares (EUI).
     */
    function _convertToAssets(
        uint256 shares
    ) internal view virtual returns (uint256) {
        return _tokenFlipper.fromEuiToEud(shares);
    }
}
