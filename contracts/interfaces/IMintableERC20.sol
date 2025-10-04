// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMintableERC20 {
    /**
     * @dev Mints `amount` tokens to `to`.
     * @param to The recipient address.
     * @param amount The amount to mint.
     */
    function mint(address to, uint256 amount) external;

    /**
     * @dev Burns `amount` tokens from `from`.
     * @param from The address to burn from.
     * @param amount The amount to burn.
     */
    function burn(address from, uint256 amount) external;

    /**
     * @dev Optional: Check if the caller is authorized to mint/burn.
     *      Can be replaced with direct `msg.sender` checks in the bridge.
     */
    function isMinter(address account) external view returns (bool);
}