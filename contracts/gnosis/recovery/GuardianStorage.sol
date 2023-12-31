// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";

/**
 * @title GuardianStorage
 * @notice Contract storing the state of wallets related to guardians.
 * This contract only contains basic setters/getters, only enabled modules for a wallet can modify its state
 * @author CANDIDE Labs team
 */
abstract contract GuardianStorage {

    address internal constant SENTINEL_GUARDIANS = address(0x1);

    struct GuardianStorageEntry {
        // the list of guardians
        mapping(address => address) guardians;
        // guardians count
        uint256 count;
        // recovery threshold
        uint256 threshold;
    }

    mapping (address => GuardianStorageEntry) internal entries;

    /**
     * @dev Lets an authorised module add a guardian to a wallet.
     * @param _wallet The target wallet.
     * @param _guardian The guardian to add.
     */
    function _addGuardian(address _wallet, address _guardian) internal {
        require(_guardian != address(0) && _guardian != SENTINEL_GUARDIANS && _guardian != _wallet, "GS: invalid guardian");
        require(!GnosisSafe(payable(_wallet)).isOwner(_guardian), "GS: guardian cannot be an owner");
        GuardianStorageEntry storage entry = entries[_wallet];
        require(entry.guardians[_guardian] == address(0), "GS: duplicate guardian");
        if (entry.count == 0){
            entry.guardians[SENTINEL_GUARDIANS] = _guardian;
            entry.guardians[_guardian] = SENTINEL_GUARDIANS;
        }else{
            entry.guardians[_guardian] = entry.guardians[SENTINEL_GUARDIANS];
            entry.guardians[SENTINEL_GUARDIANS] = _guardian;
        }
        entry.count++;
    }

    function _clearGuardians(address _wallet) internal {
        address[] memory guardians = getGuardians(_wallet);
        uint guardiansLength = guardians.length;
        if (guardiansLength == 0) {
            return;
        }

        address prevGuardian = SENTINEL_GUARDIANS;
        for(uint i = 0; i < guardiansLength; i++) {
            _revokeGuardian(_wallet, prevGuardian, guardians[i]);
        }
    }

    /**
     * @dev Lets an authorised module revoke a guardian from a wallet.
     * @param _wallet The target wallet.
     * @param _prevGuardian Guardian that pointed to the guardian to be removed in the linked list
     * @param _guardian The guardian to revoke.
     */
    function _revokeGuardian(address _wallet, address _prevGuardian, address _guardian) internal {
        GuardianStorageEntry storage entry = entries[_wallet];
        require(_guardian != address(0) && _guardian != SENTINEL_GUARDIANS, "GS: invalid guardian");
        require(entry.guardians[_prevGuardian] == _guardian, "GS: invalid previous guardian");
        entry.guardians[_prevGuardian] = entry.guardians[_guardian];
        entry.guardians[_guardian] = address(0);
        entry.count--;
    }

    /**
     * @dev Allows to update the number of required confirmations by guardians.
     * @param _wallet The target wallet.
     * @param _threshold New threshold.
     */
    function _changeThreshold(address _wallet, uint256 _threshold) internal {
        GuardianStorageEntry storage entry = entries[_wallet];
        // Validate that threshold is smaller than or equal to number of guardians.
        require(_threshold <= entry.count, "GS: threshold must be lower or equal to guardians count");
        if (entry.count == 0){
            require(_threshold == 0, "GS: threshold must be 0");
        }else{
            require(_threshold > 0, "GS: threshold cannot be 0");
        }
        entry.threshold = _threshold;
    }

    /**
     * @dev Checks if an account is a guardian for a wallet.
     * @param _wallet The target wallet.
     * @param _guardian The account.
     * @return true if the account is a guardian for a wallet.
     */
    function isGuardian(address _wallet, address _guardian) public view returns (bool) {
        return _guardian != SENTINEL_GUARDIANS && entries[_wallet].guardians[_guardian] != address(0);
    }

    /**
     * @dev Returns the number of guardians for a wallet.
     * @param _wallet The target wallet.
     * @return the number of guardians.
     */
    function guardiansCount(address _wallet) public view returns (uint256) {
        return entries[_wallet].count;
    }

    /**
     * @dev Retrieves the wallet threshold count.
     * @param _wallet The target wallet.
     * @return uint256 Threshold count.
     */
    function threshold(address _wallet) public view returns (uint256) {
        return entries[_wallet].threshold;
    }

    /**
     * @dev Gets the list of guaridans for a wallet.
     * @param _wallet The target wallet.
     * @return address[] list of guardians.
     */
    function getGuardians(address _wallet) public view returns (address[] memory) {
        GuardianStorageEntry storage entry = entries[_wallet];
        if (entry.count == 0){
            return new address[](0);
        }
        address[] memory array = new address[](entry.count);

        uint256 index = 0;
        address currentGuardian = entry.guardians[SENTINEL_GUARDIANS];
        while (currentGuardian != SENTINEL_GUARDIANS) {
            array[index] = currentGuardian;
            currentGuardian = entry.guardians[currentGuardian];
            index++;
        }
        return array;
    }

}