//SPDX-License-Identifier: GPL
pragma solidity ^0.8.12;

import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./GuardianStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


contract SocialRecoveryModule is GuardianStorage, Ownable {
    using ECDSA for bytes32;
    struct SignatureData {
        address signer;
        bytes signature;
    }

    struct PayGasData {
        address payGasToken;
        uint256 payGasAmount;
    }

    event ResetGuardians(address wallet, uint256 threshold, address[] guardians);
    event DoRecovery(address wallet, address newOwner, address payGasToken, uint256 payGasAmount);
    event AddGuardians(address wallet, address[] guardians, uint256 threshold);
    event AddGuardian(address wallet, address guardian, uint256 threshold);
    event RevokeGuardian(address wallet, address guardian, uint256 threshold);
    event ChangeThreshold(address wallet, uint256 threshold);

    error SimulateDoRecovery(uint256 gasUsed);

    address internal constant SENTINEL_OWNERS = address(0x1);

    address public gasReceiver;

    mapping(address => uint256) public walletsNonces;

    constructor(address _gasReceiver) {
        gasReceiver = _gasReceiver;
    }

    function changeGasReceiver(address _newGasReceiver) external onlyOwner {
        gasReceiver = _newGasReceiver;
    }

    /**
     * @notice Throws if the sender is not the target wallet.
     */
    modifier onlyWallet(address _wallet) {
        require(msg.sender == _wallet, "SM: unauthorized");
        _;
    }

    /**
     * @dev If this module is not enabled.
     * @param _wallet The target wallet.
     */
    modifier onlyEnableModule(address _wallet) {
        // solhint-disable-next-line reason-string
        require(GnosisSafe(payable(_wallet)).isModuleEnabled(address(this)), "SM: this module is not enabled");
        _;
    }

    /// @dev Returns the chain id used by this contract.
    function getChainId() public view returns (uint256) {
        uint256 id;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := chainid()
        }
        return id;
    }

    function encodeRecoveryData(
        address _wallet, 
        address _newOwner, 
        uint256 _nonce, 
        PayGasData calldata _payGasData
    ) public view returns(bytes32) {
        return keccak256(abi.encode(_wallet, _newOwner, _nonce, _payGasData.payGasToken, _payGasData.payGasAmount, getChainId()));
    }

    function _validateGuardianSignature(
        address _wallet,
        bytes32 _signHash,
        address _signer,
        bytes memory _signature
    ) internal view {
        require(isGuardian(_wallet, _signer), "SM: signer not a guardian");
        require(SignatureChecker.isValidSignatureNow(_signer, _signHash, _signature), "SM: invalid guardian signature");
    }

    function _simulateValidateGuardianSignature(
        address _wallet,
        bytes32 _signHash,
        address _signer,
        bytes memory _signature
    ) internal view {
        isGuardian(_wallet, _signer);
        SignatureChecker.isValidSignatureNow(_signer, _signHash, _signature);
    }

    function _checkBalance(address _wallet, PayGasData calldata _payGasData) view internal {
        if (_payGasData.payGasToken == address(0)) {
            require(_wallet.balance >= _payGasData.payGasAmount, "SM: insufficient gas token");
        } else {
            require(IERC20(_payGasData.payGasToken).balanceOf(_wallet) >= _payGasData.payGasAmount, "SM: insufficient gas token");
        }
    }

    function _transferGasToken(address _wallet, PayGasData calldata _payGasData) internal {
        GnosisSafe safe = GnosisSafe(payable(_wallet));
        address to = address(0);
        uint256 value = 0;
        bytes memory data = "";
        if (_payGasData.payGasToken == address(0)) {
            to = gasReceiver;
            value = _payGasData.payGasAmount;
        } else {
            to = _payGasData.payGasToken;
            data = abi.encodeWithSignature("transfer(address,amount)", gasReceiver, _payGasData.payGasAmount);
        }
        (bool success) = safe.execTransactionFromModule(to, value, data, Enum.Operation.Call);
        if (!success) {
            revert("SM: transfer gas token failed");
        }
    }

    function _doRecovery(address _wallet, address _newOwner) internal {
        GnosisSafe safe = GnosisSafe(payable(_wallet));
        address[] memory owners = safe.getOwners();
        bool success = false;
        // remove owners, the first owner is not removed 
        for (uint256 i = (owners.length - 1); i > 0; --i) {
            success = safe.execTransactionFromModule({
                to: _wallet,
                value: 0,
                data: abi.encodeCall(OwnerManager.removeOwner, (owners[i - 1], owners[i], 1)),
                operation: Enum.Operation.Call
            });
            if (!success) {
                revert("SM: owner removal failed");
            }
        }
        if (_newOwner == owners[0]) return;
        // set new owner
        success = safe.execTransactionFromModule({
            to: _wallet,
            value: 0,
            data: abi.encodeCall(OwnerManager.swapOwner, (SENTINEL_OWNERS, owners[0], _newOwner)),
            operation: Enum.Operation.Call
        });
        if (!success) {
            revert("SM: owner replacement failed");
        }
    }

    function resetGuardians(
        address _wallet, 
        uint256 _threshold, 
        address[] calldata _orderedGuardianWallet
    ) external onlyWallet(_wallet) onlyEnableModule(_wallet) {
        require(_threshold > 0, "SM: bad threshold");
        uint orderedGuardianWalletLength = _orderedGuardianWallet.length;
        require(orderedGuardianWalletLength >= _threshold, "SM: bad guardian wallet");

        address lastGuardian = address(0);
        for (uint i = 0; i < orderedGuardianWalletLength; i++) {
            require(_orderedGuardianWallet[i] > lastGuardian, "SM: duplicate signers/invalid ordering");
            lastGuardian = _orderedGuardianWallet[i];
        }
        _clearGuardians(_wallet);
        for(uint i = 0; i < orderedGuardianWalletLength; i++) {
            _addGuardian(_wallet, _orderedGuardianWallet[i]);
        }
        _changeThreshold(_wallet, _threshold);

        emit ResetGuardians(_wallet, _threshold, _orderedGuardianWallet);
    }


    /**
     * Lets multiple guardians confirm the execution of the recovery request.
     * @param _wallet The target wallet.
     * @param _newOwner The new owners' addressess.
     * @param _signatureData The guardians signatures.
     * @param _payGasData Pay for gas
     */
    function doRecovery(
        address _wallet, 
        address _newOwner, 
        SignatureData[] calldata _signatureData, 
        PayGasData calldata _payGasData
    ) external onlyEnableModule(_wallet) {
        _doRecovery(_wallet, _newOwner, _signatureData, _payGasData, false);
    }

    function _doRecovery(
        address _wallet, 
        address _newOwner, 
        SignatureData[] calldata _signatureData, 
        PayGasData calldata _payGasData,
        bool isSimulate
    ) internal {
        // check balance
        _checkBalance(_wallet, _payGasData);
        require(!isGuardian(_wallet, _newOwner), "SM: new owner cannot be guardian");
        bytes32 recoveryHash = encodeRecoveryData(_wallet, _newOwner, walletsNonces[_wallet], _payGasData);
        bytes32 ethSignedMessageHash = recoveryHash.toEthSignedMessageHash();
        uint256 guardiansThreshold = threshold(_wallet);
        require(guardiansThreshold > 0, "SM: empty guardians");
        uint signatureDataLength = _signatureData.length;
        require(signatureDataLength >= guardiansThreshold, "SM: signatures less than threshold");
        address lastGuardian = address(0);
        for(uint i = 0; i < signatureDataLength; i++) {
            SignatureData calldata data = _signatureData[i];
            require(data.signer > lastGuardian, "SM: duplicate signers/invalid ordering");
            if (isSimulate) {
                _simulateValidateGuardianSignature(_wallet, ethSignedMessageHash, data.signer, data.signature);
            } else {
                _validateGuardianSignature(_wallet, ethSignedMessageHash, data.signer, data.signature);
            }
            lastGuardian = data.signer;
        }

        _doRecovery(_wallet, _newOwner);
        _transferGasToken(_wallet, _payGasData);
        walletsNonces[_wallet]++;

        emit DoRecovery(_wallet, _newOwner, _payGasData.payGasToken, _payGasData.payGasAmount);
    }

    function simulateDoRecovery(
        address _wallet, 
        address _newOwner, 
        SignatureData[] calldata _signatureData, 
        PayGasData calldata _payGasData
    ) external {
        uint256 preGas = gasleft();
        require(GnosisSafe(payable(_wallet)).isModuleEnabled(address(this)), "SM: this module is not enabled");
        _doRecovery(_wallet, _newOwner, _signatureData, _payGasData, true);
        revert SimulateDoRecovery(preGas - gasleft() + 21000);
    }

    /**
     * @notice Lets the owner add a guardian for its wallet.
     * @param _wallet The target wallet.
     * @param _guardians The guardian list to add.
     * @param _threshold The new threshold that will be set after addition.
     */
    function addGuardians(
        address _wallet,
        address[] calldata _guardians,
        uint256 _threshold
    ) external onlyWallet(_wallet) onlyEnableModule(_wallet) {
        uint guardiansLength = _guardians.length;
        for (uint i = 0; i < guardiansLength; i++) {
            _addGuardian(_wallet, _guardians[i]);
        }
        _changeThreshold(_wallet, _threshold);

        emit AddGuardians(_wallet, _guardians, _threshold);
    }

    /**
     * @notice Lets the owner add a guardian for its wallet.
     * @param _wallet The target wallet.
     * @param _guardian The guardian to add.
     * @param _threshold The new threshold that will be set after addition.
     */
    function addGuardian(
        address _wallet, 
        address _guardian, 
        uint256 _threshold
    ) external onlyWallet(_wallet) onlyEnableModule(_wallet) {
        _addGuardian(_wallet, _guardian);
        _changeThreshold(_wallet, _threshold);

        emit AddGuardian(_wallet, _guardian, _threshold);
    }

    /**
     * @notice Lets the owner revoke a guardian from its wallet.
     * @param _wallet The target wallet.
     * @param _prevGuardian The previous guardian linking to the guardian in the linked list.
     * @param _guardian The guardian to revoke.
     * @param _threshold The new threshold that will be set after execution of revokation.
     */
    function revokeGuardian(
        address _wallet, 
        address _prevGuardian, 
        address _guardian, 
        uint256 _threshold
    ) external onlyWallet(_wallet) onlyEnableModule(_wallet) {
        require(isGuardian(_wallet, _guardian), "SM: must be existing guardian");
        uint256 _guardiansCount = guardiansCount(_wallet);
        require(_guardiansCount - 1 >= _threshold, "SM: invalid threshold");
        _revokeGuardian(_wallet, _prevGuardian, _guardian);
        _changeThreshold(_wallet, _threshold);

        emit RevokeGuardian(_wallet, _guardian, _threshold);
    }

    /**
     * @notice Lets the owner change the guardian threshold required to initiate a recovery.
     * @param _wallet The target wallet.
     * @param _threshold The new threshold that will be set after execution of revokation.
     */
    function changeThreshold(address _wallet, uint256 _threshold) external onlyWallet(_wallet) onlyEnableModule(_wallet) {
        _changeThreshold(_wallet, _threshold);

        emit ChangeThreshold(_wallet, _threshold);
    }
}