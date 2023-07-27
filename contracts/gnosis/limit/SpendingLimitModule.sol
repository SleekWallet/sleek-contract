//SPDX-License-Identifier: GPL
pragma solidity ^0.8.7;

import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./ISpendingLimit.sol";

interface Guardian {
    function isGuardian(address _wallet, address _guardian) external view returns (bool);
    function threshold(address _wallet) external view returns (uint256);
}

interface LimitRouterCheck {
    function whetherLimitRouter() external returns(bool);
}

contract SpendingLimitModule is ISpendingLimit, ReentrancyGuard {
    using ECDSA for bytes32;
    address public immutable socialRecoveryModule;
    address public immutable multiSendCallOnly;

    // ERC20 function
    bytes4 public constant TRANSFER = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 public constant APPROVE = bytes4(keccak256("approve(address,uint256)"));
    bytes4 public constant INCREASE_ALLOWANCE = bytes4(keccak256("increaseAllowance(address,uint256)"));

    // MultiSendCallOnly function
    bytes4 public constant MULTI_SEND = bytes4(keccak256("multiSend(bytes)"));

    // Safe -> Token -> Limit
    mapping(address => mapping (address => Limit)) public tokenSpendingLimit;
    // Wallet -> Nonce
    mapping(address => uint256) public walletNonce;

    struct Limit {
        uint256 amount;
        uint256 spent;
        uint16 resetTimeMin; // Maximum reset time span is 65k minutes
        uint32 lastResetMin;
    }

    struct SpendingLimitSetData {
        address token;
        uint256 allowanceAmount;
        uint16 resetTimeMin;
        uint32 resetBaseMin;
    }

    event SetSpendingLimit(address _wallet, address _token, uint256 _allowanceAmount, uint16 _resetTimeMin, uint32 _resetBaseMin);
    event ResetSpendingLimit(address _wallet, address _token);
    event DeleteSpendingLimit(address _wallet, address _token);

    error SpendingLimitCheck();

    constructor(address _socialRecoveryModule, address _multiSendCallOnly) {
        socialRecoveryModule = _socialRecoveryModule;
        multiSendCallOnly = _multiSendCallOnly;
    }

    /**
     * @dev If this module is not enabled.
     * @param _wallet The target wallet.
     */
    modifier onlyEnableRecoveryModule(address _wallet) {
        // solhint-disable-next-line reason-string
        require(GnosisSafe(payable(_wallet)).isModuleEnabled(address(socialRecoveryModule)), "SM: socialRecoveryModule module is not enabled");
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

    /**
     * @notice Throws if the sender is not the target wallet.
     */
    modifier onlyWallet(address _wallet) {
        require(msg.sender == _wallet, "SM: unauthorized");
        _;
    }

    function _checkLimit(
        address _wallet,
        address _to,
        uint256 _value,
        bytes calldata _data,
        Enum.Operation _operation
    ) internal {
        if (_operation == Enum.Operation.DelegateCall) {
            require(_to == multiSendCallOnly, "SM: not allow delegateCall");
            bytes4 sig = bytes4(_data[:4]);
            require(sig == MULTI_SEND, "SM: only call multiSend");
            _decodeMultiSendCallAndCheckLimit(_wallet, _data);
        } else {
            uint256 dataLength = _data.length;
            require(_to != _wallet || dataLength == 0, "SM: self calls are not allowed");
            require(_to != socialRecoveryModule || dataLength == 0, "SM: socialRecoveryModule calls are not allowed");
            if (dataLength > 0) {
                // check token limit
                _checkTokenLimit(_wallet, _to, _data);
            }

            if (_value > 0) {
                // check eth limit
                _checkEthLimit(_wallet, _value);
            }
        }
    }

    function simulateLimitTransaction(
        address _wallet,
        address _to,
        uint256 _value,
        bytes calldata _data,
        Enum.Operation _operation
    ) public {
        if (!LimitRouterCheck(_wallet).whetherLimitRouter()) {
            return;
        }
        _checkLimit(_wallet, _to, _value, _data, _operation);
        revert SpendingLimitCheck();
    }

    function executeLimitTransaction(
        address _wallet,
        address _to,
        uint256 _value,
        bytes calldata _data,
        Enum.Operation _operation
    ) public onlyEnableModule(_wallet) onlyWallet(_wallet) nonReentrant {
        _checkLimit(_wallet, _to, _value, _data, _operation);

        GnosisSafe safe = GnosisSafe(payable(_wallet));
        (bool success, bytes memory ret) = safe.execTransactionFromModuleReturnData({
            to: _to,
            value: _value,
            data: _data,
            operation: _operation
        });
        if (!success) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function _decodeMultiSendCallAndCheckLimit(address _wallet, bytes calldata _data) internal {
        uint256 transactionsLength = _data.length;
        bytes memory transactions = _data;
        // We offset 36 byte (32byte data length, 4 byte function sign)
        uint256 i = 0x24;
        // For dynamic variables, the first byte is the offset
        // Let's skip him
        assembly {
            let offset := mload(add(transactions, i))
            i := add(i, offset)
            i := add(i, 0x20)
        }
        for (; i < transactionsLength;) {
            uint8 operation;
            address to;
            uint256 value;
            uint256 dataLength;
            // bytes memory data;
            assembly {
                // First byte of the data is the operation.
                // We shift by 248 bits (256 - 8 [operation byte]) it right since mload will always load 32 bytes (a word).
                // This will also zero out unused data.
                operation := shr(0xf8, mload(add(transactions, i)))
                // We offset the load address by 1 byte (operation byte)
                // We shift it right by 96 bits (256 - 160 [20 address bytes]) to right-align the data and zero out unused data.
                to := shr(0x60, mload(add(transactions, add(i, 0x01))))
                // We offset the load address by 21 byte (operation byte + 20 address bytes)
                value := mload(add(transactions, add(i, 0x15)))
                // We offset the load address by 53 byte (operation byte + 20 address bytes + 32 value bytes)
                dataLength := mload(add(transactions, add(i, 0x35)))
                // We offset 85 byte (operation byte + 20 address bytes + 32 value bytes + 32 data length bytes)
                i := add(i, 0x55)
            }
            require(operation == 0, "SM: multiSendCallOnly");
            if (value > 0) {
                _checkEthLimit(_wallet, value);
            }
            if (dataLength > 0) {
                require(to != _wallet, "SM: self calls are not allowed");
                require(to != socialRecoveryModule, "SM: socialRecoveryModule calls are not allowed");
                // Offset 32 bytes forward (not including the original array length)
                bytes calldata data = _data[i - 32 : i + dataLength - 32];
                i += dataLength;
                _checkTokenLimit(_wallet, to, data);
            }
        }
    }

    function _checkEthLimit(address _wallet, uint256 _value) internal {
        // check eth limit
        Limit memory ethLimit = getLimit(_wallet, address(0));
        if (ethLimit.amount > 0) {
            uint256 newSpent = ethLimit.spent + _value;
            require(newSpent > ethLimit.spent && newSpent <= ethLimit.amount, "SM: newSpent > limit.spent && newSpent <= limit.amount");
            ethLimit.spent = newSpent;
            _updateLimit(_wallet, address(0), ethLimit);
        }
    }

    function _checkTokenLimit(address _wallet, address _to, bytes calldata _data) internal {
        Limit memory tokenLimit = getLimit(_wallet, _to);
        if (tokenLimit.amount > 0) {
            // decode calldata
            bytes4 sig = bytes4(_data[:4]);
            if (sig == TRANSFER || sig == INCREASE_ALLOWANCE) {
                // get transfer amount or increaseAllowance addedValue
                (, uint256 amount) = abi.decode(_data[4:], (address, uint256));
                uint256 newSpent = tokenLimit.spent + amount;
                require(newSpent > tokenLimit.spent && newSpent <= tokenLimit.amount, "SM: newSpent > limit.spent && newSpent <= limit.amount");
                tokenLimit.spent = newSpent;
                _updateLimit(_wallet, address(0), tokenLimit);
            } else if (sig == APPROVE) {
                // get spender and approve amount
                (address spender, uint256 amount) = abi.decode(_data[4:], (address, uint256));
                // get allowance
                uint256 preAllowance = IERC20(_to).allowance(_wallet, spender);
                uint256 newSpent = 0;
                if (amount >= preAllowance) {
                    newSpent = tokenLimit.spent + amount - preAllowance;
                    require(newSpent > tokenLimit.spent && newSpent <= tokenLimit.amount, "SM: newSpent > limit.spent && newSpent <= limit.amount");
                    tokenLimit.spent = newSpent;
                    _updateLimit(_wallet, address(0), tokenLimit);
                }
            }
        }
    }

    function _setSpendingLimit(
        address _wallet, 
        address _token, 
        uint256 _allowanceAmount, 
        uint16 _resetTimeMin, 
        uint32 _resetBaseMin
    ) internal {
        Limit memory limit = getLimit(_wallet, _token); 
        // Divide by 60 to get current time in minutes
        // solium-disable-next-line security/no-block-members
        uint32 currentMin = uint32(block.timestamp / 60);
        if (_resetBaseMin > 0) {
            require(_resetBaseMin <= currentMin, "resetBaseMin <= currentMin");
            limit.lastResetMin = currentMin - ((currentMin - _resetBaseMin) % _resetTimeMin);
        } else if (limit.lastResetMin == 0) {
            limit.lastResetMin = currentMin;
        }
        limit.resetTimeMin = _resetTimeMin;
        limit.amount = _allowanceAmount;
        _updateLimit(_wallet, _token, limit);
        
        emit SetSpendingLimit(_wallet, _token, _allowanceAmount, _resetTimeMin, _resetBaseMin);
    }

    function batchSetSpendingLimit(
        address _wallet, 
        SpendingLimitSetData[] calldata spendingLimitBatchSetData,
        SignatureData[] calldata _signatureData
    ) public onlyEnableRecoveryModule(_wallet) onlyEnableModule(_wallet) {
        
        bytes32 recoveryHash = encodeBatchSpendingLimitData(_wallet, spendingLimitBatchSetData);
        _validateGuardiansSignature(_wallet, recoveryHash, _signatureData);
        uint dataLength = spendingLimitBatchSetData.length;
        for (uint i = 0; i < dataLength; i++) {
            _setSpendingLimit(
                _wallet, 
                spendingLimitBatchSetData[i].token, 
                spendingLimitBatchSetData[i].allowanceAmount, 
                spendingLimitBatchSetData[i].resetTimeMin,
                spendingLimitBatchSetData[i].resetBaseMin
            );
        }
    }

    function setSpendingLimit(
        address _wallet, 
        SpendingLimitSetData calldata spendingLimitSetData, 
        SignatureData[] calldata _signatureData
    ) public onlyEnableRecoveryModule(_wallet) onlyEnableModule(_wallet) {

        bytes32 recoveryHash = encodeSpendingLimitData(_wallet, spendingLimitSetData);
        _validateGuardiansSignature(_wallet, recoveryHash, _signatureData);
        _setSpendingLimit(_wallet, spendingLimitSetData.token, spendingLimitSetData.allowanceAmount, spendingLimitSetData.resetTimeMin, spendingLimitSetData.resetBaseMin);
    }

    function resetSpendingLimit(address _wallet, address _token, SignatureData[] calldata _signatureData) public onlyEnableRecoveryModule(_wallet) onlyEnableModule(_wallet) {
        bytes32 dataHash = encodeResetSpendingLimitData(_wallet, _token);
        _validateGuardiansSignature(_wallet, dataHash, _signatureData);
        Limit memory limit = getLimit(_wallet, _token);
        limit.spent = 0;

        _updateLimit(_wallet, _token, limit);
        
        emit ResetSpendingLimit(_wallet, _token);
    }

    function deleteSpendingLimit(address _wallet, address _token, SignatureData[] calldata _signatureData) public onlyEnableRecoveryModule(_wallet) onlyEnableModule(_wallet) {
        bytes32 dataHash = encodeDeleteSpendingLimitData(_wallet, _token);
        _validateGuardiansSignature(_wallet, dataHash, _signatureData);
        Limit memory limit = getLimit(_wallet, _token);
        limit.spent = 0;
        limit.amount = 0;
        limit.resetTimeMin = 0;
        limit.lastResetMin = 0;

        _updateLimit(_wallet, _token, limit);
        
        emit DeleteSpendingLimit(_wallet, _token);
    }

    function validateGuardiansSignature(address _wallet, bytes32 _dataHash, SignatureData[] calldata _signatureData ) external onlyWallet(_wallet) {
        _validateGuardiansSignature(_wallet, _dataHash, _signatureData);
    }

    function _validateGuardiansSignature(address _wallet, bytes32 _dataHash, SignatureData[] calldata _signatureData) internal {
        // check guardian threshold
        uint256 guardiansThreshold = Guardian(socialRecoveryModule).threshold(_wallet);
        require(guardiansThreshold > 0, "SM: empty guardians");
        uint256 signatureDataLength = _signatureData.length;
        require(signatureDataLength >= guardiansThreshold, "SM: signatures less than threshold");

        bytes32 ethSignedMessageHash = _dataHash.toEthSignedMessageHash();
        address lastGuardian = address(0);
        for(uint i = 0; i < signatureDataLength; i++) {
            SignatureData calldata data = _signatureData[i];
            require(data.signer > lastGuardian, "SM: duplicate signers/invalid ordering");
            _validateGuardianSignature(_wallet, ethSignedMessageHash, data.signer, data.signature);
            lastGuardian = data.signer;
        }
        _updateNonce(_wallet);
    }

    function _updateNonce(address _wallet) private {
        walletNonce[_wallet] += 1;
    }

    function getLimit(address _wallet, address _token) private view returns (Limit memory limit) {
        limit = tokenSpendingLimit[_wallet][_token];
        // solium-disable-next-line security/no-block-members
        uint32 currentMin = uint32(block.timestamp / 60);
        // Check if we should reset the time. We do this on load to minimize storage read/ writes
        if (limit.resetTimeMin > 0 && limit.lastResetMin <= currentMin - limit.resetTimeMin) {
            limit.spent = 0;
            // Resets happen in regular intervals and `lastResetMin` should be aligned to that
            limit.lastResetMin = currentMin - ((currentMin - limit.lastResetMin) % limit.resetTimeMin);
        }
        return limit;
    }

    function _updateLimit(address _wallet, address _token, Limit memory limit) private {
        tokenSpendingLimit[_wallet][_token] = limit;
    }

    function _validateGuardianSignature(
        address _wallet,
        bytes32 _signHash,
        address _signer,
        bytes memory _signature
    ) internal view {
        require(Guardian(socialRecoveryModule).isGuardian(_wallet, _signer), "SM: signer not a guardian");
        require(SignatureChecker.isValidSignatureNow(_signer, _signHash, _signature), "SM: invalid guardian signature");
    }

    function encodeExecuteWhithGuardianData(
        address _wallet,
        address _to,
        uint256 _value,
        bytes memory _data,
        Enum.Operation _operation
    ) public view returns(bytes32) {
        return keccak256(abi.encode(_wallet, _to, _value, _data, _operation, getChainId(), walletNonce[_wallet]));
    }

    function encodeDeleteSpendingLimitData(
        address _wallet, 
        address _token
    ) public view returns(bytes32) {
        return keccak256(abi.encode(_wallet, _token, getChainId(), walletNonce[_wallet], 0x01));
    }

    function encodeResetSpendingLimitData(
        address _wallet, 
        address _token
    ) public view returns(bytes32) {
        return keccak256(abi.encode(_wallet, _token, getChainId(), walletNonce[_wallet], 0x02));
    }

    function encodeBatchSpendingLimitData(
        address _wallet, 
        SpendingLimitSetData[] calldata spendingLimitBatchSetData
    ) public view returns(bytes32) {
        return keccak256(abi.encode(_wallet, spendingLimitBatchSetData, getChainId(), walletNonce[_wallet]));
    }


    function encodeSpendingLimitData(
        address _wallet, 
        SpendingLimitSetData calldata spendingLimitSetData
    ) public view returns(bytes32) {
        return keccak256(abi.encode(_wallet, spendingLimitSetData, getChainId(), walletNonce[_wallet]));
    }

    /// @dev Returns the chain id used by this contract.
    function getChainId() public view returns (uint256) {
        uint256 id;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            id := chainid()
        }
        return id;
    }
}