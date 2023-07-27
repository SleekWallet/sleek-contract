//SPDX-License-Identifier: GPL
pragma solidity ^0.8.7;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/base/Executor.sol";
import "@gnosis.pm/safe-contracts/contracts/examples/libraries/GnosisSafeStorage.sol";
import "./EIP4337Fallback.sol";
import "../interfaces/IAccount.sol";
import "../interfaces/IEntryPoint.sol";
import "../utils/Exec.sol";
import "./limit/ISpendingLimit.sol";

    using ECDSA for bytes32;


interface Guardian {
    function isGuardian(address _wallet, address _guardian) external view returns (bool);
    function threshold(address _wallet) external view returns (uint256);
}

interface IEllipticCurve {
    function validateSignature(
        bytes32 message,
        bytes memory signature,
        bytes memory publicKey
    ) external pure returns (bool);
}

/**
 * Main EIP4337 module.
 * Called (through the fallback module) using "delegate" from the GnosisSafe as an "IAccount",
 * so must implement validateUserOp
 * holds an immutable reference to the EntryPoint
 * Inherits GnosisSafe so that it can reference the memory storage
 */
contract EIP4337Manager is IAccount, GnosisSafeStorage, Executor {

    address public immutable eip4337Fallback;
    address public immutable entryPoint;
    address public immutable recoveryModule;
    address public immutable spendingLimitModule;
    address public immutable ellipticCurve;
    bool public isDisableSchedule;
    bool public spendingLimit;
    bytes public ellipticCurvePublicKey;
    mapping(uint256 => bool) public usedNonce;

    // return value in case of signature failure, with no time-range.
    // equivalent to _packValidationData(true,0,0);
    uint256 constant internal SIG_VALIDATION_FAILED = 1;

    address internal constant SENTINEL_MODULES = address(0x1);

     // If the value of nonce is greater than this value, the transaction is considered as a scheduled transaction
    uint256 internal constant NONCE_LINE = 0x3FFFFFFFFFFFFFFF;

    uint256 internal constant ELLIPTIC_CURVE_SIGNATURE_LENGTH = 64;

    bytes4 internal constant DELAY_TRANSACTION  =  bytes4(keccak256("executeScheduledTransaction(uint256,uint256,address,uint256,bytes,uint8)"));
    bytes4 internal constant NORMAL_TRANSACTION =  bytes4(keccak256("executeAndRevert(address,uint256,bytes,uint8)"));
    bytes4 internal constant SUPER_TRANSACTION  =  bytes4(keccak256("executeWhithGuardianAndRevert(address,uint256,bytes,uint8,(address,bytes)[])"));
    bytes4 internal constant CURVE_TRANSACTION =  bytes4(keccak256("executeWithCurveAndRevert(address,uint256,bytes,uint8)"));

    constructor(address anEntryPoint, address anRecoveryModule, address anSpendingLimitModule, address anEllipticCurve) {
        entryPoint = anEntryPoint;
        eip4337Fallback = address(new EIP4337Fallback(address(this)));
        recoveryModule = anRecoveryModule;
        spendingLimitModule = anSpendingLimitModule;
        ellipticCurve = anEllipticCurve;
    }

    function whetherLimitRouter() public view returns(bool) {
        GnosisSafe safe = GnosisSafe(payable(address(this)));
        return spendingLimit
                && safe.isModuleEnabled(spendingLimitModule) 
                && safe.isModuleEnabled(recoveryModule) 
                && Guardian(recoveryModule).threshold(address(this)) > 0;
    }

    /**
     * delegate-called (using execFromModule) through the fallback, so "real" msg.sender is attached as last 20 bytes
     */
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
    external override returns (uint256 validationData) {
        address msgSender = address(bytes20(msg.data[msg.data.length - 20 :]));
        require(msgSender == entryPoint, "account: not from entrypoint");

        GnosisSafe pThis = GnosisSafe(payable(address(this)));
        bytes4 sig = bytes4(userOp.callData[:4]);
        if (userOp.signature.length == ELLIPTIC_CURVE_SIGNATURE_LENGTH) {
            bytes32 hash = sha256(abi.encode(userOpHash));
            bool isValidated = IEllipticCurve(ellipticCurve).validateSignature(hash, userOp.signature, ellipticCurvePublicKey);
            if (!isValidated) {
                validationData = SIG_VALIDATION_FAILED;
            }
        } else {
            require(sig != CURVE_TRANSACTION, "account: invalid method|sig");
            bytes32 hash = userOpHash.toEthSignedMessageHash();
            address recovered = hash.recover(userOp.signature);
            require(threshold == 1, "account: only threshold 1");
            if (!pThis.isOwner(recovered)) {
                validationData = SIG_VALIDATION_FAILED;
            }
        }

        if (whetherLimitRouter()) {
            require(sig == DELAY_TRANSACTION || sig == NORMAL_TRANSACTION || sig == SUPER_TRANSACTION || sig == CURVE_TRANSACTION, "account: invalid method");
        }

        if (userOp.initCode.length == 0) {
            if (userOp.nonce > NONCE_LINE) {
                require(!isDisableSchedule, "account: schedule module disabled");
                require(usedNonce[userOp.nonce] == false, "account: invalid nonce");
                usedNonce[userOp.nonce] = true;
                require(
                    sig == DELAY_TRANSACTION, 
                    "exec: illegal call"
                );
            } else {
                require(uint256(nonce) == userOp.nonce, "account: invalid nonce");
                nonce = bytes32(uint256(nonce) + 1);
            }
        }

        if (missingAccountFunds > 0) {
            //Note: MAY pay more than the minimum, to deposit for future transactions
            (bool success,) = payable(msgSender).call{value : missingAccountFunds}("");
            (success);
            //ignore failure (its EntryPoint's job to verify, not account.)
        }
    }

       /**
     * scheduled transaction
     */
    function executeScheduledTransaction(
        uint256 startTimestamp,
        uint256 endTimestamp,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external {
        require(block.timestamp >= startTimestamp, "exec: not start");
        require(block.timestamp < endTimestamp, "exec: already end");
        address msgSender = address(bytes20(msg.data[msg.data.length - 20 :]));
        require(msgSender == entryPoint, "account: not from entrypoint");
        require(msg.sender == eip4337Fallback, "account: not from EIP4337Fallback");
        require(!isDisableSchedule, "account: schedule module disabled");

        if (whetherLimitRouter()) {
            ISpendingLimit(spendingLimitModule).executeLimitTransaction(address(this), to, value, data, operation);
            return;
        }

        bool success = execute(
            to,
            value,
            data,
            operation,
            type(uint256).max
        );

        bytes memory returnData = Exec.getReturnData(type(uint256).max);
        // Revert with the actual reason string
        // Adopted from: https://github.com/Uniswap/v3-periphery/blob/464a8a49611272f7349c970e0fadb7ec1d3c1086/contracts/base/Multicall.sol#L16-L23
        if (!success) {
            if (returnData.length < 68) revert();
            assembly {
                returnData := add(returnData, 0x04)
            }
            revert(abi.decode(returnData, (string)));
        }
    }

    function setEllipticCurve(bytes memory anEllipticCurvePublicKey) external {
        address _msgSender = address(bytes20(msg.data[msg.data.length - 20 :]));
        require(_msgSender == address(this), "account: not auth");
        require(msg.sender == eip4337Fallback, "account: not from EIP4337Fallback");
        ellipticCurvePublicKey = anEllipticCurvePublicKey;
    }

    function flipScheduleModule() external {
        address _msgSender = address(bytes20(msg.data[msg.data.length - 20 :]));
        require(_msgSender == address(this), "account: not auth");
        require(msg.sender == eip4337Fallback, "account: not from EIP4337Fallback");
        isDisableSchedule = !isDisableSchedule;
    }

    function enableSpendingLimit() external {
        address _msgSender = address(bytes20(msg.data[msg.data.length - 20 :]));
        require(_msgSender == address(this), "account: not auth");
        require(msg.sender == eip4337Fallback, "account: not from EIP4337Fallback");
        spendingLimit = true;

        GnosisSafe safe = GnosisSafe(payable(address(this)));
        if (!safe.isModuleEnabled(spendingLimitModule)) {
            safe.enableModule(spendingLimitModule);
        }
    }

    function disableSpendingLimit() external {
        address _msgSender = address(bytes20(msg.data[msg.data.length - 20 :]));
        require(_msgSender == address(this), "account: not auth");
        require(msg.sender == eip4337Fallback, "account: not from EIP4337Fallback");
        spendingLimit = false;
    }

    function executeWhithGuardianAndRevert(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        ISpendingLimit.SignatureData[] calldata signatureData
    ) external {
        address msgSender = address(bytes20(msg.data[msg.data.length - 20 :]));
        require(msgSender == entryPoint, "account: not from entrypoint");
        require(msg.sender == eip4337Fallback, "account: not from EIP4337Fallback");

        bytes32 dataHash = ISpendingLimit(spendingLimitModule).encodeExecuteWhithGuardianData(address(this), to, value, data, operation);
        ISpendingLimit(spendingLimitModule).validateGuardiansSignature(address(this), dataHash, signatureData);

        bool success = execute(
            to,
            value,
            data,
            operation,
            type(uint256).max
        );

        bytes memory returnData = Exec.getReturnData(type(uint256).max);
        // Revert with the actual reason string
        // Adopted from: https://github.com/Uniswap/v3-periphery/blob/464a8a49611272f7349c970e0fadb7ec1d3c1086/contracts/base/Multicall.sol#L16-L23
        if (!success) {
            if (returnData.length < 68) revert();
            assembly {
                returnData := add(returnData, 0x04)
            }
            revert(abi.decode(returnData, (string)));
        }
    }

    function executeWithCurveAndRevert(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external {
        address msgSender = address(bytes20(msg.data[msg.data.length - 20 :]));
        require(msgSender == entryPoint, "account: not from entrypoint");
        require(msg.sender == eip4337Fallback, "account: not from EIP4337Fallback");

        bool success = execute(
            to,
            value,
            data,
            operation,
            type(uint256).max
        );

        bytes memory returnData = Exec.getReturnData(type(uint256).max);
        // Revert with the actual reason string
        // Adopted from: https://github.com/Uniswap/v3-periphery/blob/464a8a49611272f7349c970e0fadb7ec1d3c1086/contracts/base/Multicall.sol#L16-L23
        if (!success) {
            if (returnData.length < 68) revert();
            assembly {
                returnData := add(returnData, 0x04)
            }
            revert(abi.decode(returnData, (string)));
        }
    }

    /**
     * Execute a call but also revert if the execution fails.
     * The default behavior of the Safe is to not revert if the call fails,
     * which is challenging for integrating with ERC4337 because then the
     * EntryPoint wouldn't know to emit the UserOperationRevertReason event,
     * which the frontend/client uses to capture the reason for the failure.
     */
    function executeAndRevert(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external {
        address msgSender = address(bytes20(msg.data[msg.data.length - 20 :]));
        require(msgSender == entryPoint, "account: not from entrypoint");
        require(msg.sender == eip4337Fallback, "account: not from EIP4337Fallback");

        if (whetherLimitRouter()) {
            ISpendingLimit(spendingLimitModule).executeLimitTransaction(address(this), to, value, data, operation);
            return;
        }

        bool success = execute(
            to,
            value,
            data,
            operation,
            type(uint256).max
        );

        bytes memory returnData = Exec.getReturnData(type(uint256).max);
        // Revert with the actual reason string
        // Adopted from: https://github.com/Uniswap/v3-periphery/blob/464a8a49611272f7349c970e0fadb7ec1d3c1086/contracts/base/Multicall.sol#L16-L23
        if (!success) {
            if (returnData.length < 68) revert();
            assembly {
                returnData := add(returnData, 0x04)
            }
            revert(abi.decode(returnData, (string)));
        }
    }


    /**
     * set up a safe as EIP-4337 enabled.
     * called from the GnosisSafeAccountFactory during construction time
     * - enable 3 modules (this module, fallback and the entrypoint)
     * - this method is called with delegateCall, so the module (usually itself) is passed as parameter, and "this" is the safe itself
     */
    function setup4337Modules(
        EIP4337Manager manager //the manager (this contract)
    ) external {
        GnosisSafe safe = GnosisSafe(payable(address(this)));
        require(!safe.isModuleEnabled(manager.entryPoint()), "setup4337Modules: entrypoint already enabled");
        require(!safe.isModuleEnabled(manager.eip4337Fallback()), "setup4337Modules: eip4337Fallback already enabled");
        require(!safe.isModuleEnabled(manager.recoveryModule()), "setup4337Modules: recoveryModule already enabled");
        require(!safe.isModuleEnabled(manager.spendingLimitModule()), "setup4337Modules: spendingLimitModule already enabled");
        safe.enableModule(manager.entryPoint());
        safe.enableModule(manager.eip4337Fallback());
        safe.enableModule(manager.recoveryModule());
        safe.enableModule(manager.spendingLimitModule());
    }

    /**
     * replace EIP4337 module, to support a new EntryPoint.
     * must be called using execTransaction and Enum.Operation.DelegateCall
     * @param prevModule returned by getCurrentEIP4337Manager
     * @param oldManager the old EIP4337 manager to remove, returned by getCurrentEIP4337Manager
     * @param newManager the new EIP4337Manager, usually with a new EntryPoint
     */
    function replaceEIP4337Manager(address prevModule, EIP4337Manager oldManager, EIP4337Manager newManager) public {
        GnosisSafe pThis = GnosisSafe(payable(address(this)));
        address oldFallback = oldManager.eip4337Fallback();
        require(pThis.isModuleEnabled(oldFallback), "replaceEIP4337Manager: oldManager is not active");
        pThis.disableModule(oldFallback, oldManager.entryPoint());
        pThis.disableModule(prevModule, oldFallback);

        address eip4337fallback = newManager.eip4337Fallback();

        pThis.enableModule(newManager.entryPoint());
        pThis.enableModule(eip4337fallback);
        pThis.enableModule(newManager.recoveryModule());
        pThis.enableModule(newManager.spendingLimitModule());
        pThis.setFallbackHandler(eip4337fallback);

        validateEip4337(pThis, newManager);
    }

    /**
     * Validate this gnosisSafe is callable through the EntryPoint.
     * the test is might be incomplete: we check that we reach our validateUserOp and fail on signature.
     *  we don't test full transaction
     */
    function validateEip4337(GnosisSafe safe, EIP4337Manager manager) public {

        // this prevents mistaken replaceEIP4337Manager to disable the module completely.
        // minimal signature that pass "recover"
        bytes memory sig = new bytes(65);
        sig[64] = bytes1(uint8(27));
        sig[2] = bytes1(uint8(1));
        sig[35] = bytes1(uint8(1));
        UserOperation memory userOp = UserOperation(address(safe), uint256(nonce), "", "", 0, 1000000, 0, 0, 0, "", sig);
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;
        IEntryPoint _entryPoint = IEntryPoint(payable(manager.entryPoint()));
        try _entryPoint.handleOps(userOps, payable(msg.sender)) {
            revert("validateEip4337: handleOps must fail");
        } catch (bytes memory error) {
            if (keccak256(error) != keccak256(abi.encodeWithSignature("FailedOp(uint256,string)", 0, "AA24 signature error"))) {
                revert(string(error));
            }
        }
    }
    /**
     * enumerate modules, and find the currently active EIP4337 manager (and previous module)
     * @return prev prev module, needed by replaceEIP4337Manager
     * @return manager the current active EIP4337Manager
     */
    function getCurrentEIP4337Manager(GnosisSafe safe) public view returns (address prev, address manager) {
        prev = address(SENTINEL_MODULES);
        (address[] memory modules,) = safe.getModulesPaginated(SENTINEL_MODULES, 100);
        for (uint i = 0; i < modules.length; i++) {
            address module = modules[i];
            try EIP4337Fallback(module).eip4337manager() returns (address _manager) {
                return (prev, _manager);
            }
            // solhint-disable-next-line no-empty-blocks
            catch {}
            prev = module;
        }
        return (address(0), address(0));
    }
}
