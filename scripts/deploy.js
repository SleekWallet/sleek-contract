// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.

// npx hardhat run scripts/deploy.js

const hre = require("hardhat");

/* These contracts are deployed on zetachain by sleek */
const gnosisSafeSingletonAddr = "0xaD8122f0Ca3043837fdB69eFd99f4554E64E64D4"
const gnosisSafeProxyFactoryAddr = "0x119E7FCA724d9fEB5D7C9769fe938908ccCbc969"
const entryPointAddr = "0x4358E78412a6e2a57Fa050F199C022De25830B4A"
const ellipticCurveAddr = "0x5030D0a5b920998eEE65172eA855e2f664E4D684"
const multiSendCallOnlyAddr = "0x632887eb6126D79ED035DA09c59c697b451901E1"
/* These contracts are deployed on zetachain by sleek */

async function main () {

  const [owner] = await hre.ethers.getSigners();

  // deploy SocialRecoveryModule
  const SocialRecoveryModule = await hre.ethers.getContractFactory("SocialRecoveryModule")
  const socialRecoveryModule = await SocialRecoveryModule.deploy(owner.address)
  await socialRecoveryModule.deployed()
  console.log("SocialRecoveryModule deployed to:", socialRecoveryModule.address)

  const SpendingLimitModule = await hre.ethers.getContractFactory("SpendingLimitModule")
  const spendingLimitModule = await SpendingLimitModule.deploy(socialRecoveryModule.address, multiSendCallOnlyAddr)
  await spendingLimitModule.deployed()
  console.log("SpendingLimitModule deployed to:", spendingLimitModule.address)

  // deploy 4337Manager
  const EIP4337Manager = await hre.ethers.getContractFactory("EIP4337Manager")
  const eIP4337Manager = await EIP4337Manager.deploy(entryPointAddr, socialRecoveryModule.address, spendingLimitModule.address, ellipticCurveAddr)
  await eIP4337Manager.deployed()
  console.log("EIP4337Manager deployed to:", eIP4337Manager.address)

  // deploy GnosisSafeAccountFactory
  const GnosisSafeAccountFactory = await hre.ethers.getContractFactory("GnosisSafeAccountFactory")
  const gnosisSafeAccountFactory = await GnosisSafeAccountFactory.deploy(gnosisSafeProxyFactoryAddr, gnosisSafeSingletonAddr, eIP4337Manager.address)
  await gnosisSafeAccountFactory.deployed()
  console.log("GnosisSafeAccountFactory deployed to:", gnosisSafeAccountFactory.address)

}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
