# Sleek Wallet Contract

## About

Sleek Wallet is an intelligent contract wallet designed for ZetaChain, Ethereum mainnet, and other compatible EVM chains.

The core idea behind Sleek Wallet aligns closely with ZetaChain's vision. We firmly believe that a great wallet should be unobtrusive, allowing users to focus solely on cryptocurrency transactions and NFT activities. This concept is encapsulated in the "Walletless" philosophy, where all the intricacies of conducting token/chain transactions on ZetaChain are abstracted away. Users simply need to initiate a transaction, and ZetaChain takes care of all the gas, transfers, and fees—embodying the essence of "Chainless." Our primary goal is to enhance adoption rates by making complex elements more accessible to the wider public.

## Key Features
- Complete self-custody ensures users have absolute ownership and control of their funds.
- Social login eliminates the need for mnemonic phrases, allowing users to create wallets within seconds and providing a familiar Web2-like user experience, such as using an existing email for wallet creation and login.
- Social recovery of accounts removes concerns about wallet and fund loss, offering users the ability to recover their accounts whenever needed.
- Programmable features offer a wide array of flexible and advanced functionalities, as Sleek Wallet is based on the ERC4337 standard, granting access to unique capabilities:
    - Any EVM-based token can be used to pay for gas.
    - Gas can be paid or sponsored by third-party contracts, significantly reducing dApp usage costs.
    - Automated trading and periodic automatic deductions are possible, making it suitable for various scenarios like monthly subscription bills or dollar-cost averaging.
    - Account abstraction enables bundling multiple transactions into one, saving time and even reducing gas fees—similar to a shopping cart that streamlines multiple transactions into a single purchase.
    - Expense and transaction restrictions: Users can set limits on the amount authorized accounts can withdraw from the wallet or establish daily transaction quotas.
    - Compatibility with GnosisSafe's extensible plugins.

## Usage
```shell
npm i
npx hardhat run scripts/deploy.js
```

## Acknowledgments
* [eth-infinitism/account-abstraction](link-to-repo)
* [Gnosis Safe Contracts](https://github.com/safe-global/safe-contracts)
* [Stackup Bundler](https://github.com/stackup-wallet/stackup-bundler)