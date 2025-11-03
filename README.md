# demo-wallet

A minimal self-hosted crypto wallet for offline key management and cold storage.

[![](https://img.shields.io/badge/License-MIT-blue?logo=opensource)](./LICENSE)
[![](https://img.shields.io/github/contributors/bd53/demo-wallet?logo=github)](https://github.com/bd53/demo-wallet/graphs/contributors)
[![](https://img.shields.io/github/last-commit/bd53/demo-wallet?logo=github)](https://github.com/bd53/demo-wallet/commits/main)

For additional legal notices, refer to [NOTICE.md](./NOTICE.md).

## Documentation

https://bd53.github.io/demo-wallet/

## Features

- Bitcoin legacy _(P2PKH)_, native SegWit _(bech32/P2WPKH)_, and wrapped SegWit _(P2SH-P2WPKH)_ addresses.
- Ethereum EVM-compatible addresses.
- Solana native addresses.
- AES-256-GCM encryption with unique random IVs and salts per wallet.
- BIP39 mnemonic phrases _(12 or 24 words)_.
- Scrypt key derivation _(`N=16384`, `r=8`, `p=1`, 32-byte key)_.
- Deterministic account derivation _(BIP44, 20 accounts per wallet + configurable)_.
- Secure zeroization of sensitive data _(mnemonics, keys, seeds)_.
- Optional QR output _(wallet viewing, mnemonics, shares, private keys)_.
- Bitcoin private key conversion _(hex -> WIF, compressed or uncompressed)_.
- Wallet metadata tracking _(creation date, last accessed, derived accounts)_.
- Seedless wallet generation using SSS _(Shamir Secret Sharing)_ with configurable threshold and total shares.
- Individual AES-256-GCM encryption for each Shamir share.
- Wallet restore using mnemonic phrases or threshold number of encrypted Shamir shares.
