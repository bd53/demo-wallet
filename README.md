# demo-wallet

A minimal self-hosted crypto wallet for offline key management and cold storage.

For additional legal notices, refer to [NOTICE.md](./NOTICE.md).

## Features

- Bitcoin legacy _(p2pkh)_, native segwit _(bech32)_, and wrapped segwit addresses.
- Ethereum standard EVM-compatible addresses.
- Native Solana addresses.
- AES-256-GCM encryption with unique salts.
- BIP39 mnemonic phrases _(12 or 24 words)_.
- Scrypt key derivation _(32,768 iterations)_.
- Unlimited account derivation _(BIP44)_.
- Bitcoin private key conversion _(hex -> WIF)_.

## Installation

### Build

1. Download the LTS version of [Node.js](https://nodejs.org/en).
2. Open a command-line terminal (e.g., Terminal, Command Prompt).
3. Enter `node --version` to verify the installation.
4. Run `npm install -g pnpm` to globally install the package manager [pnpm](https://pnpm.io).
5. Download or clone the repository with `git clone https://github.com/bd53/demo-wallet`.
6. Install all dependencies with `pnpm i`.
7. Build the resource with `pnpm build`.

## Usage

### Commands

Just about every command shares two common flags:

- `-p, --password <password>`
- `--online`

If the system has an active network and `--online` is **not** provided, the command will **not** work.

### Generate Wallet

```bash
# Generate with 24-word mnemonic
ts-node index.ts generate -p "password"

# Generate with 12-word mnemonic
ts-node index.ts generate -p "password" -w 12
```

| Flag/Alias                  | Option   | Type    | Description                                  |
| --------------------------- | -------- | ------- | -------------------------------------------- |
| `-p, --password <password>` | Required | string  | Password for encryption (min. 8 characters). |
| `-w, --words <count>`       | Optional | string  | Mnemonic word count (12/24, default = `24`). |
| `--online`                  | Optional | boolean | Allows running online.                       |

**Note: Generated addresses are fully functional and can receive and hold funds indefinitely.**

If you want to access or transfer funds from an address, export the private key _(or mnemonic phrase)_ and import it into a trusted, compatible online wallet.

This project is for educational purposes only and is intended to demonstrate a minimal example of offline key management and cold storage, this is **not** financial advice.

### View Your Addresses

```bash
# Show default account (account 0)
ts-node index.ts show -p "password"

# Show specific account (account 5)
ts-node index.ts show -p "password" -a 5

# Show default account + QR codes
ts-node index.ts show -p "password" --qr

# Show specific account (account 3) + QR codes
ts-node index.ts show -p "password" -a 3 --qr
```

| Flag/Alias                  | Option   | Type    | Description                         |
| --------------------------- | -------- | ------- | ----------------------------------- |
| `-p, --password <password>` | Required | string  | Wallet decryption password.         |
| `-a, --account <index>`     | Optional | number  | Account to show (default = `0`).    |
| `--qr`                      | Optional | boolean | Displays QR codes for each address. |
| `--online`                  | Optional | boolean | Allows running online.              |

### Derive Multiple Accounts

Generate multiple receiving addresses from the same seed:

```bash
# Derive first 5 accounts
ts-node index.ts derive -p "password" -c 5

# Derive up to 20 accounts
ts-node index.ts derive -p "password" -c 20
```

| Flag/Alias                  | Option   | Type    | Description                               |
| --------------------------- | -------- | ------- | ----------------------------------------- |
| `-p, --password <password>` | Required | string  | Wallet decryption password.               |
| `-c, --count <number>`      | Optional | number  | Accounts to derive (1–20, default = `5`). |
| `--online`                  | Optional | boolean | Allows running online.                    |

### Export Mnemonic

```bash
ts-node index.ts mnemonic -p "password" --reveal
```

| Flag/Alias                  | Option   | Type    | Description                 |
| --------------------------- | -------- | ------- | --------------------------- |
| `-p, --password <password>` | Required | string  | Wallet decryption password. |
| `--reveal`                  | Optional | boolean | Displays mnemonic.          |
| `--online`                  | Optional | boolean | Allows running online.      |

### Export Private Key

```bash
# Export private key for a specific chain
ts-node index.ts privatekey -p "password" -c ethereum

# Export private key for (account 1) + QR code
ts-node index.ts privatekey -p "password" -c solana -a 1 --qr
```

| Flag/Alias                  | Option   | Type    | Description                                     |
| --------------------------- | -------- | ------- | ----------------------------------------------- |
| `-p, --password <password>` | Required | string  | Wallet decryption password.                     |
| `-c, --chain <chain>`       | Required | string  | Blockchain: `bitcoin`, `ethereum`, or `solana`. |
| `-a, --account <index>`     | Optional | number  | Account to export key from (default = `0`).     |
| `--qr`                      | Optional | boolean | Displays private key as a QR code.              |
| `--online`                  | Optional | boolean | Allows running online.                          |

**Note: Some tools expect WIF format. Convert hex -> WIF offline if needed.**

This command technically defeats the purpose of everything. It's provided only for users who insist on accessing or managing their funds from another device, which is **not** recommended for secure cold storage setups.

### Convert Private Key (hex -> WIF)

```bash
# Convert a Bitcoin private key (mainnet)
ts-node convert.ts -k <hex-private-key>

# Convert a Bitcoin private key (testnet)
ts-node convert.ts -k <hex-private-key> --testnet
```

| Flag/Alias        | Option   | Type    | Description                                     |
| ----------------- | -------- | ------- | ----------------------------------------------- |
| `-k, --key <hex>` | Required | string  | Private key in hex format (64 characters).      |
| `--testnet`       | Optional | boolean | Converts key for testnet (default = `mainnet`). |

### Restore Wallet

If your local wallet file has been deleted or lost, you can use a mnemonic phrase to recover your wallet:

```bash
ts-node index.ts restore \
  -m "witch collapse practice feed shame open despair creek road again ice least" \
  -p "new-password"
```

| Flag/Alias                  | Option   | Type    | Description                                      |
| --------------------------- | -------- | ------- | ------------------------------------------------ |
| `-m, --mnemonic <phrase>`   | Required | string  | Full 12/24-word recovery phrase.                 |
| `-p, --password <password>` | Required | string  | New password for encryption (min. 8 characters). |
| `--online`                  | Optional | boolean | Allows running online.                           |

### Change Password

```bash
ts-node index.ts change-password \
  -o "current-password" \
  -n "new-password"
```

| Flag/Alias             | Option   | Type    | Description                                      |
| ---------------------- | -------- | ------- | ------------------------------------------------ |
| `-o, --old <password>` | Required | string  | Current password.                                |
| `-n, --new <password>` | Required | string  | New password for encryption (min. 8 characters). |
| `--online`             | Optional | boolean | Allows running online.                           |

### Verify Wallet Integrity

```bash
ts-node index.ts verify -p "password"
```

| Flag/Alias                  | Option   | Type    | Description                 |
| --------------------------- | -------- | ------- | --------------------------- |
| `-p, --password <password>` | Required | string  | Wallet decryption password. |
| `--online`                  | Optional | boolean | Allows running online.      |

### Delete Wallet

This permanently deletes your wallet file. Ensure you have your mnemonic backed up:

```bash
ts-node index.ts delete --confirm
```

| Flag/Alias  | Option   | Type    | Description                  |
| ----------- | -------- | ------- | ---------------------------- |
| `--confirm` | Required | boolean | Required to actually delete. |
| `--online`  | Optional | boolean | Allows running online.       |

## HD Wallet Structure (BIP44)

This wallet uses the BIP44 standard for hierarchical deterministic wallets:

```
m / purpose' / coin_type' / account' / change / address_index

Bitcoin: m/44'/0'/account'/0/0
Ethereum: m/44'/60'/account'/0/0
Solana: m/44'/501'/account'/0'
```

- Account 0: Your primary wallet
- Account 1+: Additional wallets from the same seed

All accounts are cryptographically derived from your mnemonic.

## Security

- Run only on a clean, offline machine. Disconnect all network interfaces before using.
- Use a live OS _(e.g., Debian, Arch, or Fedora)_ for true air-gap generation.
- Never store your mnemonic digitally. Use metal or paper backups only.
- Avoid screenshots, cloud backups, or password managers that sync online.

This wallet protects against:

- Remote attacks _(air-gapped)_
- Malware _(offline generation)_
- Phishing _(no online interaction)_
- Exchange hacks _(self-custody)_
- Service shutdowns _(no dependencies)_

This wallet does **not** protect against:

- Physical theft of the device _(use encryption + secure location)_
- $5 wrench attack _(use secure locations + don't talk about crypto)_
- Compromised system during generation _(use clean/live OS)_
- Poor mnemonic storage _(engrave in metal + use multiple locations)_

## Additional Resources

- [BIP39 Mnemonic](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP44 Multi-Account Hierarchy](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
