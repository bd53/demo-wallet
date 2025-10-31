import * as ecc from '@bitcoin-js/tiny-secp256k1-asmjs';
import { Keypair } from '@solana/web3.js';
import BIP32Factory from 'bip32';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';
import bs58 from 'bs58';
import { Command } from 'commander';
import * as crypto from 'crypto';
import { ethers } from 'ethers';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import qrcode from 'qrcode';
import { name, version } from './package.json';
import { Addresses, Metadata, Wallet } from './types';

process.umask(0o077);

const bip32 = BIP32Factory(ecc);
const program = new Command();

const WALLET_DIR = process.env.WALLET_DIR || path.join(process.env.HOME || process.env.USERPROFILE || '.', '.demo-wallet');
const WALLET_FILE = path.join(WALLET_DIR, 'wallet.json');
const METADATA_FILE = path.join(WALLET_DIR, 'metadata.json');

const SCRYPT = { N: 16384, r: 8, p: 1 };
const PASSWORD_LENGTH = 8;
const ACCOUNT_MAX = 20;

if (!fs.existsSync(WALLET_DIR)) {
  fs.mkdirSync(WALLET_DIR, { mode: 0o700, recursive: true });
}

const net = (): boolean => {
  const interfaces = os.networkInterfaces();
  return Object.values(interfaces).some(list => list?.some(iface => !iface.internal));
};

const erase = {
  buffer: (b?: Buffer | null) => {
    if (b && Buffer.isBuffer(b)) {
      try {
        b.fill(0);
      } catch (err) {
        console.error('Failed to erase buffer from memory');
      }
    }
  },
  buffers: (...buffers: (Buffer | null | undefined)[]) => {
    buffers.forEach(b => erase.buffer(b));
  }
};

const status = (online: boolean): boolean => {
  if (net() && !online) {
    console.log('Network interfaces are active. Disconnect or use --online to override.');
    return false;
  }
  return true;
};

const validatePassword = (password: string): boolean => {
  if (!password) {
    console.log('Password cannot be empty.');
    return false;
  }
  if (password.length < PASSWORD_LENGTH) {
    console.log(`Password must be at least ${PASSWORD_LENGTH} characters long.`);
    return false;
  }
  const upper = /[A-Z]/.test(password);
  const lower = /[a-z]/.test(password);
  const number = /[0-9]/.test(password);
  const symbol = /[!@#$%^&*(),.?":{}|<>_\-\\[\]\/~`+=;]/.test(password);
  if (!(upper && lower && number && symbol)) {
    console.log('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special symbol.');
    return false;
  }
  return true;
};

const validateAccountIndex = (index: number): boolean => {
  if (index < 0 || index >= ACCOUNT_MAX) {
    console.log(`Account index must be between 0 and ${ACCOUNT_MAX - 1}.`);
    return false;
  }
  return true;
};

const exists = (): boolean => fs.existsSync(WALLET_FILE);

const check = (): boolean => {
  if (!exists()) {
    console.log('No wallet found. Run `generate` first.');
    return false;
  }
  return true;
};

const found = (): boolean => {
  if (exists()) {
    console.log('Wallet already exists. Use `delete` first if you want to create a new one.');
    return false;
  }
  return true;
};

const encryptMnemonic = (mnemonicBuf: Buffer, password: string): Wallet => {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, SCRYPT);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(mnemonicBuf), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { iv: iv.toString('hex'), content: encrypted.toString('hex'), tag: tag.toString('hex'), salt: salt.toString('hex') };
  } finally {
    erase.buffer(key);
  }
};

const decryptMnemonic = (data: Wallet, password: string): Buffer => {
  const salt = Buffer.from(data.salt, 'hex');
  const key = crypto.scryptSync(password, salt, 32, SCRYPT);
  let decrypted: Buffer | null = null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(data.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(data.tag, 'hex'));
    decrypted = Buffer.concat([decipher.update(Buffer.from(data.content, 'hex')), decipher.final()]);
    const mnemonic = Buffer.from(decrypted);
    erase.buffer(decrypted);
    return mnemonic;
  } catch (err) {
    if (decrypted) erase.buffer(decrypted);
    throw new Error('Decryption failed. Invalid password or corrupted wallet file.');
  } finally {
    erase.buffer(key);
  }
};

const deriveAllAddresses = async (mnemonicBuf: Buffer, index: number = 0): Promise<Addresses> => {
  const seed = await bip39.mnemonicToSeed(mnemonicBuf.toString('utf8'));
  try {
    const rootBTC = bip32.fromSeed(seed);
    const keyBTC = rootBTC.derivePath(`m/44'/0'/0'/0/${index}`);
    const p2pkh = bitcoin.payments.p2pkh({ pubkey: keyBTC.publicKey, network: bitcoin.networks.bitcoin }).address!;
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: keyBTC.publicKey, network: bitcoin.networks.bitcoin }).address!;
    const p2sh = bitcoin.payments.p2sh({ redeem: bitcoin.payments.p2wpkh({ pubkey: keyBTC.publicKey, network: bitcoin.networks.bitcoin }) }).address!;
    const hdNode = ethers.HDNodeWallet.fromSeed(seed);
    const ethWallet = hdNode.derivePath(`m/44'/60'/0'/0/${index}`);
    const solPath = `m/44'/501'/${index}'/0'`;
    const solSeed = ethers.HDNodeWallet.fromSeed(seed).derivePath(solPath).privateKey;
    const solKeypair = Keypair.fromSeed(Buffer.from(solSeed.slice(2), 'hex').subarray(0, 32));
    return { bitcoin: { p2pkh, p2wpkh, p2sh }, ethereum: ethWallet.address, solana: solKeypair.publicKey.toBase58() };
  } finally {
    erase.buffer(seed);
  }
};

const deriveMultipleAccounts = async (password: string, count: number = 5): Promise<void> => {
  if (!check()) return;
  if (count < 1 || count > ACCOUNT_MAX) {
    console.log(`You can only derive between 1 and ${ACCOUNT_MAX} accounts.`);
    return;
  }
  let mnemonicBuf: Buffer | null = null;
  try {
    const data = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'));
    mnemonicBuf = decryptMnemonic(data, password);
    console.log(`\nDeriving ${count} account(s)...\n`);
    for (let i = 0; i < count; i++) {
      const addresses: Addresses = await deriveAllAddresses(mnemonicBuf, i);
      console.log('--------------------------------------------------------------');
      console.log(`Account ${i}:`);
      console.log(`  Bitcoin (SegWit): ${addresses.bitcoin.p2wpkh}`);
      console.log(`  Ethereum: ${addresses.ethereum}`);
      console.log(`  Solana: ${addresses.solana}`);
    }
    console.log('--------------------------------------------------------------\n');
    updateMetadata(count);
  } catch (err) {
    console.log((err as Error).message);
  } finally {
    if (mnemonicBuf) erase.buffer(mnemonicBuf);
  }
};

const saveMetadata = (metadata: Metadata) => {
  fs.writeFileSync(METADATA_FILE, JSON.stringify(metadata, null, 2), { mode: 0o600 });
};

const loadMetadata = (): Metadata | null => {
  if (!fs.existsSync(METADATA_FILE)) return null;
  try {
    return JSON.parse(fs.readFileSync(METADATA_FILE, 'utf8'));
  } catch (err) {
    console.error('Failed to load metadata file');
    return null;
  }
};

const updateMetadata = (addressCount?: number) => {
  const metadata = loadMetadata();
  if (metadata) {
    metadata.lastAccessed = new Date().toISOString();
    if (addressCount !== undefined) {
      metadata.addressCount = Math.max(metadata.addressCount, addressCount);
    }
    saveMetadata(metadata);
  }
};

const generateQRCode = async (data: string, label: string): Promise<void> => {
  try {
    await new Promise<void>((resolve, reject) => {
      qrcode.toString(data, { type: 'terminal', small: true }, (err, url) => {
        if (err) reject(err);
        else {
          console.log(`${label}:\n${url}`);
          resolve();
        }
      });
    });
  } catch (e) {
    console.log(`Error generating ${label} QR code:`, (e as Error).message);
  }
};

const generateAddressQRCodes = async (addresses: Addresses): Promise<void> => {
  await generateQRCode(addresses.bitcoin.p2wpkh, 'Bitcoin');
  await generateQRCode(addresses.ethereum, 'Ethereum');
  await generateQRCode(addresses.solana, 'Solana');
};

const displayAddresses = (addresses: Addresses, account: number) => {
  console.log(`\nWallet Addresses (Account ${account}):`);
  console.log('\nBitcoin:');
  console.log(`  Legacy (P2PKH): ${addresses.bitcoin.p2pkh}`);
  console.log(`  Native SegWit: ${addresses.bitcoin.p2wpkh}`);
  console.log(`  Wrapped SegWit: ${addresses.bitcoin.p2sh}`);
  console.log(`\nEthereum: ${addresses.ethereum}`);
  console.log(`\nSolana: ${addresses.solana}\n`);
};

const displayWalletInfo = (metadata: Metadata) => {
  console.log('\nWallet Info:');
  console.log(`   Version: ${metadata.version}`);
  console.log(`   Created: ${new Date(metadata.createdAt).toLocaleString()}`);
  console.log(`   Accounts: ${metadata.addressCount}`);
  if (metadata.lastAccessed) {
    console.log(`   Last Accessed: ${new Date(metadata.lastAccessed).toLocaleString()}`);
  }
};

const generateWallet = async (password: string, count: 12 | 24 = 24): Promise<void> => {
  if (!validatePassword(password) || !found()) return;
  const strength = count === 24 ? 256 : 128;
  const entropy = crypto.randomBytes(strength / 8);
  let mnemonicBuf: Buffer | null = null;
  try {
    const mnemonicStr = bip39.entropyToMnemonic(entropy);
    mnemonicBuf = Buffer.from(mnemonicStr, 'utf8');
    erase.buffer(entropy);
    const encrypted = encryptMnemonic(mnemonicBuf, password);
    fs.writeFileSync(WALLET_FILE, JSON.stringify(encrypted, null, 2), { mode: 0o600 });
    const metadata: Metadata = { version: '2.0', createdAt: new Date().toISOString(), addressCount: 1 };
    saveMetadata(metadata);
    const addresses: Addresses = await deriveAllAddresses(mnemonicBuf);
    console.log('\nWallet generated successfully.\n');
    console.log('Write down your mnemonic phrase and store it securely offline.');
    console.log('Use the `mnemonic --reveal` command to view it (only on an air-gapped machine).\n');
    displayAddresses(addresses, 0);
    console.log(`Wallet stored in: ${WALLET_FILE}`);
    console.log(`Metadata stored in: ${METADATA_FILE}`);
  } finally {
    if (mnemonicBuf) erase.buffer(mnemonicBuf);
  }
};

const showWallet = async (password: string, account: number = 0, qr: boolean = false): Promise<void> => {
  if (!check() || !validateAccountIndex(account)) return;
  let mnemonicBuf: Buffer | null = null;
  try {
    const data = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'));
    mnemonicBuf = decryptMnemonic(data, password);
    const addresses: Addresses = await deriveAllAddresses(mnemonicBuf, account);
    updateMetadata();
    displayAddresses(addresses, account);
    if (qr) {
      await generateAddressQRCodes(addresses);
    }
  } catch (err) {
    console.log((err as Error).message);
  } finally {
    if (mnemonicBuf) erase.buffer(mnemonicBuf);
  }
};

const restoreWallet = async (mnemonic: string, password: string): Promise<void> => {
  if (!validatePassword(password) || !found()) return;
  const trimmed = mnemonic.trim();
  let mnemonicBuf: Buffer | null = null;
  try {
    if (!bip39.validateMnemonic(trimmed)) {
      console.log('Invalid mnemonic phrase.');
      return;
    }
    mnemonicBuf = Buffer.from(trimmed, 'utf8');
    const encrypted = encryptMnemonic(mnemonicBuf, password);
    fs.writeFileSync(WALLET_FILE, JSON.stringify(encrypted, null, 2), { mode: 0o600 });
    const metadata: Metadata = { version: '2.0', createdAt: new Date().toISOString(), addressCount: 1 };
    saveMetadata(metadata);
    const addresses: Addresses = await deriveAllAddresses(mnemonicBuf);
    console.log('\nWallet restored successfully.\n');
    displayAddresses(addresses, 0);
    updateMetadata();
  } finally {
    if (mnemonicBuf) erase.buffer(mnemonicBuf);
  }
};

const verifyWallet = (password: string) => {
  if (!check()) return;
  let mnemonicBuf: Buffer | null = null;
  try {
    const data = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'));
    mnemonicBuf = decryptMnemonic(data, password);
    if (bip39.validateMnemonic(mnemonicBuf.toString('utf8'))) {
      console.log('Wallet file is valid and password is correct.');
      const metadata: Metadata | null = loadMetadata();
      if (metadata) {
        displayWalletInfo(metadata);
      }
    } else {
      console.log('Wallet file appears corrupted.');
    }
  } catch (err) {
    console.log((err as Error).message);
  } finally {
    if (mnemonicBuf) erase.buffer(mnemonicBuf);
  }
};

const deleteWallet = (confirm: boolean) => {
  if (!check()) return;
  if (!confirm) {
    console.log('This will permanently delete your wallet file.');
    console.log('Use --confirm flag to proceed: delete --confirm');
    return;
  }
  try {
    try {
      const stats = fs.statSync(WALLET_FILE);
      const fd = fs.openSync(WALLET_FILE, 'r+');
      const zeros = Buffer.alloc(Math.min(65536, stats.size), 0);
      let written = 0;
      while (written < stats.size) {
        const to = Math.min(zeros.length, stats.size - written);
        fs.writeSync(fd, zeros, 0, to, written);
        written += to;
      }
      fs.closeSync(fd);
    } catch (err) {
      console.error('Failed to securely overwrite wallet file');
    }
    fs.unlinkSync(WALLET_FILE);
    if (fs.existsSync(METADATA_FILE)) {
      fs.unlinkSync(METADATA_FILE);
    }
    console.log('Wallet deleted successfully.');
    console.log('Make sure you have your mnemonic phrase backed up.\n');
  } catch (err) {
    console.log('Failed to delete wallet file:', (err as Error).message);
  }
};

const changePassword = (oldPassword: string, newPassword: string) => {
  if (!check() || !validatePassword(newPassword)) return;
  let mnemonicBuf: Buffer | null = null;
  try {
    const data = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'));
    mnemonicBuf = decryptMnemonic(data, oldPassword);
    const encrypted: Wallet = encryptMnemonic(mnemonicBuf, newPassword);
    fs.writeFileSync(WALLET_FILE, JSON.stringify(encrypted, null, 2), { mode: 0o600 });
    console.log('Password changed successfully.\n');
    updateMetadata();
  } catch (err) {
    console.log((err as Error).message);
  } finally {
    if (mnemonicBuf) erase.buffer(mnemonicBuf);
  }
};

const exportMnemonic = (password: string, reveal: boolean = false) => {
  if (!check()) return;
  let mnemonicBuf: Buffer | null = null;
  try {
    const data = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'));
    mnemonicBuf = decryptMnemonic(data, password);
    if (!reveal) {
      console.log('Mnemonic hidden. Use --reveal to explicitly show it (only on an air-gapped machine).');
      updateMetadata();
      return;
    }
    console.log('\nDo NOT share this phrase.\n');
    console.log(`Your mnemonic phrase:\n${mnemonicBuf.toString('utf8')}\n`);
    console.log('Write this down on paper and store in a secure location.');
    console.log('Never store it digitally or share it with anyone.\n');
    updateMetadata();
  } catch (err) {
    console.log((err as Error).message);
  } finally {
    if (mnemonicBuf) erase.buffer(mnemonicBuf);
  }
};

const exportPrivateKey = async (password: string, chain: 'bitcoin' | 'ethereum' | 'solana', index: number = 0, qr: boolean = false): Promise<void> => {
  if (!check() || !validateAccountIndex(index)) return;
  let mnemonicBuf: Buffer | null = null;
  let seed: Buffer | null = null;
  let privkeyBuf: Buffer | null = null;
  let privkeyDisplayBuf: Buffer | null = null;
  try {
    const data = JSON.parse(fs.readFileSync(WALLET_FILE, 'utf8'));
    mnemonicBuf = decryptMnemonic(data, password);
    seed = await bip39.mnemonicToSeed(mnemonicBuf.toString('utf8'));
    switch (chain) {
      case 'bitcoin': {
        const root = bip32.fromSeed(seed);
        const keyBTC = root.derivePath(`m/44'/0'/0'/0/${index}`);
        if (!keyBTC.privateKey) {
          throw new Error('Failed to derive Bitcoin private key.');
        }
        privkeyBuf = Buffer.from(keyBTC.privateKey);
        privkeyDisplayBuf = Buffer.from(privkeyBuf.toString('hex'), 'utf8');
        break;
      }
      case 'ethereum': {
        const hdNode = ethers.HDNodeWallet.fromSeed(seed);
        const wallet = hdNode.derivePath(`m/44'/60'/0'/0/${index}`);
        privkeyBuf = Buffer.from(wallet.privateKey.slice(2), 'hex');
        privkeyDisplayBuf = Buffer.from(wallet.privateKey, 'utf8');
        break;
      }
      case 'solana': {
        const solPath = `m/44'/501'/${index}'/0'`;
        const solSeed = ethers.HDNodeWallet.fromSeed(seed).derivePath(solPath).privateKey;
        const solKeypair = Keypair.fromSeed(Buffer.from(solSeed.slice(2), 'hex').subarray(0, 32));
        privkeyBuf = Buffer.from(solKeypair.secretKey);
        privkeyDisplayBuf = Buffer.from(bs58.encode(privkeyBuf), 'utf8');
        break;
      }
      default:
        throw new Error('Unsupported chain.');
    }
    console.log('\nDo NOT share this key.\n');
    console.log('Only use it to manage funds by importing it into a trusted online wallet.\n');
    console.log(`${chain.toUpperCase()} Private Key (Account ${index}):\n${privkeyDisplayBuf.toString('utf8')}\n`);
    if (qr) {
      await generateQRCode(privkeyDisplayBuf.toString('utf8'), 'Private Key');
    }
    updateMetadata();
  } catch (err) {
    console.log((err as Error).message);
  } finally {
    erase.buffers(seed, mnemonicBuf, privkeyBuf, privkeyDisplayBuf);
  }
};

program
  .name(name)
  .version(version);

program
  .command('generate')
  .description('Generate a new wallet (offline)')
  .requiredOption(`-p, --password <password>`, `Password for encryption (min ${PASSWORD_LENGTH} chars)`)
  .option('-w, --words <count>', 'Word count: 12 or 24 (default: 24)', '24')
  .option('--online', 'Allow running while network interfaces are active (unsafe)')
  .action(async (opts) => {
    if (!status(!!opts.online)) return;
    const count = parseInt(opts.words);
    if (count !== 12 && count !== 24) {
      console.log('Word count must be 12 or 24');
      return;
    }
    await generateWallet(opts.password, count as 12 | 24);
  });

program
  .command('show')
  .description('Show wallet addresses')
  .requiredOption('-p, --password <password>', 'Password for decryption')
  .option('-a, --account <index>', 'Account index (default: 0)', '0')
  .option('--qr', 'Show QR codes for addresses in terminal')
  .option('--online', 'Allow running while network interfaces are active (unsafe)')
  .action(async (opts) => {
    if (!status(!!opts.online)) return;
    await showWallet(opts.password, parseInt(opts.account), !!opts.qr);
  });

program
  .command('derive')
  .description('Derive multiple account addresses')
  .requiredOption('-p, --password <password>', 'Password for decryption')
  .option(`-c, --count <number>`, `Number of accounts to derive (1-${ACCOUNT_MAX}, default: 5)`, '5')
  .option('--online', 'Allow running while network interfaces are active (unsafe)')
  .action(async (opts) => {
    if (!status(!!opts.online)) return;
    await deriveMultipleAccounts(opts.password, parseInt(opts.count));
  });

program
  .command('mnemonic')
  .description('Export mnemonic phrase (KEEP SECRET). Use --reveal to display.')
  .requiredOption('-p, --password <password>', 'Password for decryption')
  .option('--reveal', 'Explicitly reveal mnemonic in terminal (use only on offline machine)')
  .option('--online', 'Allow running while network interfaces are active (unsafe)')
  .action((opts) => {
    if (!status(!!opts.online)) return;
    exportMnemonic(opts.password, !!opts.reveal);
  });

program
  .command('privatekey')
  .description('Export a wallet private key for a specific chain (use with caution)')
  .requiredOption('-p, --password <password>', 'Password for decryption')
  .requiredOption('-c, --chain <chain>', 'Chain: bitcoin | ethereum | solana')
  .option('-a, --account <index>', 'Account index (default: 0)', '0')
  .option('--qr', 'Show QR code for private key (use offline only)')
  .option('--online', 'Allow running while network interfaces are active (unsafe)')
  .action(async (opts) => {
    if (!status(!!opts.online)) return;
    await exportPrivateKey(opts.password, opts.chain, parseInt(opts.account), !!opts.qr);
  });

program
  .command('restore')
  .description('Restore wallet from mnemonic')
  .requiredOption('-m, --mnemonic <phrase>', 'Your 12 or 24 word phrase')
  .requiredOption(`-p, --password <password>`, `Password for encryption (min ${PASSWORD_LENGTH} chars)`)
  .option('--online', 'Allow running while network interfaces are active (unsafe)')
  .action(async (opts) => {
    if (!status(!!opts.online)) return;
    await restoreWallet(opts.mnemonic, opts.password);
  });

program
  .command('change-password')
  .description('Change wallet password')
  .requiredOption('-o, --old <password>', 'Current password')
  .requiredOption(`-n, --new <password>`, `New password (min ${PASSWORD_LENGTH} chars)`)
  .option('--online', 'Allow running while network interfaces are active (unsafe)')
  .action((opts) => {
    if (!status(!!opts.online)) return;
    changePassword(opts.old, opts.new);
  });

program
  .command('verify')
  .description('Verify wallet file integrity')
  .requiredOption('-p, --password <password>', 'Password for decryption')
  .option('--online', 'Allow running while network interfaces are active (unsafe)')
  .action((opts) => {
    if (!status(!!opts.online)) return;
    verifyWallet(opts.password);
  });

program
  .command('delete')
  .description('Delete wallet file permanently')
  .option('--confirm', 'Confirm deletion')
  .option('--online', 'Allow running while network interfaces are active (unsafe)')
  .action((opts) => {
    if (!status(!!opts.online)) return;
    deleteWallet(!!opts.confirm);
  });

program.parse(process.argv);
