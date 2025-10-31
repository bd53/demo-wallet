import * as ecc from '@bitcoin-js/tiny-secp256k1-asmjs';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import { Command } from 'commander';

const program = new Command();
const opts = program.opts();

const Convert = () => {
  try {
    const { key, testnet } = opts;
    if (!key) throw new Error('Missing required --key <hex> argument.');
    if (!/^[0-9a-fA-F]{64}$/.test(key)) throw new Error('Invalid private key. Must be a 64-character hex string.');
    const network = testnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
    const ECPair = ECPairFactory(ecc);
    const pair = ECPair.fromPrivateKey(Buffer.from(key, 'hex'), { network });
    const wif = pair.toWIF();
    console.log(`WIF (${testnet ? 'testnet' : 'mainnet'}): ${wif}`);
  } catch (err) {
    console.log((err as Error).message);
    process.exit(1);
  }
};

program
  .name('convert')
  .description('Convert Bitcoin private key (hex) to WIF format')
  .requiredOption('-k, --key <hex>', 'Private key in hex format')
  .option('--testnet', 'Use Bitcoin testnet network')
  .parse(process.argv);

Convert();
