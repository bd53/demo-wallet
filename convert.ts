import * as ecc from '@bitcoin-js/tiny-secp256k1-asmjs';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory, ECPairInterface } from 'ecpair';
import { Command } from 'commander';
import { Options } from './types';

const ECPair = ECPairFactory(ecc);
const program = new Command();
const opts = program.opts<Options>();

const hexToWIF = (hexKey: string, testnet = false, compressed = true) => {
  if (!hexKey) throw new Error('Missing private key.');
  if (!/^[0-9a-fA-F]{64}$/.test(hexKey)) throw new Error('Invalid private key. Must be a 64-character hex string.');
  const network = testnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
  const pair: ECPairInterface = ECPair.fromPrivateKey(Buffer.from(hexKey, 'hex'), { network, compressed });
  return pair.toWIF();
};

program
  .name('convert')
  .description('Convert Bitcoin private key (hex) to WIF format')
  .requiredOption('-k, --key <hex>', 'Private key in hex format')
  .option('--testnet', 'Use Bitcoin testnet network')
  .option('-u', '--uncompressed', 'Generate uncompressed WIF key')
  .parse(process.argv);

try {
  const wif = hexToWIF(opts.key, opts.testnet, !opts.uncompressed);
  console.log(`WIF (${opts.testnet ? 'testnet' : 'mainnet'}, ${opts.uncompressed ? 'uncompressed' : 'compressed'}): ${wif}`);
} catch (err) {
  console.log((err as Error).message);
  process.exit(1);
}
