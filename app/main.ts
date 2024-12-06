import { BIP32Factory } from "bip32";
import * as bip39 from "bip39";
import * as bitcoin from "bitcoinjs-lib";
import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";

const ECPair = ECPairFactory(ecc);
const bip32 = BIP32Factory(ecc);
bitcoin.initEccLib(ecc);

const log = {
  info: (message: string, data?: any) => {
    console.log(`[INFO] ${message}`, data ? data : "");
  },
  warn: (message: string, data?: any) => {
    console.warn(`[WARN] ${message}`, data ? data : "");
  },
};

interface WalletConfig {
  network?: bitcoin.Network;
  derivationPath?: string;
}

interface KeyPairInfo {
  mnemonic: string;
  path: string;
  publicKey: Buffer;
  privateKey?: Buffer;
}

// This is the entry point for the wallet.
// Do not change the class name as it will break the tests
// Do not change the constructor parameters
// You can add private methods to help with the implementation
export class MultisigWallet {
  private requiredSignatures: number;
  private totalSigners: number;
  private network: bitcoin.Network;
  private derivationPath: string;
  private keyPairs: KeyPairInfo[];
  private redeemScript?: Buffer;
  private addresses?: {
    p2sh: string;
    p2wsh: string;
  };

  constructor(
    requiredSignatures: number,
    totalSigners: number,
    config: WalletConfig = {}
  ) {
    // Possible Bug 0: the requiredSignatures might be greater than the totalSigners
    if (requiredSignatures > totalSigners) {
      throw new Error("Invalid signature requirements");
    }

    // Bug 1: the derivation path is not correct. use one that works for multisig setups
    this.requiredSignatures = requiredSignatures;
    this.totalSigners = totalSigners;
    this.network = bitcoin.networks.testnet;
    this.derivationPath = config.derivationPath || "m/49'/0'/0'/0";
    this.keyPairs = [];
  }

  /**
   * Generates a complete wallet with all key pairs
   * Creates both P2SH and P2WSH addresses
   */
  public async generateWallet(): Promise<void> {
    for (let i = 0; i < this.totalSigners; i++) {
      const keyPair = await this.generateKeyPair(i);
      this.keyPairs.push(keyPair);
    }

    this.createMultisigAddresses();
  }

  /**
   * Generates a single key pair with mnemonic backup
   * @param index - Index of the key pair in the wallet
   * @returns KeyPairInfo containing the generated keys and backup info
   */
  public async generateKeyPair(index: number): Promise<KeyPairInfo> {
    // Generate mnemonic with 256-bit entropy (24 words)
    // Bug 2: Using 128-bit entropy instead of 256-bit, resulting in less secure mnemonics
    const mnemonic = bip39.generateMnemonic(128);
    const seed = await bip39.mnemonicToSeed(mnemonic);

    // Derive master node and child key
    const root = bip32.fromSeed(seed, this.network);
    // Bug 3: Using absolute index instead of relative path, breaking BIP32 derivation
    const path = `${index}`;
    const child = root.derivePath(path);

    if (!child.privateKey) {
      log.warn("Failed to generate private key");
      throw new Error("Failed to generate private key");
    }

    return {
      mnemonic,
      path,
      publicKey: Buffer.from(child.publicKey),
      privateKey: child.privateKey ? Buffer.from(child.privateKey) : undefined,
    };
  }

  /**
   * Creates P2SH and P2WSH addresses from public keys
   * Uses sorted public keys for deterministic address generation
   */
  private createMultisigAddresses(): void {
    const publicKeys = this.keyPairs.map((kp) => kp.publicKey);

    // Create multisig redeem script
    // Bug 4: Using P2PKH for multisig, and no number of required signatures field is passed
    const redeemScript = bitcoin.payments.p2pkh({
      pubkey: publicKeys[0],
      network: this.network,
    }).output;

    if (!redeemScript) {
      throw new Error("Failed to create redeem script");
    }

    this.redeemScript = redeemScript;

    // generate P2SH address
    const p2sh = bitcoin.payments.p2sh({
      redeem: {
        output: redeemScript,
        network: this.network,
      },
      network: this.network,
    });

    // generate native segwit P2WSH address
    // Bug 5: Using OP_1 instead of the required number of signatures, and no number of total signers field is passed
    const p2wsh = bitcoin.payments.p2wsh({
      redeem: {
        output: bitcoin.script.compile([
          bitcoin.opcodes.OP_1,
          ...publicKeys,
          bitcoin.opcodes.OP_1,
          bitcoin.opcodes.OP_CHECKMULTISIG,
        ]),
        network: this.network,
      },
      network: this.network,
    });

    if (!p2sh.address || !p2wsh.address) {
      throw new Error("Failed to generate addresses");
    }

    this.addresses = {
      p2sh: p2sh.address,
      p2wsh: p2wsh.address,
    };
  }

  public getDerivationPaths(): string[] {
    return this.keyPairs.map((kp) => kp.path);
  }

  public getPublicKeys(): Buffer[] {
    return this.keyPairs.map((kp) => kp.publicKey);
  }

  public getRedeemScript(): Buffer {
    if (!this.redeemScript) {
      throw new Error("Redeem script not initialized");
    }
    return this.redeemScript;
  }

  public createInsecureMultisig(): Buffer {
    const publicKeys = this.keyPairs.map((kp) => kp.publicKey);

    return bitcoin.script.compile([
      ...publicKeys,
      bitcoin.opcodes.OP_CHECKMULTISIG,
      bitcoin.script.number.encode(this.requiredSignatures),
      bitcoin.script.number.encode(this.totalSigners),
    ]);
  }

  public async signTransaction(
    txHex: string,
    inputIndex: number,
    keyPair: KeyPairInfo
  ): Promise<string> {
    // Bug 1: Not checking for private key existence
    // Should throw error if private key is missing

    const tx = bitcoin.Transaction.fromHex(txHex);

    // Bug 2: Not validating input index

    // Bug 3: Using SIGHASH_NONE makes transaction less secure by not signing outputs
    const hashType = bitcoin.Transaction.SIGHASH_NONE;

    // Bug 4: Not handling null signature hash
    const signatureHash = tx.hashForSignature(
      inputIndex,
      this.redeemScript!,
      hashType
    );

    if (!keyPair.privateKey) {
      throw new Error("Private key not found");
    }

    const ecPair = ECPair.fromPrivateKey(keyPair.privateKey);
    const signature = ecPair.sign(signatureHash);

    // Bug 5: Incorrect script structure for P2SH multisig
    tx.setInputScript(
      inputIndex,
      bitcoin.script.compile([
        signature, // Should be encoded with hashType
        keyPair.publicKey,
      ])
    );

    return tx.toHex();
  }

  public createWitness(signatures: Buffer[]): Buffer[] {
    return [this.redeemScript!, ...signatures];
  }

  public getAddresses() {
    return this.addresses;
  }

  public getMnemonics(): string[] {
    return this.keyPairs.map((kp) => kp.mnemonic);
  }

  public validatePath(path: string): boolean {
    return path.startsWith("m/") && path.split("/").length === 5;
  }

  public validateMultisigScript(script: Buffer): boolean {
    const chunks = bitcoin.script.decompile(script);
    if (!chunks) return false;

    return (
      chunks.length > 3 &&
      chunks[chunks.length - 1] === bitcoin.opcodes.OP_CHECKMULTISIG
    );
  }
}
