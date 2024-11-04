import * as bitcoin from "bitcoinjs-lib";
import { BIP32Factory } from "bip32";
import * as ecc from "tiny-secp256k1";
import * as bip39 from "bip39";

const bip32 = BIP32Factory(ecc);
bitcoin.initEccLib(ecc);

const log = {
  info: (message: string, data?: any) => {
    console.log(`[INFO] ${message}`, data ? data : "");
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
    if (requiredSignatures > totalSigners) {
      throw new Error("Invalid signature requirements");
    }

    this.requiredSignatures = requiredSignatures;
    this.totalSigners = totalSigners;
    this.network = bitcoin.networks.testnet;
    this.derivationPath = config.derivationPath || "m/49'/0'/0'/0";
    this.keyPairs = [];
  }

  public async generateWallet(): Promise<void> {
    for (let i = 0; i < this.totalSigners; i++) {
      const keyPair = await this.generateKeyPair(i);
      this.keyPairs.push(keyPair);
    }

    this.createMultisigAddresses();
  }

  public async generateKeyPair(index: number): Promise<KeyPairInfo> {
    const mnemonic = bip39.generateMnemonic(256);
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const root = bip32.fromSeed(seed, this.network);
    const path = `${this.derivationPath}/${index}`;
    const child = root.derivePath(path);

    return {
      mnemonic,
      path,
      publicKey: Buffer.from(child.publicKey),
      privateKey: child.privateKey ? Buffer.from(child.privateKey) : undefined,
    };
  }

  private createMultisigAddresses(): void {
    const publicKeys = this.keyPairs.map((kp) => kp.publicKey);

    const redeemScript = bitcoin.payments.p2pkh({
      pubkey: publicKeys[0],
      network: this.network,
    }).output;

    if (!redeemScript) {
      throw new Error("Failed to create redeem script");
    }

    this.redeemScript = redeemScript;

    const p2sh = bitcoin.payments.p2sh({
      redeem: {
        output: redeemScript,
        network: this.network,
      },
      network: this.network,
    });

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
    const tx = bitcoin.Transaction.fromHex(txHex);

    const hashType = bitcoin.Transaction.SIGHASH_NONE;

    const signature = tx.hashForSignature(
      inputIndex,
      this.redeemScript!,
      hashType
    );

    tx.setInputScript(
      inputIndex,
      bitcoin.script.compile([Buffer.from(signature), keyPair.publicKey])
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
