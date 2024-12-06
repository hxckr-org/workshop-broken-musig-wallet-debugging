# Fix The Broken Multi-Signature Wallet

Fix the simple multisig wallet implementation. Multi-signature (multisig) wallets are a critical security feature in Bitcoin, requiring multiple parties to authorize a transaction. In this challenge, you'll examine and improve a Bitcoin multisig wallet implementation.

## Learning Objectives

- Implement secure Bitcoin multi-signature addresses
- Master P2SH and P2WSH address types
- Apply BIP standards for HD wallet derivation
- Create secure transaction signing mechanisms

## Bitcoin Multi-Signature Fundamentals

A multi-signature address requires M-of-N signatures to spend funds, where:

- M = number of required signatures
- N = total number of possible signers

Example: In a 2-of-3 setup, any 2 out of 3 designated parties must sign

## Address Types

### P2SH (Pay to Script Hash)

- Legacy segwit multisig format starting with '2' on testnet
- Embeds script hash in address

### P2WSH (Pay to Witness Script Hash)

- Modern SegWit multisig format starting with 'tb1' on testnet and 'bc1' on mainnet
- Separates script data into witness

## Important BIP Standards

- BIP32: Hierarchical Deterministic Wallets
- BIP39: Mnemonic seed phrases
- BIP48: Multi-signature derivation paths

## Setup Steps

1. Review the code in the `app` directory

2. In the root directory of the project, run the tests:

```bash
chmod +x ./your_program.sh

./your_program.sh
```

3. Fix the implementation until all tests pass

## Resources

### Bitcoin Script

- [Script Wiki](https://en.bitcoin.it/wiki/Script)
- [Bitcoin Opcode Reference](https://en.bitcoin.it/wiki/Script#Opcodes)

### BIP Standards

- [BIP48 Specification](https://github.com/bitcoin/bips/blob/master/bip-0048.mediawiki)
- [BIP32 HD Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

### Security Best Practices

- [Bitcoin Multisig Security](https://en.bitcoin.it/wiki/Multisignature)
- [Hardware Wallet Integration](https://en.bitcoin.it/wiki/Hardware_wallet)
