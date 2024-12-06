# Multisig Wallet Workshop

## Overview

This workshop will guide you through the creation of a multisig wallet using Python and the Bitcoin utilities library. A multisig wallet requires multiple signatures to authorize a transaction, enhancing security.

## Prerequisites

Before you begin, ensure you have the following installed:

- [Bun (recommended)](https://bun.sh/docs/installation) or [Node.js](https://nodejs.org/en/download/)
- [Git](https://git-scm.com/downloads)

## Setup

## Quick Start

1. Clone the repository:

```bash
git clone <repository-url>
cd <repository-name>
```

2. Install dependencies:

```bash
bun install
```

or

```bash
npm install
```

## Passing the First Stage

The entry point to the workshop is the [main.ts](app/main.ts) file. To pass the first stage, you need to create an empty commit and push it to the remote repository.

```bash
git commit --allow-empty -m "Pass the first stage"
git push
```

## Passing Other Stages

Study the code in the [main.ts](app/main.ts) file and fix the bugs. There are comments in the code that will guide you to the solution. When you are done, create a new commit and push it to the remote repository.

```bash
git commit -am "Pass the stage"
git push
```

You should see the logs for your changes in your terminal.

You can also run the program manually to test your changes.

```bash
chmod +x ./your_program.sh

./your_program.sh
```

## Goals

- Fix the bugs in the program

1. fix validation of the requiredSignatures and totalSigners
2. fix the derivation path
3. fix the creation of the multisig addresses
4. fix the redeem script
5. fix the transaction signing

For every bug you fix, you should see the logs for your changes in your terminal when you push to the remote repository or run the program manually.
