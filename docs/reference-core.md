<p align="center">
  <img src="blocknet.png" width="128" height="128" alt="Blocknet">
</p>

<h1 align="center">Blocknet</h1>

<p align="center">
  A client for running Blocknet cores.<br>
  <img src="https://img.shields.io/badge/blocknet-Mainnet-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/blocknet-Testnet-ff00aa?style=flat-square&labelColor=000">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/license-BSD--3--Clause-aaff00?style=flat-square&labelColor=000">
  <img src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-aaff00?style=flat-square&labelColor=000">
</p>

## Interactive Command Reference

These commands are available inside `blocknet attach`, which opens an interactive shell connected to a running [Blocknet core](https://github.com/blocknetprivacy/core). The core is the daemon that runs the blockchain node, wallet, miner, and peer-to-peer network. Every command below is sent to the core over its HTTP API — the shell is a thin client that formats the results for your terminal.

Closing the shell (`quit` or Ctrl-C) does not stop the core. See [reference-blocknet.md](reference-blocknet.md) for the commands that manage core lifecycle (start, stop, install, upgrade, etc.).

### Command Summary

#### Wallet
| Command | Description |
|---|---|
| `load` | Load a wallet file into the core |
| `balance` | Show wallet balance |
| `address` | Show receiving address |
| `send <addr> <amt> [memo]` | Send funds with optional memo |
| `sign` | Sign a message with your spend key |
| `verify` | Verify a signed message against an address |
| `history` | Show transaction history |
| `outputs` | Show wallet outputs (spent and unspent) |
| `seed` | Show wallet recovery seed (careful!) |
| `import` | Create wallet file from seed or spend/view keys |
| `viewkeys` | Create a view-only wallet file |
| `lock` | Lock wallet |
| `unlock` | Unlock wallet |
| `save` | Save wallet to disk |
| `sync` | Rescan blocks for outputs |

#### Daemon
| Command | Description |
|---|---|
| `status` | Show node and wallet status |
| `peers` | List connected peers |
| `banned` | List banned peers |
| `export-peer` | Export peer addresses to peer.txt |
| `mining` | Manage mining |
| `certify` | Check chain integrity (difficulty + timestamps) |
| `purge` | Delete all blockchain data (cannot be undone) |
| `version` | Print version |
| `about` | About this software |
| `license` | Show license |
| `quit` | Exit (saves automatically) |
| `help <command>` | Show detailed help for a command |

---

### Detailed Command Reference

---

#### `load`

Loads a wallet file into the running core. See the [Wallet Management](reference-wallet.md) guide for the full story on loading, backups, auto-load, and recovery.

**Use this when:**
you just started the core and need to open your wallet.

**Example:**
```
> load
  Found wallet files:
  1) /Users/you/.config/bnt/wallets/main.wallet.dat
  2) /Users/you/blocknet-mainnet.wallet.dat
  3) Enter a custom path
  4) Create a new wallet

  Choose: 1
  Password: ********

  Wallet loaded
  Address: 9PNo...

  Save wallet path to config for auto-load? [y/N]: y
  Saved. Next start will use this wallet automatically.
```

**Notes:**
- Can only be called once per core session — [restart the core](troubleshooting.md#cant-switch-wallets) to switch wallets.
- Saving to config makes future starts [auto-load](reference-wallet.md#auto-loading-on-startup) this wallet via the `--wallet` flag. See the [Configuration Reference](reference-config.md#paths) for the `wallet_file` field.

---

#### `balance`

**Aliases:** `bal`, `b`

Shows your spendable coins, pending coins, and total.

**Use this when:**
you want to know how much you can spend right now.

**Example:**
```
> bal

# Balance
  spendable:  12.5 BNT
  confirming: 1 BNT
  total:      13.5 BNT
  outputs:    9 unspent, 5 spent
```

---

#### `address`

**Aliases:** `addr`, `a`

Shows your receive address to share with someone paying you.

**Use this when:**
someone asks where to send you coins.

**Example:**
```
> addr

# Address

  9PNoFCqUa7K8e5JfV2Hs3TBt7kMzRGkPxJ4xVmn5cFb...

  Get a short name like @name or $name at https://blocknet.id
```

---

#### `send`

```
send <address> <amount> [memo|hex:<memo_hex>]
```

Sends BNT to another wallet, optionally with a note.

**Use this when:**
you need to pay someone now.

**Example:**
```
> send @rock 100 "hello"

# Send

  Send 100 BNT to @rock?
  Fee:     0.00015 BNT
  Change:  12.49985 BNT
  Memo:    hello
  Confirm [y/N]: y
  Sent: 9f0b...
  Explorer: https://explorer.blocknetcrypto.com/tx/9f0b...
```

**Notes:**
- You can send whole numbers or fractions (example: `1` or `1.25` BNT).
- Memos with spaces are supported.
- Short names can be used as `@name` or `$name`.
- `send all` sends your entire spendable balance.
- Pasting a `blocknet://` URI or `bntpay.com/` link auto-parses as a send.

---

#### `sign`

Signs a message so you can prove wallet ownership.

**Use this when:**
a service asks you to prove this wallet is yours.

**Example:**
```
> sign
  Enter the text to sign, press ENTER when you're done.

> prove wallet ownership

# Sign
  8f2d... (signature hex)
```

**Notes:**
- View-only wallets cannot sign.
- Message should be short (up to about 1,000 characters).

---

#### `verify`

Checks if a signature really came from an address.

**Use this when:**
you received a signed message and need to trust it.

**Example:**
```
> verify
  Enter the address:
> 9PNo...
  Enter the message that was signed:
> prove wallet ownership
  Enter the signature (hex):
> 8f2d...

# Signature is VALID
```

**Notes:**
- Signature must be pasted exactly as produced by `sign`.

---

#### `history`

**Aliases:** `hist`, `h`

Shows incoming transactions, oldest to newest.

**Use this when:**
you need to review recent wallet activity.

**Example:**
```
> hist

# History
  block 14200 IN  72.325 BNT  coinbase  c7f2e1d3...
  block 14205 IN  1.25 BNT    regular   a1b2c3d4...
```

---

#### `outputs`

**Aliases:** `outs`, `out`

```
outputs [spent|unspent|pending] [index]
outputs tx <txid>
outputs tx <txid>:<index>
```

Shows outputs your wallet owns, with status and drill-down details.

**Use this when:**
you want to inspect spendable/spent/pending outputs.

**Example:**
```
> outputs unspent

# Outputs
  #1  unspent     regular  conf: 217
      amount: 7.5 BNT
      block:  13990  tx: c7f2e1d3...:1
  #2  unspent     coinbase conf: 7
      amount: 72.325 BNT
      block:  14200  tx: a1b2c3d4...:0
```

```
> outputs 1

# Outputs
  #1
    status:       unspent
    amount:       7.5 BNT
    type:         regular
    confirmations:217
    block:        13990
    tx output:    c7f2e1d3...:1
    one-time pub: ...
    commitment:   ...
```

**Notes:**
- Use filters: `spent`, `unspent`, `pending`.
- Use an index to see one output's details (example: `outputs 3`).
- `outputs tx <txid>` shows all owned outputs in that tx.

---

#### `seed`

Shows your 12-word recovery seed after warning prompts. See [Viewing your recovery seed](reference-wallet.md#viewing-your-recovery-seed) for important security guidance.

**Use this when:**
you are backing up wallet recovery words.

**Example:**
```
> seed

# Seed
  WARNING: Your recovery seed controls all funds.
  Anyone with this seed can steal your coins.
  Never share it. Never enter it online.

  Show recovery seed? [y/N]: y
  Password: ********

   1.abandon    2.ability    3.able       4.about
   5.above      6.absent     7.absorb     8.abstract
   9.absurd    10.abuse     11.access    12.accident

  Write these words down and store them safely.
  Recover with: import (option 1: recovery seed)
```

**Notes:**
- Anyone with this seed can spend your funds.

---

#### `import`

Creates a new wallet file from a seed phrase. See [Recovery from seed](reference-wallet.md#recovery-from-seed) for the full recovery workflow.

**Use this when:**
you need to load an existing wallet into this node.

**Example:**
```
> import

# Import
  1) 12-word recovery seed
  2) spend-key/view-key (requires direct core access)

  Choose [1/2]: 1
  Input the 12 words of your seed:
> abandon ability able about above absent absorb abstract absurd abuse access accident
  Input the name of this wallet:
> restored.wallet.dat
  Password: ********

  name: restored.wallet.dat
  address: 9PNo...
```

---

#### `viewkeys`

Creates a wallet file that can watch funds but cannot spend.

**Use this when:**
you want watch-only access on another machine.

**Notes:**
- Requires core API endpoint (not yet available in attach mode).

---

#### `prove`

```
prove <txid>
```

Generates a proof that you sent a transaction.

**Use this when:**
someone needs proof of payment.

**Notes:**
- Requires core API endpoint (not yet available in attach mode).

---

#### `audit`

Audits wallet key images for duplicates (burned funds detection).

**Use this when:**
you suspect a key derivation issue burned some outputs.

**Notes:**
- Requires core API endpoint (not yet available in attach mode).

---

#### `lock`

Locks wallet actions that require your password. See [Locking and unlocking](reference-wallet.md#locking-and-unlocking) for details on what's blocked while locked.

**Use this when:**
you are stepping away from your terminal.

**Example:**
```
> lock

# Locked
```

---

#### `unlock`

Unlocks wallet actions after password confirmation.

**Use this when:**
you get a "wallet is locked" error.

**Example:**
```
> unlock
Password: ********

# Unlocked
```

---

#### `save`

The core daemon saves the wallet automatically.

**Use this when:**
you want to confirm wallet state is persisted.

**Example:**
```
> save

# Saved
  Wallet is saved automatically by the core daemon.
```

---

#### `sync`

**Aliases:** `scan`

Triggers a blockchain rescan for wallet outputs.

**Use this when:**
wallet looks behind chain height or missing transactions. See [Sync is slow or stuck](troubleshooting.md#sync-is-slow-or-stuck) if the scanner isn't catching up.

**Example:**
```
> sync

# Sync
  Known blocks:   14207
  Blocks scanned: 14200
  Sync triggered — the core will scan for new outputs.
```

---

#### `status`

Shows node health and wallet summary in one screen.

**Use this when:**
you need a quick "is everything healthy?" check.

**Example:**
```
> status

# Node
  Peer ID:     12D3KooW...
  Peers:       8
  Height:      14207
  Best Hash:   0000c3a5b7e2d1f4
  Syncing:     false

# Wallet
  Type:        Full
  Balance:     12.5 BNT + 1 BNT pending
  Outputs:     9 unspent / 14 total
  Address:     9PNo...
```

---

#### `peers`

Lists currently connected peers.

**Use this when:**
you need to confirm network connectivity.

**Example:**
```
> peers

# Peers (8)
  12D3KooWBLUP...
    /ip4/192.168.1.5/tcp/28080
  12D3KooWNoUc...
    /ip4/10.0.0.2/tcp/28080
  ...
```

---

#### `banned`

Shows peers that were banned and why.

**Use this when:**
you suspect peer filtering or connectivity issues.

**Example:**
```
> banned

# Banned (1)
  12D3KooWXyz...
    addr:   /ip4/...
    reason: repeated bad blocks
    count:  3x, expires in 2h30m
```

---

#### `export-peer`

Writes connected peer addresses to `peer.txt`.

**Use this when:**
you want another node to connect to known peers.

**Example:**
```
> export-peer

# Export
  8 peer addresses written to peer.txt
  Share this file or its contents with other nodes.
```

---

#### `mining`

```
mining
mining start
mining stop
mining threads <N>
```

Controls local mining and how many CPU threads mining uses.

**Use this when:**
you want to mine, stop mining, or tune CPU/RAM use.

**Example:**
```
> mining start

# Mining
  Started

> mining threads 4

# Mining
  Threads set to 4 (~8GB RAM)

> mining

# Mining — active (2m31s)
  Hashrate:     12.50 H/s
  Total hashes: 1893

> mining stop

# Mining
  Stopped
```

**Notes:**
- Roughly 2GB RAM per thread.
- Thread aliases: `threads`, `thread`, `t`.

---

#### `certify`

Checks the chain for broken or inconsistent block data.

**Use this when:**
you suspect corruption or strange chain behavior.

**Notes:**
- Requires core API endpoint (not yet available in attach mode).

---

#### `purge`

Deletes local chain data but keeps your wallet and funds.

**Use this when:**
chain is stuck/corrupted and regular sync cannot recover.

**Example:**
```
> purge

# Purge
  This will delete all blockchain data.
  Your wallet will NOT be deleted.
  This action CANNOT be undone.

  Confirm purge? [y/N]: y
  Password: ********
  Blockchain data purged. Core will shut down.
```

**Notes:**
- Your wallet file and money are not deleted.
- Requires password confirmation.

---

#### `version`

Prints the Blocknet version.

**Example:**
```
> version

# Version dev
```

---

#### `about`

Shows project info and upstream links.

**Example:**
```
> about

# About
  Blocknet vX.Y.Z
  Zero-knowledge money. Made in USA.

  BSD 3-Clause License
  Copyright (c) 2026, Blocknet Privacy

  https://blocknetcrypto.com
  https://explorer.blocknetcrypto.com
  https://github.com/blocknetprivacy
```

---

#### `license`

Prints the full software license text.

---

#### `quit`

**Aliases:** `exit`, `q`

Exits the attach session. The core keeps running.
