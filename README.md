# blocknet

Private digital currency. Stealth addresses, ring signatures, confidential transactions.

## specs

| | |
|---|---|
| algorithm | Argon2id (2GB) |
| block time | 5 min |
| supply | ~10M + 0.2/block tail |
| ring size | 16 (fixed) |
| addresses | stealth (dual-key) |
| amounts | Pedersen + Bulletproofs |
| signatures | CLSAG |
| hashing | SHA3-256 |

## download

Pre-built binaries at [blocknetcrypto.com](https://blocknetcrypto.com). Single binary, no extra files needed.

## build from source

Requires Go 1.22+ and Rust 1.75+.

### linux

```
sudo apt install build-essential
make all
```

### macos

```
xcode-select --install
make all
```

### windows (msys2)

Install MSYS2 from https://www.msys2.org/, then in MINGW64 shell:

```
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-rust mingw-w64-x86_64-go
make all
```

Or without make:

```
cd crypto-rs && cargo build --release
cd .. && CGO_ENABLED=1 go build -o blocknet .
```

The Rust crypto library is statically linked into the binary. No shared libraries needed at runtime.

## run

```
./blocknet
```

### commands

```
status              node and wallet status
balance             wallet balance
address             receiving address
send <addr> <amt>   send funds
history             transaction history
mining start        start mining
mining stop         stop mining
mining threads <N>  set mining threads (2GB RAM each)
peers               connected peers
banned              banned peers
export-peer         export peer address to peer.txt
sync                force chain sync
seed                show recovery phrase
viewkeys            export view-only wallet keys
lock                lock wallet
unlock              unlock wallet
save                save wallet to disk
quit                exit
```

### flags

```
--wallet <path>     wallet file (default: wallet.dat)
--data <path>       data directory (default: ./data)
--listen <addr>     p2p listen address (default: /ip4/0.0.0.0/tcp/28080)
--seed              run as seed node (persistent identity)
--daemon            headless mode (no interactive shell)
--recover           recover wallet from mnemonic
--viewonly          create view-only wallet (requires --spend-pub and --view-priv)
--spend-pub <hex>   spend public key for view-only wallet
--view-priv <hex>   view private key for view-only wallet
--explorer <addr>   run block explorer (e.g. --explorer :8080)
--nocolor           disable colored output
--test              run crypto and chain tests
```

Custom peers can be passed as positional args:

```
./blocknet /ip4/1.2.3.4/tcp/28080/p2p/12D3KooW...
```

## privacy

Ring signatures with 16 decoys make the true sender indistinguishable.

One-time stealth addresses prevent linking transactions to recipients.

Pedersen commitments hide values. Bulletproofs prove validity without revealing amounts.

Dandelion++ obscures transaction origin on the network layer.

## license

BSD 3-Clause. See LICENSE.
