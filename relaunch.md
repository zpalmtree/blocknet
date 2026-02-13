# Blocknet Mainnet Relaunch Runbook

This runbook defines the minimum changes and operator actions required to relaunch from height 0 after a catastrophic chain event.

## Concrete Code Targets (Current Repo)

- Genesis constants and constructor: `block.go` -> `GenesisMessage`, `GenesisTimestamp`, `GenesisPrevHash()`, `GetGenesisBlock()`, `validateGenesisBlock()`.
- Chain/network identity signaling: `p2p/sync.go` -> `ChainStatus` (currently has `Version`), `handleStatus()`, `getStatusFrom()`; `daemon.go` -> `getChainStatus()`.
- P2P protocol identifiers: `p2p/node.go` -> `ProtocolPEX`, `ProtocolBlock`, `ProtocolTx`, `ProtocolSync`, `ProtocolDandelion`.
- Seed list: `daemon.go` -> `DefaultSeedNodes`.
- Version/user agent source: `main.go` -> `Version`; `daemon.go` -> `nodeCfg.UserAgent = "blocknet/" + Version`.
- Data directory defaults:
  - `main.go` -> `flag.String("data", "./data", ...)`
  - `cli.go` -> `DefaultCLIConfig().DataDir = "./data"`
  - `daemon.go` -> `DefaultDaemonConfig().DataDir = "./data"`
- Chain DB filename construction: `storage.go` -> `NewStorage()` -> `filepath.Join(dataDir, "chain.db")`.
- Wallet filename defaults:
  - `main.go` -> `flag.String("wallet", "wallet.dat", ...)`
  - `cli.go` -> `DefaultCLIConfig().WalletFile = "wallet.dat"`
  - wallet load/create path: `wallet/wallet.go` -> `LoadOrCreateWallet()`, `LoadWallet()`, `NewWallet()`.
- Persistent libp2p identity path: `p2p/identity.go` -> `defaultIdentityPath()` currently returns `filepath.Join(configDir, "blocknet", "identity.key")`.

## Goals

- Hard split old and new networks at consensus and transport layers.
- Prevent old peers from successfully speaking to new nodes.
- Ensure all participants start from a clean local state.

## 1) Mandatory Code/Config Changes Before Launch

1. **Regenerate genesis identity**
   - Update `GenesisMessage` in `block.go`.
   - Update `GenesisTimestamp` in `block.go`.
   - Keep genesis deterministic and fixed for all nodes.

2. **Bump P2P protocol namespace/version**
   - Update protocol IDs in `p2p/node.go`:
     - `ProtocolPEX`
     - `ProtocolBlock`
     - `ProtocolTx`
     - `ProtocolSync`
     - `ProtocolDandelion`
   - Move from `/blocknet/.../1.0.0` to a new version namespace so old nodes cannot negotiate streams.

3. **Add explicit `NetworkID` and `ChainID` constants**
   - Define fixed relaunch identifiers as code constants (for example in a dedicated `network_params.go`).
   - Include them in peer status exchange payloads (`p2p/sync.go` `ChainStatus`) and reject mismatches in `handleStatus()` and sync admission paths.
   - Set the values from daemon status source (`daemon.go` `getChainStatus()`), not from mutable runtime input.
   - Suggested concrete names and wiring:

```go
// network_params.go
package main

const (
    // Human-readable network label.
    NetworkID = "blocknet-mainnet-2026-02-relaunch"

    // Fixed chain epoch identifier for handshake/status checks.
    // Keep stable for this relaunched chain.
    ChainID uint32 = 0x20260213
)
```

```go
// p2p/sync.go (ChainStatus)
type ChainStatus struct {
    BestHash  [32]byte `json:"best_hash"`
    Height    uint64   `json:"height"`
    TotalWork uint64   `json:"total_work"`
    Version   uint32   `json:"version"`
    NetworkID string   `json:"network_id"`
    ChainID   uint32   `json:"chain_id"`
}
```

```go
// daemon.go (getChainStatus)
func (d *Daemon) getChainStatus() p2p.ChainStatus {
    return p2p.ChainStatus{
        BestHash:  d.chain.BestHash(),
        Height:    d.chain.Height(),
        TotalWork: d.chain.TotalWork(),
        Version:   1,
        NetworkID: NetworkID,
        ChainID:   ChainID,
    }
}
```

```go
// p2p/sync.go (handleStatus/getStatusFrom checks)
if status.NetworkID != expectedNetworkID || status.ChainID != expectedChainID {
    return // reject mismatch immediately
}
```

4. **Rotate bootstrap seed list**
   - Replace `DefaultSeedNodes` in `daemon.go` with only new relaunch peers.
   - Do not include any pre-relaunch peer addresses.

5. **Version bump**
   - Bump `Version` in `main.go` so logs/user-agent clearly identify relaunch binaries.

6. **Use a new chain data location and filename scheme**
   - Change default `--data` path in `main.go` from `./data` to a relaunch namespace (for example `./data-main`).
   - Change `DefaultCLIConfig().DataDir` in `cli.go` from `./data` to the same relaunch namespace.
   - Change `DefaultDaemonConfig().DataDir` in `daemon.go` from `./data` to the same relaunch namespace.
   - Change DB filename in `storage.go` `NewStorage()` from `chain.db` to a relaunch-specific name (for example `chain.mainnet.db`).
   - Never auto-open legacy chain files in relaunch binaries.

7. **Change XDG app namespace for persistent identity/config**
   - Update `p2p/identity.go` `defaultIdentityPath()` from `filepath.Join(configDir, "blocknet", "identity.key")` to a relaunch namespace (for example `filepath.Join(configDir, "blocknet-main", "identity.key")`).
   - Keep old namespace read-only for migration detection only.

8. **Adopt explicit wallet filename convention**
   - Change default wallet filename in `main.go` from `wallet.dat` to relaunch format (for example `wallet.blocknet.wallet.dat`).
   - Change `DefaultCLIConfig().WalletFile` in `cli.go` from `wallet.dat` to relaunch format.
   - Keep `wallet/wallet.go` `LoadOrCreateWallet()` behavior, but ensure callers pass the new default name.

9. **Replace legacy payment-ID aux trailer with canonical mandatory memo field**
   - Remove transaction aux trailer usage for payment metadata (`TxAuxData`, `EncodeTxWithAux`, `DecodeTxWithAux`, `BlockAuxData.PaymentIDs`).
   - Add a mandatory per-output encrypted memo field in canonical transaction outputs.
   - Backward compatibility is intentionally out of scope for relaunch; enforce only new format from genesis.

## 1A) Mandatory Memo Field Spec (Relaunch Consensus)

### Decision

- Relaunch memo policy is fixed: **128 bytes per output**, mandatory on every output.
- This is a locked relaunch constant (not configurable at runtime).
- `aux` goes away for memo/payment metadata.
- Memo moves into the main transaction struct as a fixed-size output field.
- Memo bytes are signed/hashed as part of canonical tx serialization and therefore affect `TxID`.

### Why this replaces aux

- Aux trailers are not consensus-canonical and are easier to strip/mutate in transit.
- Canonical output embedding gives deterministic relay/mining/storage behavior.
- Fixed memo size on every output avoids presence/absence fingerprinting.
- Relaunch allows a clean break, so no compatibility tax is required.

### Output format (consensus-level)

- Add to each output, after `EncryptedAmount`:
  - `EncryptedMemo [128]byte` (always present, every output, every tx).
- Memo size is always exactly `128` bytes.
- Coinbase outputs also carry this field for uniformity (encrypted under deterministic coinbase path or set by coinbase-specific deterministic rule, but still fixed-size and present).

### Plaintext memo envelope (before encryption)

- 128-byte plaintext buffer:
  - byte `0`: `version` (`0x01` for relaunch format)
  - byte `1`: `length` (`0..124`)
  - bytes `2..3`: `checksum` (`uint16`, little-endian, over payload bytes only)
  - bytes `4..(4+length-1)`: payload raw bytes
  - remaining bytes: random padding
- Empty memo:
  - `length=0`
  - checksum of empty payload
  - padding still random (not zero-padded) to avoid deterministic "empty memo" fingerprints.

### Encryption / decryption

- Per-output stream mask derivation:
  - `mask = SHA3-256(shared_secret || "memo" || output_index || block_domain_sep)`
  - Expand mask to 128 bytes with counter mode:
    - `block_i = SHA3-256(mask || uint32_le(i))` for `i = 0..3`
    - concatenate to 128 bytes.
- Ciphertext:
  - `EncryptedMemo = PlainMemo XOR mask128`.
- Non-coinbase outputs:
  - `shared_secret` uses existing stealth ECDH path (sender: `txPriv * recipientViewPub`, recipient: `viewPriv * txPub`).
- Coinbase outputs:
  - use deterministic consensus derivation tied to coinbase output context (height, output index, tx pubkey) so every node serializes/validates identically.

### Validation rules (consensus vs wallet/UI)

- Consensus MUST enforce:
  - each output includes exactly 128 memo bytes.
  - `EncryptedMemo` is not the all-zero byte array (rejects legacy/default-zero memo patterns deterministically).
  - memo bytes are treated as opaque ciphertext at the consensus layer; consensus cannot validate envelope version/length/checksum without the per-output shared secret.
  - no aux payment-ID map/trailer is accepted in relaunch tx format.
- Consensus MUST NOT enforce:
  - UTF-8 correctness, text policy, display policy, URL handling, bidi stripping.
- Wallet/API/UI SHOULD enforce/display policy:
  - accept either `memo_text` (UTF-8) or `memo_hex`.
  - reject dangerous control/bidi/zero-width classes at input layer where needed.
  - always escape on render, no auto-linking.

### Fees and weight

- Memo bytes are part of canonical serialized tx size.
- Standard per-byte fee policy applies; no special memo discount/multiplier.
- Capacity impact:
  - additional 128 bytes per output in tx size and bandwidth.
  - this is an intentional privacy tradeoff for uniform memo surface.

### Mempool / miner / block semantics

- Mempool stores canonical tx bytes only; no sidecar memo metadata.
- Miner and block template logic do not build `BlockAuxData.PaymentIDs`.
- Block JSON and storage no longer carry payment-ID aux maps.
- Reorg re-add path uses tx bytes directly; no memo reconstruction from block aux required.

### API / CLI contract changes

- Replace `payment_id` input/output with memo fields:
  - request: `memo_text` or `memo_hex` (optional input; output field still always exists after decrypt path, may be empty).
  - response/history: expose decoded memo text when valid UTF-8 and safe, plus hex form for raw fidelity.
- CLI:
  - replace optional `send <address> <amount> [payment_id]` with memo-capable form (for example `send <address> <amount> [memo]` plus explicit flags for text/hex).
- Explorer:
  - show memo as encrypted blob unless wallet keys are available (default explorer behavior remains ciphertext-only).

### Remove/replace code paths in current repo

- Remove:
  - `tx_aux.go` (`EncodeTxWithAux`, `DecodeTxWithAux`, aux marker logic).
  - `TxAuxData` usage in `mempool.go`, `daemon.go`, `miner.go`, `api_handlers.go`, `cli.go`, `explorer.go`.
  - `BlockAuxData.PaymentIDs` plumbing where only memo/payment metadata is concerned.
- Add/modify:
  - `TransactionOutput` serialization/deserialization in core tx structs (`crypto.go` and related serializers) to include `[128]byte EncryptedMemo`.
  - wallet scanner decrypt path to read memo directly from output instead of block aux map.
  - send/build path to construct plaintext envelope, encrypt, and embed memo per output.
  - API schema (`api_openapi.json`) and handlers for `memo_text`/`memo_hex`.

### Hashability and integrity tradeoff (explicit)

- **Current aux approach:** payment metadata does not affect tx hash/signature domain.
- **Relaunch memo-in-output approach:** memo bytes are in canonical serialization, so any memo mutation changes tx hash and invalidates signatures relative to tx ID references.
- Net effect:
  - stronger integrity and relay determinism.
  - larger serialized tx footprint.
  - no requirement for future fork just to secure memo integrity.

### Relaunch acceptance criteria for this feature

- All produced txs include 128-byte encrypted memo on every output.
- No node accepts relaunch txs carrying legacy aux payment-ID trailers.
- Wallet scan/history reads memo from canonical outputs only.
- Mempool/miner/block paths operate without `TxAuxData`/`BlockAuxData.PaymentIDs`.
- API/CLI no longer expose `payment_id`; memo interfaces are documented and enforced.

## 1B) Complete Implementation Blast Radius (No Omissions)

This section is the exhaustive code-change inventory for migrating from payment-ID aux to mandatory 128-byte per-output memo.

### A) Consensus, transaction model, and canonical wire format

1. **`transaction.go` (`TxOutput`, serialization, signing domain, parsing)**
   - Add `EncryptedMemo [128]byte` to `TxOutput`.
   - Update `(*Transaction).Serialize()`:
     - include memo bytes for every output in canonical binary encoding.
     - update size pre-calculation from `32 + 32 + 8 + 4 + len(out.RangeProof)` to include `+128`.
   - Update `(*Transaction).SigningHash()`:
     - include output memo bytes in prefix hash so signatures bind memo bytes.
   - Update `DeserializeTx()`:
     - require and parse 128 memo bytes for each output.
     - update minimum output byte checks to account for memo field.
   - Update JSON-visible output shape as needed so API responses carry encrypted memo in tx output objects when exposed.

2. **`wallet/builder.go` (wallet canonical serializer parity)**
   - Extend `outputData` with memo bytes.
   - Update `serializeTxPrefix()` and `serializeTx()` to include output memo bytes in exactly the same position/order as `transaction.go`.
   - Ensure prefix hashing done before signatures includes memo bytes.
   - Build memo envelope (`version|length|checksum|payload|padding`), encrypt per output, and embed in each output.
   - Ensure change output also gets a memo field (empty envelope + randomized padding, encrypted).

3. **`transaction.go` tx builders/validators**
   - Update `CreateTransaction(...)` output construction to always populate memo bytes.
   - Update `CreateCoinbase(...)` coinbase output creation to always populate memo bytes.
   - Update any output sanity checks in `ValidateTransaction(...)` path to enforce canonical output shape containing memo bytes.

4. **`block.go` block size and model cleanup**
   - Remove payment-ID-specific comments/semantics that rely on aux metadata.
   - Update `(*Transaction).Size()` implementation (currently in `block.go`) to add memo bytes per output so `MaxBlockSize` enforcement remains accurate.
   - If `BlockAuxData` has no remaining purpose after memo migration, remove:
     - `type BlockAuxData`
     - `Block.AuxData` field.

### B) Remove aux transport/data path entirely

1. **Delete `tx_aux.go`**
   - Remove aux marker format, `EncodeTxWithAux`, `DecodeTxWithAux`, and tx-boundary parser usage for aux.

2. **`daemon.go`**
   - Remove all `DecodeTxWithAux(...)` call sites:
     - gossip tx ingest path(s)
     - sync ingest path(s).
   - Remove `EncodeTxWithAux(...)` usage in broadcast path.
   - Change `SubmitTransaction(txData []byte, aux ...*TxAuxData)` to canonical-only tx submission (no aux arg).
   - Remove block reorg helper logic that reconstructs tx aux from `BlockAuxData.PaymentIDs`.
   - Update mempool sync helper that currently returns tx bytes with aux appended.

3. **`mempool.go`**
   - Remove:
     - `type TxAuxData`.
     - `MempoolEntry.Aux`.
     - aux variadic arg from `AddTransaction`.
     - `GetTransactionWithAux`.
     - aux return value from `GetTransactionsForBlock`.
     - `GetAllTransactionDataWithAux`.
   - Update `OnBlockDisconnected` to re-add plain serialized tx bytes only.

4. **`miner.go`**
   - Remove aux map parameter from `MineBlock(...)`.
   - Remove block aux assembly from tx aux map.
   - Update mining loop call site currently receiving `txs, auxData := mempool.GetTransactionsForBlock(...)`.

5. **`block.go` / chain persistence**
   - Remove payment-ID aux serialization assumptions in block JSON/model persistence if `AuxData` is removed.

### C) Wallet scanning/storage and memo crypto helpers

1. **`wallet/scanner.go`**
   - Remove `BlockData.PaymentIDs`.
   - Replace payment-ID decrypt logic with memo decrypt logic using output-carried ciphertext.
   - Replace or retire:
     - `EncryptPaymentID(...)`
     - `DecryptPaymentID(...)`
     in favor of memo envelope encrypt/decrypt helpers.
   - Ensure scanner decrypts memo per owned output and stores decoded/raw memo data.

2. **`wallet/wallet.go`**
   - Replace:
     - `OwnedOutput.PaymentID []byte`
     - `SendRecord.PaymentID []byte`
     with memo equivalents (raw bytes and/or decoded text fields).
   - Update wallet persistence JSON tags/compat expectations for new memo fields.

3. **`cli.go` scanner glue**
   - Update `blockToScanData(...)` to stop piping `block.AuxData.PaymentIDs`.
   - Ensure auto scan and sync scan paths use output memo from canonical tx data.

### D) CLI and API behavior contracts

1. **`cli.go`**
   - `cmdSend`:
     - replace optional `[payment_id]` parsing with memo input model.
     - remove payment-ID hex validation flow.
     - remove tx aux assembly.
   - `cmdHistory`:
     - replace payment-id display fields with memo display fields.
   - Update any help/usage text referencing `payment_id`.

2. **`api_handlers.go`**
   - `handleSend` request schema:
     - remove `payment_id`.
     - add memo fields (for example `memo_text` and `memo_hex`).
   - `handleSend` logic:
     - remove payment-ID parse/length checks.
     - remove tx aux creation and submission path.
     - build/encrypt memo into tx outputs.
   - `handleSend` response:
     - remove `payment_id`; expose memo result fields if needed.
   - `handleHistory`:
     - replace `payment_id` output field with memo equivalents.
   - `handleBlockTemplate`:
     - remove block-aux build from mempool aux map.
   - `handleTx`:
     - confirm response shape for tx output memo exposure is intentional and documented.

3. **`api_openapi.json`**
   - Remove all `payment_id` schema properties/descriptions.
   - Update `/api/wallet/send` request body to memo fields.
   - Update `/api/wallet/send` response schema examples.
   - Update `/api/wallet/history` output schema/examples.
   - Update any tx/output schema components to document output-level encrypted memo field.

### E) Explorer and public rendering

1. **`explorer.go`**
   - Remove mempool-aux and block-aux lookup logic for encrypted payment IDs.
   - Read encrypted memo directly from tx outputs.
   - Update template labels and field names from Payment ID to Memo (encrypted), and ensure rendering safety remains strict.

### F) Tests and fixtures that must be updated

1. **Serialization/parsing tests**
   - Update tx binary round-trip tests (`tests.go` and any focused tests) to include memo bytes in outputs.
   - Add cases for malformed/truncated memo bytes in deserialize path.

2. **Mempool/daemon/miner tests**
   - Remove aux-dependent expectations and helpers.
   - Update gossip ingest tests that currently rely on `DecodeTxWithAux`.
   - Update mining/template tests that currently pass or inspect aux maps.

3. **Wallet/scanner tests**
   - Add coverage for:
     - decrypting valid memo envelopes,
     - empty memo envelope behavior,
     - invalid checksum/version handling.

4. **API contract tests**
   - Replace payment_id request/response assertions with memo field assertions.
   - Validate OpenAPI and handler behavior remain aligned.

### G) Required codebase-wide search/replace targets

Before merge, these identifiers must have no active payment-ID semantics:

- `payment_id`
- `PaymentID`
- `PaymentIDs`
- `TxAuxData`
- `EncodeTxWithAux`
- `DecodeTxWithAux`
- `GetTransactionWithAux`
- `GetAllTransactionDataWithAux`
- `BlockAuxData` (if no non-memo use remains)
- `aux_data` payment metadata references

### H) Recommended implementation sequence (strict order)

1. Canonical tx/output format changes (`transaction.go`, `wallet/builder.go`, coinbase/create paths).
2. Remove aux plumbing (`tx_aux.go`, `mempool.go`, `daemon.go`, `miner.go`, block aux references).
3. Wallet scanner/storage memo migration (`wallet/scanner.go`, `wallet/wallet.go`, CLI scan glue).
4. API/CLI contract migration (`api_handlers.go`, `cli.go`).
5. OpenAPI and docs (`api_openapi.json`, `README.md`, this runbook if needed).
6. Explorer migration (`explorer.go` templates/fields).
7. Test suite updates for all affected paths.

## 2) Identity and Infra Rotation

1. **Generate new seed-node peer identities**
   - Create fresh libp2p identity keys for all public seed nodes.
   - Publish only new multiaddrs.

2. **Retire old identity keys on infra**
   - Remove/replace any values referenced by `BLOCKNET_P2P_KEY`.
   - Remove old persistent key files at `~/.config/blocknet/identity.key` on seed hosts if used.
   - If seed nodes also carry local wallet files, remove those legacy wallet files as part of the same rotation.

3. **Rebuild seed peer artifacts**
   - Regenerate exported peer files and deployment manifests with new peer IDs and addresses.

## 3) Required Operator Actions (All Nodes)

1. Stop node/wallet services.
2. Remove old chain state:
   - delete old default path `./data`
   - delete old DB file `<old-data-dir>/chain.db`
3. Start relaunch binary with:
   - new `--data` path (for example `./data-main`)
   - new `--wallet` filename (for example `alice.blocknet.wallet.dat`)
   - new seed peers only
4. Verify local chain restarts at genesis and syncs from new network.

## 4) Legacy File Quarantine Policy (Do Not Reuse Old State)

When relaunch binaries detect legacy filenames/formats, they should quarantine them immediately by renaming with a loud suffix.

1. **Wallet files**
   - Example: `wallet.dat` -> `wallet.OLD.DELETE.ME.dat`
   - Example: `alice.wallet.dat` -> `alice.wallet.OLD.DELETE.ME.dat`
   - Trigger point: before calling wallet open/create flow (`wallet.LoadOrCreateWallet()`).

2. **Chain database files/directories**
   - Rename legacy DB files/directories with `OLD.DELETE.ME` in the name before initializing relaunch storage.
   - Do not silently migrate legacy chain state into relaunch paths.
   - Explicit legacy targets in current layout:
     - `./data/chain.db` -> `./data/chain.OLD.DELETE.ME.db`
     - `./data` -> `./data.OLD.DELETE.ME` (if replacing entire dir)
   - Trigger point: before `NewChain()` -> `NewStorage()`.

3. **Legacy config/identity namespace**
   - If `~/.config/blocknet/...` is present, rename to an obvious quarantine name (for example `~/.config/blocknet.OLD.DELETE.ME`), or require explicit operator confirmation before first launch.
   - Explicit key target in current code: `~/.config/blocknet/identity.key`.
   - Trigger point: before `p2p.NewNode()` (which constructs `NewIdentityManager()`).

4. **Operator visibility**
   - Log every quarantine rename at startup with full path.
   - Emit a single summary warning that quarantined files are from the pre-relaunch network and must not be reused.
   - Include symbol names in logs where useful (for example: `main --wallet default`, `main --data default`, `defaultIdentityPath()` legacy hit).

## 5) Launch-Day Validation Checklist

- [ ] At least 2 independent seed nodes online with new peer IDs.
- [ ] New nodes can connect/sync to relaunch seeds.
- [ ] Old binary/old peers cannot open expected protocol streams.
- [ ] Genesis hash/timestamp observed across multiple fresh nodes is identical.
- [ ] No node boots from pre-relaunch local chain data.
- [ ] Legacy files are quarantined with `OLD.DELETE.ME` naming and clearly visible in logs.
- [ ] No process is reading `./data/chain.db`, `wallet.dat`, or `~/.config/blocknet/identity.key`.

## 6) Nice-to-Have Hardening

- Add startup guard: fail fast if local height-0 block does not match current hardcoded genesis.
- Publish a one-page operator migration notice with exact wipe path and restart command examples.
- Maintain separate DNS names/docs for relaunch bootstrap endpoints.

