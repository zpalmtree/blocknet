package params

// NetworkID is a public network identifier used as a domain separator in
// wallet/protocol constructions (e.g. memo KDFs, address checksums).
const NetworkID = "blocknet_mainnet"

// ChainID is a fixed relaunch epoch identifier used in P2P status handshakes.
// It is intentionally a constant (not derived) for auditability and to avoid
// accidental changes if genesis mechanics are refactored later.
const ChainID uint32 = 0x20260215
