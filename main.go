package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"blocknet/wallet"
)

const Version = "0.5.0"

func main() {
	// Parse command line flags
	version := flag.Bool("version", false, "Print version and exit")
	walletFile := flag.String("wallet", DefaultWalletFilename, "Path to wallet file")
	dataDir := flag.String("data", DefaultDataDir, "Data directory")
	listen := flag.String("listen", "/ip4/0.0.0.0/tcp/28080", "P2P listen address")
	seedMode := flag.Bool("seed", false, "Run as seed node (persistent P2P identity)")
	recover := flag.Bool("recover", false, "Recover wallet from mnemonic seed")
	daemonMode := flag.Bool("daemon", false, "Run headless (no interactive shell)")
	explorerAddr := flag.String("explorer", "", "HTTP address for block explorer (e.g. :8080)")
	apiAddr := flag.String("api", "", "API listen address (e.g. 127.0.0.1:8332)")
	noColor := flag.Bool("nocolor", false, "Disable colored output")
	noVersionCheck := flag.Bool("no-version-check", false, "Disable remote version check on startup")
	viewOnly := flag.Bool("viewonly", false, "Create a view-only wallet")
	spendPub := flag.String("spend-pub", "", "Spend public key (hex) for view-only wallet")
	// Deprecated: secrets on argv are visible via process inspection (ps, /proc).
	viewPrivDeprecated := flag.String("view-priv", "", "DEPRECATED (insecure): do not pass view private key via CLI; use --view-priv-env/BLOCKNET_VIEW_PRIV")
	viewPrivEnv := flag.String("view-priv-env", "BLOCKNET_VIEW_PRIV", "Environment variable name containing view private key (hex) for view-only wallet")
	flag.Parse()

	if *version {
		fmt.Println(Version)
		return
	}

	// Quarantine well-known legacy default paths before any init work.
	// This is intentionally conservative: it only quarantines legacy defaults
	// when the operator did not explicitly provide the corresponding flags.
	if renames, err := quarantineLegacyDefaults(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: legacy quarantine failed: %v\n", err)
		os.Exit(1)
	} else if len(renames) > 0 {
		for _, r := range renames {
			absFrom, _ := filepath.Abs(r.From)
			absTo, _ := filepath.Abs(r.To)
			if absFrom != "" && absTo != "" {
				fmt.Fprintf(os.Stderr, "Quarantined legacy path: %s -> %s\n", absFrom, absTo)
			} else {
				fmt.Fprintf(os.Stderr, "Quarantined legacy path: %s -> %s\n", r.From, r.To)
			}
		}
		fmt.Fprintln(os.Stderr, "Warning: quarantined paths are pre-relaunch state and must not be reused.")
	}

	// View-only wallet creation mode
	if *viewOnly {
		if *viewPrivDeprecated != "" {
			fmt.Fprintln(os.Stderr, "Error: --view-priv no longer accepts a private key on the command line.")
			fmt.Fprintln(os.Stderr, "Set the key in an environment variable and use --view-priv-env to pick the name (default: BLOCKNET_VIEW_PRIV).")
			fmt.Fprintln(os.Stderr, "Example: BLOCKNET_VIEW_PRIV=<hex> blocknet --viewonly --spend-pub <hex>")
			os.Exit(1)
		}

		if *spendPub == "" {
			fmt.Fprintln(os.Stderr, "Error: --viewonly requires --spend-pub")
			fmt.Fprintln(os.Stderr, "Usage: BLOCKNET_VIEW_PRIV=<hex> blocknet --viewonly --spend-pub <hex>")
			os.Exit(1)
		}

		envName := strings.TrimSpace(*viewPrivEnv)
		if envName == "" {
			fmt.Fprintln(os.Stderr, "Error: --view-priv-env must not be empty")
			os.Exit(1)
		}
		viewPrivHex := strings.TrimSpace(os.Getenv(envName))
		if viewPrivHex == "" {
			fmt.Fprintf(os.Stderr, "Error: environment variable %s is not set (expected 64 hex chars)\n", envName)
			fmt.Fprintln(os.Stderr, "Usage: BLOCKNET_VIEW_PRIV=<hex> blocknet --viewonly --spend-pub <hex>")
			os.Exit(1)
		}

		// Reduce lifetime in-process (does not remove from parent shell env).
		_ = os.Unsetenv(envName)

		if err := createViewOnlyWallet(*walletFile, *spendPub, viewPrivHex); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Seed mode: ensure P2P identity is persistent (and stable across restarts).
	// Honor explicit env override if user set it themselves.
	if *seedMode && strings.TrimSpace(os.Getenv("BLOCKNET_P2P_KEY")) == "" {
		if err := os.Setenv("BLOCKNET_P2P_KEY", filepath.Join(*dataDir, "identity.key")); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to set BLOCKNET_P2P_KEY: %v\n", err)
		}
	}
	// Seed bootstrap assist: if we fail to start due to missing seed reachability,
	// still export our peer addresses so operators can bake updated seed IDs.
	if *seedMode && strings.TrimSpace(os.Getenv("BLOCKNET_EXPORT_PEER_ON_START_FAIL")) == "" {
		_ = os.Setenv("BLOCKNET_EXPORT_PEER_ON_START_FAIL", "1")
	}

	// Normal mode: start interactive CLI
	seedNodes := DefaultSeedNodes
	if len(flag.Args()) > 0 {
		seedNodes = append(seedNodes, flag.Args()...)
	}
	cfg := CLIConfig{
		WalletFile:     *walletFile,
		DataDir:        *dataDir,
		ListenAddrs:    []string{*listen},
		SeedNodes:      seedNodes,
		RecoverMode:    *recover,
		DaemonMode:     *daemonMode,
		ExplorerAddr:   *explorerAddr,
		APIAddr:        *apiAddr,
		NoColor:        *noColor,
		NoVersionCheck: *noVersionCheck,
	}

	cli, err := NewCLI(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := cli.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func createViewOnlyWallet(filename, spendPubHex, viewPrivHex string) error {
	// Parse hex keys
	spendPubBytes, err := hex.DecodeString(spendPubHex)
	if err != nil || len(spendPubBytes) != 32 {
		return fmt.Errorf("invalid spend public key (expected 64 hex chars)")
	}

	viewPrivBytes, err := hex.DecodeString(viewPrivHex)
	if err != nil || len(viewPrivBytes) != 32 {
		return fmt.Errorf("invalid view private key (expected 64 hex chars)")
	}

	var keys wallet.ViewOnlyKeys
	copy(keys.SpendPubKey[:], spendPubBytes)
	copy(keys.ViewPrivKey[:], viewPrivBytes)

	// Derive view public key from view private key
	kp, err := GenerateRistrettoKeypairFromSeed(keys.ViewPrivKey)
	if err != nil {
		return fmt.Errorf("failed to derive view public key: %w", err)
	}
	keys.ViewPubKey = kp.PublicKey

	// Prompt for password
	fmt.Print("Enter password for new view-only wallet: ")
	var password string
	if _, err := fmt.Scanln(&password); err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if len(password) < 3 {
		return fmt.Errorf("password must be at least 3 characters")
	}

	// Create wallet config
	cfg := wallet.WalletConfig{
		CheckStealthOutput: CheckStealthOutput,
		DeriveOutputSecret: DeriveStealthSecret,
	}

	// Create view-only wallet
	w, err := wallet.NewViewOnlyWallet(filename, []byte(password), keys, cfg)
	if err != nil {
		return fmt.Errorf("failed to create view-only wallet: %w", err)
	}

	fmt.Printf("View-only wallet created: %s\n", filename)
	fmt.Printf("Address: %s\n", w.Address())
	fmt.Println("\nThis wallet can monitor incoming funds but cannot spend.")

	return nil
}
