package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func cmdSetup(args []string) error {
	reader := bufio.NewReader(os.Stdin)

	green, pink, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;255;0;170m", "\033[2m", "\033[0m"
	if NoColor {
		green, pink, dim, reset = "", "", "", ""
	}

	fmt.Println()
	fmt.Printf("  %sWelcome to Blocknet!%s\n", green, reset)
	fmt.Println()
	fmt.Println("  This will walk you through setting up your node.")
	fmt.Println("  You can always change things later by editing the config file")
	fmt.Printf("  or running %sblocknet config%s.\n", dim, reset)
	fmt.Println()
	fmt.Println("  Press Enter to accept the default (shown in brackets),")
	fmt.Println("  or type your answer.")
	fmt.Println()

	// Check if config already exists
	cfgPath := ConfigFile()
	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Printf("  %sA config file already exists at %s%s\n", dim, cfgPath, reset)
		fmt.Print("  Overwrite it? [y/N]: ")
		answer := readLine(reader)
		if strings.ToLower(answer) != "y" {
			fmt.Println()
			fmt.Println("  Setup cancelled. Your existing config is unchanged.")
			return nil
		}
		fmt.Println()
	}

	cfg := DefaultConfig()

	// --- Mainnet ---
	fmt.Printf("  %s── Mainnet ──%s\n\n", green, reset)

	fmt.Printf("  Enable mainnet? This is the real network where coins have value.\n")
	fmt.Print("  [Y/n]: ")
	if answer := readLine(reader); strings.ToLower(answer) == "n" {
		cfg.Cores[Mainnet].Enabled = false
		fmt.Println()
	} else {
		cfg.Cores[Mainnet].Enabled = true
		fmt.Println()

		fmt.Printf("  What API address should mainnet listen on?\n")
		fmt.Printf("  %sThis is how blocknet attach talks to the core.%s\n", dim, reset)
		fmt.Printf("  [127.0.0.1:8332]: ")
		if answer := readLine(reader); answer != "" {
			cfg.Cores[Mainnet].APIAddr = answer
		}
		fmt.Println()
	}

	// --- Testnet ---
	fmt.Printf("  %s── Testnet ──%s\n\n", pink, reset)

	fmt.Println("  Enable testnet? This is a separate network for testing.")
	fmt.Println("  Testnet coins have no real value.")
	fmt.Print("  [y/N]: ")
	if answer := readLine(reader); strings.ToLower(answer) == "y" {
		cfg.Cores[Testnet].Enabled = true
		fmt.Println()

		fmt.Printf("  What API address should testnet listen on?\n")
		fmt.Printf("  %sMust be different from mainnet.%s\n", dim, reset)
		fmt.Printf("  [127.0.0.1:18332]: ")
		if answer := readLine(reader); answer != "" {
			cfg.Cores[Testnet].APIAddr = answer
		}
		fmt.Println()
	} else {
		cfg.Cores[Testnet].Enabled = false
		fmt.Println()
	}

	// --- Auto-upgrade ---
	fmt.Printf("  %s── Upgrades ──%s\n\n", green, reset)

	fmt.Println("  Automatically download and apply new core releases?")
	fmt.Printf("  %sWhen a new version is available, blocknet will download it%s\n", dim, reset)
	fmt.Printf("  %sand restart your cores to apply it.%s\n", dim, reset)
	fmt.Print("  [Y/n]: ")
	if answer := readLine(reader); strings.ToLower(answer) == "n" {
		cfg.AutoUpgrade = false
	} else {
		cfg.AutoUpgrade = true
	}
	fmt.Println()

	// --- Save config ---
	if err := EnsureConfigDir(); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := SaveConfig(cfgPath, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("  Config saved to %s\n\n", cfgPath)

	// --- Install core ---
	anyEnabled := false
	for _, cc := range cfg.Cores {
		if cc != nil && cc.Enabled {
			anyEnabled = true
			break
		}
	}

	if !anyEnabled {
		fmt.Println("  No cores enabled. You can enable one later with:")
		fmt.Printf("    blocknet enable mainnet\n\n")
		fmt.Printf("  %sSetup complete!%s\n\n", green, reset)
		return nil
	}

	hasCore := false
	if resolved, err := ResolveInstalledVersion("latest"); err == nil {
		if _, err := os.Stat(CoreBinaryPath(resolved)); err == nil {
			hasCore = true
		}
	}

	if hasCore {
		fmt.Println("  A core version is already installed.")
	} else {
		fmt.Println("  You don't have a core installed yet.")
		fmt.Println("  Would you like to download the latest one now?")
		fmt.Printf("  %sThis is required before you can start a node.%s\n", dim, reset)
		fmt.Print("  [Y/n]: ")
		if answer := readLine(reader); strings.ToLower(answer) != "n" {
			fmt.Println()
			fmt.Println("  Downloading latest core...")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			latest, err := LatestRelease(ctx)
			if err != nil {
				fmt.Printf("\n  %sCouldn't fetch releases: %v%s\n", dim, err, reset)
				fmt.Println("  You can install manually later: blocknet install latest")
			} else {
				asset := FindAsset(latest.Assets)
				if asset == nil {
					fmt.Printf("\n  %sNo binary for your platform in %s%s\n", dim, latest.Tag, reset)
					fmt.Println("  You can install manually later: blocknet install latest")
				} else {
					fmt.Printf("  Downloading %s (%s)...\n", latest.Tag, asset.Name)
					destPath := CoreBinaryPath(latest.Tag)
					if err := DownloadAsset(ctx, asset.URL, destPath); err != nil {
						fmt.Printf("\n  %sDownload failed: %v%s\n", dim, err, reset)
						fmt.Println("  You can install manually later: blocknet install latest")
					} else {
						fmt.Printf("  Installed %s\n", latest.Tag)
						hasCore = true
					}
				}
			}
		}
		fmt.Println()
	}

	// --- Start now? ---
	if hasCore {
		fmt.Println("  Would you like to start your node(s) now?")
		fmt.Print("  [Y/n]: ")
		if answer := readLine(reader); strings.ToLower(answer) != "n" {
			fmt.Println()
			if err := cmdStart(nil); err != nil {
				fmt.Printf("  %sCouldn't start: %v%s\n\n", dim, err, reset)
			}
		} else {
			fmt.Println()
			fmt.Println("  You can start later with: blocknet start")
		}
	}

	// --- Shell completions ---
	if shell := detectShell(); shell != "" {
		rcFile := shellRCFile(shell)
		fmt.Printf("  %s── Shell Completions ──%s\n\n", green, reset)
		fmt.Printf("  Detected shell: %s%s%s\n", dim, shell, reset)
		fmt.Println("  Tab completions let you press Tab to auto-complete commands")
		fmt.Println("  like 'blocknet sta' → 'blocknet start'.")
		fmt.Println()
		if rcFile != "" {
			fmt.Printf("  Install completions to %s%s%s?\n", dim, rcFile, reset)
		} else {
			fmt.Println("  Install completions?")
		}
		fmt.Print("  [Y/n]: ")
		if answer := readLine(reader); strings.ToLower(answer) != "n" {
			if err := installCompletions(shell, rcFile); err != nil {
				fmt.Printf("  %sCouldn't install completions: %v%s\n", dim, err, reset)
				fmt.Printf("  You can add them manually: blocknet completions %s\n", shell)
			} else {
				fmt.Printf("  Completions installed. They'll work in new terminal sessions.\n")
			}
		}
		fmt.Println()
	}

	fmt.Printf("  %sSetup complete!%s Here's what you can do next:\n\n", green, reset)
	fmt.Println("    blocknet status            See what's running")
	fmt.Println("    blocknet attach mainnet     Open the interactive shell")
	fmt.Println("    blocknet help               See all commands")
	fmt.Println()
	return nil
}

func detectShell() string {
	if runtime.GOOS == "windows" {
		return ""
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		return ""
	}

	base := filepath.Base(shell)
	switch base {
	case "bash":
		return "bash"
	case "zsh":
		return "zsh"
	case "fish":
		return "fish"
	}
	return ""
}

func shellRCFile(shell string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch shell {
	case "bash":
		rc := filepath.Join(home, ".bashrc")
		if _, err := os.Stat(rc); err == nil {
			return rc
		}
		return filepath.Join(home, ".bash_profile")
	case "zsh":
		return filepath.Join(home, ".zshrc")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	}
	return ""
}

func installCompletions(shell, rcFile string) error {
	if rcFile == "" {
		return fmt.Errorf("couldn't determine rc file for %s", shell)
	}

	var evalLine string
	switch shell {
	case "bash":
		evalLine = `eval "$(blocknet completions bash)"`
	case "zsh":
		evalLine = `eval "$(blocknet completions zsh)"`
	case "fish":
		evalLine = `blocknet completions fish | source`
	default:
		return fmt.Errorf("unsupported shell: %s", shell)
	}

	existing, err := os.ReadFile(rcFile)
	if err == nil && strings.Contains(string(existing), "blocknet completions") {
		return nil
	}

	if shell == "fish" {
		dir := filepath.Dir(rcFile)
		os.MkdirAll(dir, 0755)
	}

	f, err := os.OpenFile(rcFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "\n# Blocknet shell completions\n%s\n", evalLine)
	return err
}

// selfBinaryName returns the name of the running binary for use in eval lines.
// Falls back to "blocknet" if detection fails.
func selfBinaryName() string {
	path, err := exec.LookPath(os.Args[0])
	if err != nil {
		return "blocknet"
	}
	return filepath.Base(path)
}

func readLine(reader *bufio.Reader) string {
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
