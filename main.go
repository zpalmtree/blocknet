package main

import (
	"fmt"
	"os"
)

var (
	Version = "1.0.0"
	NoColor bool
)

func main() {
	args := filterFlags(os.Args[1:])
	if len(args) == 0 {
		if err := cmdStatus(nil); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var err error
	switch args[0] {
	case "start":
		err = cmdStart(args[1:])
	case "stop":
		err = cmdStop(args[1:])
	case "restart":
		err = cmdRestart(args[1:])
	case "status":
		err = cmdStatus(args[1:])
	case "attach":
		err = cmdAttach(args[1:])
	case "enable":
		err = cmdEnable(args[1:])
	case "disable":
		err = cmdDisable(args[1:])
	case "upgrade":
		err = cmdUpgrade(args[1:])
	case "list":
		err = cmdList(args[1:])
	case "install":
		err = cmdInstall(args[1:])
	case "uninstall":
		err = cmdUninstall(args[1:])
	case "use":
		err = cmdUse(args[1:])
	case "logs":
		err = cmdLogs(args[1:])
	case "cleanup":
		err = cmdCleanup(args[1:])
	case "doctor":
		err = cmdDoctor(args[1:])
	case "setup":
		err = cmdSetup(args[1:])
	case "completions":
		err = cmdCompletions(args[1:])
	case "config":
		err = cmdConfig(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("blocknet %s\n", Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`blocknet %s

Usage: blocknet <command> [args]

Lifecycle:
  start [mainnet|testnet]     Start managed cores
  stop [mainnet|testnet]      Stop managed cores
  restart [mainnet|testnet]   Restart managed cores
  enable [mainnet|testnet]    Enable auto-start for a core
  disable [mainnet|testnet]   Disable auto-start for a core
  status                      Show status of all managed cores

Interactive:
  attach [mainnet|testnet]    Open interactive CLI session
  logs [mainnet|testnet]      Follow core log output

Versions:
  list                        List available and installed core versions
  install <version>           Download a core version
  uninstall <version>         Remove a core version
  use <version> [network]     Set which core version to use
  upgrade                     Download and apply latest core release
  cleanup                     Remove core versions not in use

Maintenance:
  setup                       First-run setup wizard
  doctor                      Check system health and diagnose issues
  config                      Print current configuration
  completions <shell>         Generate shell completions (bash/zsh/fish)
  version                     Print version
  help                        Show this help

Flags:
  --nocolor                   Disable colored output
`, Version)
}

func filterFlags(args []string) []string {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		NoColor = true
	}
	var filtered []string
	for _, a := range args {
		switch a {
		case "--nocolor", "--no-color":
			NoColor = true
		default:
			filtered = append(filtered, a)
		}
	}
	return filtered
}
