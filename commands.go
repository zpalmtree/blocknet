package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cmdStart(args []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}
	if err := EnsureConfigDir(); err != nil {
		return err
	}

	var networks []Network
	if len(args) > 0 {
		net, err := ParseNetwork(args[0])
		if err != nil {
			return err
		}
		networks = []Network{net}
	} else {
		for _, net := range []Network{Mainnet, Testnet} {
			cc := cfg.Cores[net]
			if cc != nil && cc.Enabled {
				networks = append(networks, net)
			}
		}
		if len(networks) == 0 {
			return fmt.Errorf("no cores enabled in config — enable one or specify a network")
		}
	}

	if warns := validateConfig(cfg, networks); len(warns) > 0 {
		for _, w := range warns {
			fmt.Fprintf(os.Stderr, "  warning: %s\n", w)
		}
	}

	if cfg.AutoUpgrade {
		maybeAutoUpgrade(cfg)
	}

	for _, net := range networks {
		if pid, err := readCorePidFile(net); err == nil && processAlive(pid) {
			fmt.Printf("  %s already running (pid %d)\n", net, pid)
			continue
		}

		cc := cfg.Cores[net]
		if cc == nil {
			cc = &CoreConfig{Enabled: true, Version: "latest"}
			if net == Mainnet {
				cc.APIAddr = "127.0.0.1:8332"
			} else {
				cc.APIAddr = "127.0.0.1:18332"
			}
		}

		resolved, err := ResolveInstalledVersion(cc.Version)
		if err != nil {
			return fmt.Errorf("%s: %w", net, err)
		}
		binPath := CoreBinaryPath(resolved)

		fmt.Printf("  Starting %s core (%s)...\n", net, resolved)
		pid, err := startCore(net, cc, binPath)
		if err != nil {
			return err
		}

		writeCorePidFile(net, pid)
		fmt.Printf("  %s core running (pid %d, api %s)\n", net, pid, cc.APIAddr)
	}
	return nil
}

func cmdStop(args []string) error {
	var networks []Network
	if len(args) > 0 {
		net, err := ParseNetwork(args[0])
		if err != nil {
			return err
		}
		networks = []Network{net}
	} else {
		networks = []Network{Mainnet, Testnet}
	}

	stopped := 0
	for _, net := range networks {
		if err := stopCore(net); err != nil {
			if len(args) > 0 {
				return err
			}
			continue
		}
		stopped++
		fmt.Printf("  %s core stopped\n", net)
	}
	if stopped == 0 && len(args) == 0 {
		fmt.Println("  No cores running")
	}
	return nil
}

func cmdRestart(args []string) error {
	cmdStop(args)
	return cmdStart(args)
}

func cmdStatus(args []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	green, pink, dim, reset := "\033[38;2;170;255;0m", "\033[38;2;255;0;170m", "\033[2m", "\033[0m"
	if NoColor {
		green, pink, dim, reset = "", "", "", ""
	}

	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil {
			continue
		}

		netColor := green
		if net == Testnet {
			netColor = pink
		}

		enabledTag := fmt.Sprintf("%senabled%s", netColor, reset)
		if !cc.Enabled {
			enabledTag = fmt.Sprintf("%sdisabled%s", dim, reset)
		}

		pid, pidErr := readCorePidFile(net)
		alive := pidErr == nil && processAlive(pid)

		runTag := fmt.Sprintf("%sstopped%s", dim, reset)
		if alive {
			runTag = fmt.Sprintf("%srunning%s", netColor, reset)
		}

		fmt.Printf("\n%s#%s %s [%s] [%s]\n", netColor, reset, net, runTag, enabledTag)

		if !alive || cc.APIAddr == "" {
			continue
		}

		dataDir := cc.ResolveDataDir(net)
		client, err := NewCoreClient(cc.APIAddr, CookiePath(dataDir))
		if err != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		raw, err := client.Status(ctx)
		cancel()
		if err != nil {
			continue
		}

		var status struct {
			Height  uint64 `json:"chain_height"`
			Peers   int    `json:"peers"`
			Syncing bool   `json:"syncing"`
		}
		json.Unmarshal(raw, &status)

		fmt.Printf("  Height:   %d\n", status.Height)
		fmt.Printf("  Peers:    %d\n", status.Peers)
		fmt.Printf("  Syncing:  %v\n", status.Syncing)
		fmt.Printf("  API:      %s\n", cc.APIAddr)
	}
	fmt.Println()
	return nil
}

func cmdAttach(args []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	var targetNet Network
	if len(args) > 0 {
		targetNet, err = ParseNetwork(args[0])
		if err != nil {
			return err
		}
	} else {
		var enabled []Network
		for _, net := range []Network{Mainnet, Testnet} {
			cc := cfg.Cores[net]
			if cc != nil && cc.Enabled && cc.APIAddr != "" {
				enabled = append(enabled, net)
			}
		}
		switch len(enabled) {
		case 0:
			return fmt.Errorf("no cores enabled with an API address")
		case 1:
			targetNet = enabled[0]
		default:
			targetNet = Mainnet
		}
	}

	cc := cfg.Cores[targetNet]
	if cc == nil || cc.APIAddr == "" {
		return fmt.Errorf("%s has no API address configured", targetNet)
	}

	dataDir := cc.ResolveDataDir(targetNet)
	client, err := NewCoreClient(cc.APIAddr, CookiePath(dataDir))
	if err != nil {
		return fmt.Errorf("cannot connect to %s core: %w", targetNet, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, err = client.Status(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("%s core is not reachable at %s", targetNet, cc.APIAddr)
	}

	session := NewAttachSession(client, targetNet, NoColor)
	return session.Run()
}

func cmdEnable(args []string) error  { return setEnabled(args, true) }
func cmdDisable(args []string) error { return setEnabled(args, false) }

func setEnabled(args []string, enabled bool) error {
	if len(args) == 0 {
		word := "enable"
		if !enabled {
			word = "disable"
		}
		return fmt.Errorf("usage: blocknet %s <mainnet|testnet>", word)
	}

	net, err := ParseNetwork(args[0])
	if err != nil {
		return err
	}

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	cc := cfg.Cores[net]
	if cc == nil {
		return fmt.Errorf("no config for %s", net)
	}

	cc.Enabled = enabled
	if err := EnsureConfigDir(); err != nil {
		return err
	}
	if err := SaveConfig(ConfigFile(), cfg); err != nil {
		return err
	}

	label := "enabled"
	if !enabled {
		label = "disabled"
	}
	fmt.Printf("  %s %s\n", net, label)
	return nil
}

func cmdUpgrade(args []string) error {
	fmt.Println("  Checking for new releases...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	latest, err := LatestRelease(ctx)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}

	fmt.Printf("  Latest: %s (%s)\n", latest.Tag, latest.Date.Format("Jan 02, 2006"))

	destPath := CoreBinaryPath(latest.Tag)
	if _, err := os.Stat(destPath); err == nil {
		fmt.Printf("  %s already installed\n", latest.Tag)
		return nil
	}

	asset := FindAsset(latest.Assets)
	if asset == nil {
		return fmt.Errorf("release %s does not include a binary for your platform (%s)\n  this is expected for early releases before multi-platform builds were added\n  try a newer version: blocknet install latest", latest.Tag, BinaryName())
	}

	fmt.Printf("  Downloading %s...\n", asset.Name)
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	if err := DownloadAsset(dlCtx, asset.URL, destPath); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	fmt.Printf("  Installed %s\n", latest.Tag)

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	restarted := 0
	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil || IsPinned(cc.Version) {
			continue
		}
		pid, pidErr := readCorePidFile(net)
		if pidErr != nil || !processAlive(pid) {
			continue
		}
		fmt.Printf("  Restarting %s core with %s...\n", net, latest.Tag)
		stopCore(net)
		newPid, err := startCore(net, cc, destPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: %s restart failed: %v\n", net, err)
			continue
		}
		writeCorePidFile(net, newPid)
		fmt.Printf("  %s core restarted (pid %d)\n", net, newPid)
		restarted++
	}

	if restarted == 0 {
		fmt.Println("  Restart running cores to use the new version")
	}
	return nil
}

func cmdList(args []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	releases, err := ListReleases(ctx)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}

	inUse := make(map[string]Network)
	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil {
			continue
		}
		v := strings.ToLower(cc.Version)
		if v == "latest" {
			if resolved, err := ResolveInstalledVersion("latest"); err == nil {
				inUse[resolved] = net
			}
		} else {
			inUse[cc.Version] = net
		}
	}

	installed := make(map[string]bool)
	for _, r := range releases {
		if _, err := os.Stat(CoreBinaryPath(r.Tag)); err == nil {
			installed[r.Tag] = true
		}
	}
	if _, err := os.Stat(CoreBinaryPath("nightly")); err == nil {
		installed["nightly"] = true
	}

	cyan, green, pink, dim, reset := "\033[36m", "\033[38;2;170;255;0m", "\033[38;2;255;0;170m", "\033[2m", "\033[0m"
	if NoColor {
		cyan, green, pink, dim, reset = "", "", "", "", ""
	}

	fmt.Printf("\n  %-12s %-18s %s\n", "version", "date", "status")
	fmt.Printf("  %s\n", strings.Repeat("─", 50))

	nightlyStatus := ""
	if net, ok := inUse["nightly"]; ok {
		c := green
		if net == Testnet {
			c = pink
		}
		nightlyStatus = fmt.Sprintf("%s[%s]%s", c, net, reset)
	} else if installed["nightly"] {
		nightlyStatus = fmt.Sprintf("%sinstalled%s", cyan, reset)
	}
	fmt.Printf("  %-12s %-18s %s\n", "nightly", "latest", nightlyStatus)

	for _, r := range releases {
		if r.Prerelease {
			continue
		}
		date := r.Date.Format("Jan 02, 2006")
		status := ""
		if net, ok := inUse[r.Tag]; ok {
			c := green
			if net == Testnet {
				c = pink
			}
			status = fmt.Sprintf("%s[%s]%s", c, net, reset)
		} else if installed[r.Tag] {
			status = fmt.Sprintf("%sinstalled%s", cyan, reset)
		} else {
			date = fmt.Sprintf("%s%s%s", dim, date, reset)
		}
		fmt.Printf("  %-12s %-18s %s\n", r.Tag, date, status)
	}
	fmt.Println()
	return nil
}

func cmdInstall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: blocknet install <version>")
	}
	version := args[0]

	fmt.Printf("  Finding %s...\n", version)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if strings.EqualFold(version, "latest") {
		latest, err := LatestRelease(ctx)
		if err != nil {
			return fmt.Errorf("fetch releases: %w", err)
		}
		version = latest.Tag
		fmt.Printf("  Latest is %s\n", version)
	}

	destPath := CoreBinaryPath(version)
	if version != "nightly" {
		if _, err := os.Stat(destPath); err == nil {
			fmt.Printf("  %s already installed\n", version)
			return nil
		}
	}

	releases, err := ListReleases(ctx)
	if err != nil {
		return fmt.Errorf("fetch releases: %w", err)
	}

	var asset *Asset
	for _, r := range releases {
		if r.Tag != version {
			continue
		}
		asset = FindAsset(r.Assets)
		break
	}
	if asset == nil {
		return fmt.Errorf("release %s does not include a binary for your platform (%s)\n  this is expected for early releases before multi-platform builds were added\n  try: blocknet list (to see available versions)", version, BinaryName())
	}

	fmt.Printf("  Downloading %s...\n", asset.Name)
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	if err := DownloadAsset(dlCtx, asset.URL, destPath); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	fmt.Printf("  Installed %s -> %s\n", version, destPath)
	return nil
}

func cmdUninstall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: blocknet uninstall <version>")
	}
	version := args[0]

	dir := CoreDir(version)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("%s is not installed", version)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	fmt.Printf("  Uninstalled %s\n", version)
	return nil
}

func cmdUse(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: blocknet use <version> [mainnet|testnet]")
	}
	version := args[0]

	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	if len(args) >= 2 {
		net, err := ParseNetwork(args[1])
		if err != nil {
			return err
		}
		cc := cfg.Cores[net]
		if cc == nil {
			return fmt.Errorf("no config for %s", net)
		}
		cc.Version = version
		fmt.Printf("  %s set to %s\n", net, version)
	} else {
		for _, net := range []Network{Mainnet, Testnet} {
			if cc := cfg.Cores[net]; cc != nil {
				cc.Version = version
			}
		}
		fmt.Printf("  All cores set to %s\n", version)
	}

	if err := EnsureConfigDir(); err != nil {
		return err
	}
	return SaveConfig(ConfigFile(), cfg)
}

func cmdConfig(args []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func cmdLogs(args []string) error {
	net := Mainnet
	if len(args) > 0 {
		var err error
		net, err = ParseNetwork(args[0])
		if err != nil {
			return err
		}
	}

	path := LogFile(net)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("no log file for %s (has it been started?)", net)
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, _ := f.Stat()
	offset := int64(0)
	if info.Size() > 8192 {
		offset = info.Size() - 8192
	}
	f.Seek(offset, io.SeekStart)
	if offset > 0 {
		buf := make([]byte, 1)
		for {
			_, err := f.Read(buf)
			if err != nil || buf[0] == '\n' {
				break
			}
		}
	}
	io.Copy(os.Stdout, f)

	fmt.Printf("\n  following %s log... (ctrl+c to stop)\n\n", net)

	for {
		n, err := io.Copy(os.Stdout, f)
		if err != nil {
			return err
		}
		if n == 0 {
			time.Sleep(250 * time.Millisecond)
		}
	}
}

func cmdCleanup(args []string) error {
	cfg, err := LoadConfig(ConfigFile())
	if err != nil {
		return err
	}

	inUse := make(map[string]bool)
	for _, net := range []Network{Mainnet, Testnet} {
		cc := cfg.Cores[net]
		if cc == nil {
			continue
		}
		if resolved, err := ResolveInstalledVersion(cc.Version); err == nil {
			inUse[resolved] = true
		}
		if IsPinned(cc.Version) {
			inUse[cc.Version] = true
		}
	}

	coresDir := filepath.Join(ConfigDir(), "cores")
	entries, err := os.ReadDir(coresDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("  No core versions installed")
			return nil
		}
		return err
	}

	var removed int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ver := e.Name()
		if inUse[ver] {
			continue
		}
		dir := filepath.Join(coresDir, ver)
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not remove %s: %v\n", ver, err)
			continue
		}
		fmt.Printf("  Removed %s\n", ver)
		removed++
	}

	if removed == 0 {
		fmt.Println("  Nothing to clean up")
	} else {
		fmt.Printf("  Cleaned up %d version(s)\n", removed)
	}
	return nil
}
