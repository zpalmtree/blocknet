package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func lastCheckFile() string {
	return filepath.Join(ConfigDir(), ".last_upgrade_check")
}

func readLastCheck() time.Time {
	data, err := os.ReadFile(lastCheckFile())
	if err != nil {
		return time.Time{}
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

func writeLastCheck() {
	os.MkdirAll(filepath.Dir(lastCheckFile()), 0755)
	os.WriteFile(lastCheckFile(), []byte(strconv.FormatInt(time.Now().Unix(), 10)+"\n"), 0644)
}

func maybeAutoUpgrade(cfg *Config) {
	interval := cfg.CheckIntervalDuration()
	last := readLastCheck()
	if time.Since(last) < interval {
		return
	}

	writeLastCheck()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	latest, err := LatestRelease(ctx)
	if err != nil {
		return
	}

	destPath := CoreBinaryPath(latest.Tag)
	if _, err := os.Stat(destPath); err == nil {
		return
	}

	asset := FindAsset(latest.Assets)
	if asset == nil {
		return
	}

	fmt.Printf("  New core version available: %s\n", latest.Tag)
	fmt.Printf("  Downloading %s...\n", asset.Name)

	dlCtx, dlCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer dlCancel()

	if err := DownloadAsset(dlCtx, asset.URL, destPath); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: auto-upgrade download failed: %v\n", err)
		return
	}

	fmt.Printf("  Installed %s (will be used on next restart)\n", latest.Tag)
}
