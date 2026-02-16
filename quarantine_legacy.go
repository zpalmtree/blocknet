package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type quarantineRename struct {
	From string
	To   string
}

func argHasFlag(argv []string, name string) bool {
	dash := "-" + name
	dash2 := "--" + name
	for _, a := range argv {
		if a == dash || a == dash2 {
			return true
		}
		if strings.HasPrefix(a, dash+"=") || strings.HasPrefix(a, dash2+"=") {
			return true
		}
	}
	return false
}

func quarantineSuffixPath(path string) string {
	ext := filepath.Ext(path)
	if ext == "" {
		return path + ".OLD.DELETE.ME"
	}
	base := strings.TrimSuffix(path, ext)
	return base + ".OLD.DELETE.ME" + ext
}

func uniqueQuarantinePath(path string) string {
	candidate := quarantineSuffixPath(path)
	if _, err := os.Stat(candidate); err != nil {
		return candidate // either doesn't exist, or stat failed; let rename attempt decide
	}
	// Avoid collisions if quarantine already exists.
	ts := time.Now().UTC().Format("20060102T150405Z")
	ext := filepath.Ext(path)
	if ext == "" {
		return path + ".OLD.DELETE.ME." + ts
	}
	base := strings.TrimSuffix(path, ext)
	return base + ".OLD.DELETE.ME." + ts + ext
}

func quarantineRenameIfExists(from string) (*quarantineRename, error) {
	if _, err := os.Stat(from); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", from, err)
	}
	to := uniqueQuarantinePath(from)
	if err := os.Rename(from, to); err != nil {
		return nil, fmt.Errorf("rename %s -> %s: %w", from, to, err)
	}
	return &quarantineRename{From: from, To: to}, nil
}

// quarantineLegacyDefaults renames well-known legacy default paths out of the way
// to prevent accidental reuse and to make pre-relaunch state obvious.
//
// It is intentionally conservative: only quarantine legacy defaults when the user
// did not explicitly provide the corresponding flag/env override.
func quarantineLegacyDefaults(argv []string) ([]quarantineRename, error) {
	var renames []quarantineRename

	// Legacy wallet default in cwd.
	if !argHasFlag(argv, "wallet") {
		if r, err := quarantineRenameIfExists("wallet.dat"); err != nil {
			return nil, err
		} else if r != nil {
			renames = append(renames, *r)
		}
	}

	// Legacy chain data directory default in cwd.
	if !argHasFlag(argv, "data") {
		if r, err := quarantineRenameIfExists("data"); err != nil {
			return nil, err
		} else if r != nil {
			renames = append(renames, *r)
		}
	}

	// Legacy XDG identity key (do not touch if the operator explicitly pointed
	// BLOCKNET_P2P_KEY at that path).
	legacyXDG, err := legacyXDGIdentityPath()
	if err != nil {
		return nil, err
	}
	if envPath := strings.TrimSpace(os.Getenv("BLOCKNET_P2P_KEY")); envPath == "" || filepath.Clean(envPath) != filepath.Clean(legacyXDG) {
		if r, err := quarantineRenameIfExists(legacyXDG); err != nil {
			return nil, err
		} else if r != nil {
			renames = append(renames, *r)
		}
	}

	return renames, nil
}

func legacyXDGIdentityPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "blocknet", "identity.key"), nil
}

