package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadWhitelistFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")
	content := `["12D3KooWQUNGJrsU5nRXNk45FT3ZumdtWC9Sg9Xt2AgU3XkP382R"]`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	ids, err := loadWhitelistFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 peer ID, got %d", len(ids))
	}
}

func TestLoadWhitelistFile_MultiplePeers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")
	content := `[
		"12D3KooWQUNGJrsU5nRXNk45FT3ZumdtWC9Sg9Xt2AgU3XkP382R",
		"12D3KooWSQTy8rav5nmapgxomAMpSrigJTUXHmjH25dtHhGU3BAM"
	]`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	ids, err := loadWhitelistFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 peer IDs, got %d", len(ids))
	}
}

func TestLoadWhitelistFile_InvalidPeerID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")
	if err := os.WriteFile(path, []byte(`["not-a-peer-id"]`), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadWhitelistFile(path); err == nil {
		t.Fatal("expected error for invalid peer ID")
	}
}

func TestLoadWhitelistFile_EmptyEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")
	if err := os.WriteFile(path, []byte(`[""]`), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadWhitelistFile(path); err == nil {
		t.Fatal("expected error for empty peer ID entry")
	}
}

func TestLoadWhitelistFile_NotJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")
	if err := os.WriteFile(path, []byte(`this is not json`), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadWhitelistFile(path); err == nil {
		t.Fatal("expected error for non-JSON content")
	}
}

func TestLoadWhitelistFile_MissingFile(t *testing.T) {
	if _, err := loadWhitelistFile("/nonexistent/whitelist.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadWhitelistFile_EmptyArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")
	if err := os.WriteFile(path, []byte(`[]`), 0644); err != nil {
		t.Fatal(err)
	}

	ids, err := loadWhitelistFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected 0 peer IDs, got %d", len(ids))
	}
}
