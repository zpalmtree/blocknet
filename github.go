package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	releasesURL = "https://api.github.com/repos/blocknetprivacy/core/releases"
	userAgent   = "blocknet"
)

type Release struct {
	Tag        string
	Date       time.Time
	Assets     []Asset
	Prerelease bool
}

type Asset struct {
	Name string
	URL  string
}

// ListReleases fetches all releases from the core repository.
func ListReleases(ctx context.Context) ([]Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var raw []struct {
		TagName    string `json:"tag_name"`
		PublishedAt string `json:"published_at"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse releases: %w", err)
	}

	releases := make([]Release, 0, len(raw))
	for _, r := range raw {
		t, _ := time.Parse(time.RFC3339, r.PublishedAt)
		rel := Release{
			Tag:        r.TagName,
			Date:       t,
			Prerelease: r.Prerelease,
		}
		for _, a := range r.Assets {
			rel.Assets = append(rel.Assets, Asset{
				Name: a.Name,
				URL:  a.BrowserDownloadURL,
			})
		}
		releases = append(releases, rel)
	}
	return releases, nil
}

// LatestRelease returns the newest non-prerelease version.
func LatestRelease(ctx context.Context) (*Release, error) {
	releases, err := ListReleases(ctx)
	if err != nil {
		return nil, err
	}
	for i := range releases {
		if !releases[i].Prerelease {
			return &releases[i], nil
		}
	}
	return nil, fmt.Errorf("no releases found")
}

// FindAsset picks the asset matching the current platform from a release.
// Assets follow the naming convention: blocknet-core-<arch>-<os>-<ver>.zip
func FindAsset(assets []Asset) *Asset {
	prefix := BinaryName()
	for i, a := range assets {
		if strings.HasPrefix(a.Name, prefix) {
			return &assets[i]
		}
	}
	return nil
}

// DownloadAsset downloads a URL to destPath. If the URL points to a .zip,
// the binary is extracted from the archive. Partial downloads never leave a
// broken file on disk.
func DownloadAsset(ctx context.Context, dlURL, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if strings.HasSuffix(dlURL, ".zip") {
		err := extractBinaryFromZip(tmpPath, destPath)
		os.Remove(tmpPath)
		return err
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, destPath)
}

func extractBinaryFromZip(zipPath, destPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	prefix := "blocknet-core"
	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if f.FileInfo().IsDir() || !strings.HasPrefix(name, prefix) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("extract %s: %w", name, err)
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			rc.Close()
			return err
		}

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			rc.Close()
			return err
		}

		_, copyErr := io.Copy(out, rc)
		rc.Close()
		out.Close()
		if copyErr != nil {
			os.Remove(destPath)
			return fmt.Errorf("extract %s: %w", name, copyErr)
		}
		return nil
	}
	return fmt.Errorf("no binary matching %q found in zip", prefix)
}
