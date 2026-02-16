package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestViewPriv_DeprecatedFlagRejected(t *testing.T) {
	tmp := t.TempDir()
	walletPath := filepath.Join(tmp, "viewonly.dat")

	res := runMainHelper(t, helperRun{
		args: []string{
			"--viewonly",
			"--wallet", walletPath,
			"--spend-pub", strings.Repeat("11", 32),
			"--view-priv", strings.Repeat("22", 32),
		},
		env: map[string]string{
			"BLOCKNET_VIEW_PRIV": "",
		},
		stdin: "abc\n",
	})
	if res.exitCode == 0 {
		t.Fatalf("expected non-zero exit code; stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "--view-priv no longer accepts") {
		t.Fatalf("unexpected stderr: %q", res.stderr)
	}
}

func TestViewPriv_EnvMissingErrors(t *testing.T) {
	tmp := t.TempDir()
	walletPath := filepath.Join(tmp, "viewonly.dat")

	res := runMainHelper(t, helperRun{
		args: []string{
			"--viewonly",
			"--wallet", walletPath,
			"--spend-pub", strings.Repeat("11", 32),
		},
		env: map[string]string{
			"BLOCKNET_VIEW_PRIV": "",
		},
		stdin: "abc\n",
	})
	if res.exitCode == 0 {
		t.Fatalf("expected non-zero exit code; stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "environment variable BLOCKNET_VIEW_PRIV is not set") {
		t.Fatalf("unexpected stderr: %q", res.stderr)
	}
}

func TestViewPriv_EnvOverrideSucceedsAndCreatesWalletFile(t *testing.T) {
	tmp := t.TempDir()
	walletPath := filepath.Join(tmp, "viewonly.dat")

	const envName = "CUSTOM_VIEW_PRIV"
	res := runMainHelper(t, helperRun{
		args: []string{
			"--viewonly",
			"--wallet", walletPath,
			"--spend-pub", strings.Repeat("11", 32),
			"--view-priv-env", envName,
		},
		env: map[string]string{
			envName: strings.Repeat("22", 32),
		},
		stdin: "abc\n",
	})
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0; stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if _, err := os.Stat(walletPath); err != nil {
		t.Fatalf("expected wallet file to exist at %q: %v (stdout=%q stderr=%q)", walletPath, err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "View-only wallet created:") {
		t.Fatalf("expected success output, got stdout=%q stderr=%q", res.stdout, res.stderr)
	}
}

// ---- Helper subprocess harness ----

type helperRun struct {
	args  []string
	env   map[string]string // value "" means unset
	stdin string
}

type helperResult struct {
	exitCode int
	stdout   string
	stderr   string
}

func runMainHelper(t *testing.T, run helperRun) helperResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=TestHelperProcessMain", "--"}, run.args...)...)
	cmd.Env = applyEnv(os.Environ(), run.env)
	cmd.Stdin = strings.NewReader(run.stdin)
	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("failed to run helper: %v", err)
		}
	}
	return helperResult{
		exitCode: exitCode,
		stdout:   out.String(),
		stderr:   errBuf.String(),
	}
}

func applyEnv(base []string, updates map[string]string) []string {
	// Convert to map for easy update/unset.
	m := make(map[string]string, len(base))
	for _, kv := range base {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	m["GO_WANT_HELPER_PROCESS"] = "1"
	for k, v := range updates {
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

func TestHelperProcessMain(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	// Extract args after "--".
	args := []string{}
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	os.Args = append([]string{os.Args[0]}, args...)

	// Reset global flags so main() can parse in this subprocess.
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	main()
	os.Exit(0)
}

