package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blocknet/wallet"
)

func TestOpenAPIAndHandlerMemoContractParity(t *testing.T) {
	// --- Handler-side behavior (real mux, real auth middleware, real wallet) ---
	chain, _, cleanup := mustCreateTestChain(t)
	defer cleanup()
	mustAddGenesisBlock(t, chain)

	// We only need a "current height" that makes our synthetic output mature.
	chain.mu.Lock()
	chain.height = 100
	chain.mu.Unlock()

	daemon, stopDaemon := mustStartTestDaemon(t, chain)
	defer stopDaemon()

	walletFile := filepath.Join(t.TempDir(), "wallet.dat")
	w, err := wallet.NewWallet(walletFile, []byte("pw"), defaultWalletConfig())
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	// Give the wallet one mature output so handleSend reaches memo validation
	// before failing later in the expensive build path.
	w.AddOutput(&wallet.OwnedOutput{
		TxID:        [32]byte{0x01},
		OutputIndex: 0,
		Amount:      10_000_000,
		BlockHeight: 0,
		IsCoinbase:  false,
		Spent:       false,
	})
	// And one output with a decrypted memo so handleHistory includes memo_hex.
	w.AddOutput(&wallet.OwnedOutput{
		TxID:        [32]byte{0x02},
		OutputIndex: 1,
		Amount:      1,
		BlockHeight: 0,
		IsCoinbase:  false,
		Spent:       false,
		Memo:        []byte{0x01, 0x02, 0x03},
	})

	api := NewAPIServer(daemon, w, nil, t.TempDir(), []byte("pw"))
	mux := http.NewServeMux()
	api.registerPublicRoutes(mux)
	api.registerPrivateRoutes(mux)

	// Mirror production handler chain.
	token := "test-token"
	var handler http.Handler = mux
	handler = authMiddleware(token, handler)
	handler = maxBodySize(handler, maxRequestBodyBytes)

	authz := map[string]string{
		"Authorization": "Bearer " + token,
		"Content-Type":  "application/json",
	}

	doReq := func(method, path string, body []byte, headers map[string]string, remoteAddr string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.RemoteAddr = remoteAddr
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	// Mutual exclusion: memo_text + memo_hex must fail.
	{
		body := []byte(`{"address":"` + w.Address() + `","amount":1,"memo_text":"hi","memo_hex":"00"}`)
		rr := doReq("POST", "/api/wallet/send", body, authz, "198.51.100.10:1234")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for memo mutual exclusion, got %d: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "provide either memo_text or memo_hex") {
			t.Fatalf("unexpected error body for mutual exclusion: %s", rr.Body.String())
		}
	}

	// Hex validation: odd-length or non-hex memo_hex must fail.
	{
		body := []byte(`{"address":"` + w.Address() + `","amount":1,"memo_hex":"0"}`)
		rr := doReq("POST", "/api/wallet/send", body, authz, "198.51.100.11:1234")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid memo_hex, got %d: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "invalid memo_hex") {
			t.Fatalf("unexpected error body for invalid memo_hex: %s", rr.Body.String())
		}
	}

	// Length bound: memo payload must be <= 124 bytes.
	{
		long := strings.Repeat("a", wallet.MemoSize-3) // 125 bytes; over wallet limit (124)
		body := []byte(`{"address":"` + w.Address() + `","amount":1,"memo_text":"` + long + `"}`)
		rr := doReq("POST", "/api/wallet/send", body, authz, "198.51.100.12:1234")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for too-long memo_text, got %d: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "memo too long") {
			t.Fatalf("unexpected error body for too-long memo_text: %s", rr.Body.String())
		}
	}

	// History response should surface memo_hex (hex) when memo payload is present.
	{
		rr := doReq("GET", "/api/wallet/history", nil, authz, "198.51.100.13:1234")
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 from history, got %d: %s", rr.Code, rr.Body.String())
		}
		var got struct {
			Count   int                      `json:"count"`
			Outputs []map[string]interface{} `json:"outputs"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("failed to decode history JSON: %v", err)
		}
		if got.Count == 0 || len(got.Outputs) == 0 {
			t.Fatalf("expected history outputs, got count=%d len(outputs)=%d", got.Count, len(got.Outputs))
		}
		foundMemo := false
		for _, out := range got.Outputs {
			if v, ok := out["memo_hex"]; ok {
				s, ok := v.(string)
				if !ok {
					t.Fatalf("memo_hex is not string: %#v", v)
				}
				if s != "010203" {
					// We inserted a known memo; ensure it round-trips as hex.
					t.Fatalf("unexpected memo_hex: got %q want %q", s, "010203")
				}
				foundMemo = true
			}
			// Ensure legacy field name does not reappear.
			if _, ok := out["payment_id"]; ok {
				t.Fatalf("unexpected payment_id field in history output: %#v", out)
			}
		}
		if !foundMemo {
			t.Fatal("expected at least one output with memo_hex")
		}
	}

	// --- OpenAPI-side contract (schema reflects handler behavior) ---
	specBytes, err := os.ReadFile("api_openapi.json")
	if err != nil {
		t.Fatalf("failed to read api_openapi.json: %v", err)
	}

	var spec map[string]interface{}
	if err := json.Unmarshal(specBytes, &spec); err != nil {
		t.Fatalf("failed to parse api_openapi.json: %v", err)
	}

	// Validate SendRequest has memo_text + memo_hex and does not mention payment_id.
	components := mustGetMap(t, spec, "components")
	allSchemas := mustGetMap(t, components, "schemas")
	sendReq := mustGetMap(t, allSchemas, "SendRequest")
	props := mustGetMap(t, sendReq, "properties")

	if _, ok := props["memo_text"]; !ok {
		t.Fatal("SendRequest missing memo_text in OpenAPI")
	}
	if _, ok := props["memo_hex"]; !ok {
		t.Fatal("SendRequest missing memo_hex in OpenAPI")
	}
	if _, ok := props["payment_id"]; ok {
		t.Fatal("SendRequest unexpectedly includes legacy payment_id in OpenAPI")
	}
	if _, ok := props["memo"]; ok {
		t.Fatal("SendRequest unexpectedly includes memo (single-field) in OpenAPI")
	}

	// Ensure the mutual-exclusion invariant is machine-expressed.
	if _, ok := sendReq["oneOf"]; !ok {
		t.Fatal("SendRequest missing oneOf mutual-exclusion constraint in OpenAPI")
	}

	// Ensure schema encodes the same bounds we enforce in handlers.
	memoText := mustGetMap(t, props, "memo_text")
	if got, ok := memoText["maxLength"].(float64); !ok || int(got) != 124 {
		t.Fatalf("SendRequest.memo_text maxLength mismatch: got %#v want 124", memoText["maxLength"])
	}
	memoHex := mustGetMap(t, props, "memo_hex")
	if got, ok := memoHex["maxLength"].(float64); !ok || int(got) != 248 {
		t.Fatalf("SendRequest.memo_hex maxLength mismatch: got %#v want 248", memoHex["maxLength"])
	}
	if pat, ok := memoHex["pattern"].(string); !ok || !strings.Contains(pat, "{2}") {
		t.Fatalf("SendRequest.memo_hex pattern missing even-length constraint: got %#v", memoHex["pattern"])
	}

	// Ensure `/api/wallet/send` documents idempotency header support.
	paths := mustGetMap(t, spec, "paths")
	sendPath := mustGetMap(t, paths, "/api/wallet/send")
	sendPost := mustGetMap(t, sendPath, "post")
	rawParams, ok := sendPost["parameters"]
	if !ok {
		t.Fatal("/api/wallet/send post missing parameters")
	}
	params, ok := rawParams.([]interface{})
	if !ok {
		t.Fatal("/api/wallet/send post parameters is not an array")
	}
	foundIdem := false
	for _, p := range params {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if name, _ := pm["name"].(string); strings.EqualFold(name, "Idempotency-Key") {
			foundIdem = true
			break
		}
	}
	if !foundIdem {
		t.Fatal("/api/wallet/send post missing Idempotency-Key parameter")
	}
}

func mustGetMap(t *testing.T, m map[string]interface{}, key string) map[string]interface{} {
	t.Helper()
	raw, ok := m[key]
	if !ok {
		t.Fatalf("missing key %q in OpenAPI object", key)
	}
	out, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("key %q is not an object in OpenAPI", key)
	}
	return out
}
