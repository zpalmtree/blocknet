package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOpenAPIMiningCompactSubmitContract(t *testing.T) {
	specBytes, err := os.ReadFile("api_openapi.json")
	if err != nil {
		t.Fatalf("failed to read api_openapi.json: %v", err)
	}

	var spec map[string]any
	if err := json.Unmarshal(specBytes, &spec); err != nil {
		t.Fatalf("failed to parse api_openapi.json: %v", err)
	}

	components := mustGetMapAny(t, spec, "components")
	schemas := mustGetMapAny(t, components, "schemas")

	blockTemplate := mustGetMapAny(t, schemas, "BlockTemplate")
	blockTemplateProps := mustGetMapAny(t, blockTemplate, "properties")
	if _, ok := blockTemplateProps["template_id"]; !ok {
		t.Fatal("BlockTemplate schema missing template_id")
	}

	compactSubmit := mustGetMapAny(t, schemas, "CompactSubmitBlock")
	compactProps := mustGetMapAny(t, compactSubmit, "properties")
	if _, ok := compactProps["template_id"]; !ok {
		t.Fatal("CompactSubmitBlock missing template_id")
	}
	if _, ok := compactProps["nonce"]; !ok {
		t.Fatal("CompactSubmitBlock missing nonce")
	}

	paths := mustGetMapAny(t, spec, "paths")
	submitPath := mustGetMapAny(t, paths, "/api/mining/submitblock")
	submitPost := mustGetMapAny(t, submitPath, "post")
	requestBody := mustGetMapAny(t, submitPost, "requestBody")
	content := mustGetMapAny(t, requestBody, "content")
	appJSON := mustGetMapAny(t, content, "application/json")
	reqSchema := mustGetMapAny(t, appJSON, "schema")

	oneOf, ok := reqSchema["oneOf"].([]any)
	if !ok || len(oneOf) != 2 {
		t.Fatalf("submitblock request schema must be oneOf with 2 options, got %#v", reqSchema["oneOf"])
	}
}

func mustGetMapAny(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	raw, ok := m[key]
	if !ok {
		t.Fatalf("missing key %q in OpenAPI object", key)
	}
	out, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("key %q is not an object in OpenAPI", key)
	}
	return out
}
