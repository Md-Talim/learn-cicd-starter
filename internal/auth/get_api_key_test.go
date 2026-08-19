package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey abc123xyz")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if key != "abc123xyz" {
		t.Errorf("expected key 'abc123xyz', got %q", key)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_Malformed_SchemeMissing(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer token123")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error for missing ApiKey scheme")
	}
}

func TestGetAPIKey_Malformed_NoSpace(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error for malformed header with no space")
	}
}

func TestGetAPIKey_Malformed_InvalidScheme(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Basic token123")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error for invalid scheme")
	}
}
