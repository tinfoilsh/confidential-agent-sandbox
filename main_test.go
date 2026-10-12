package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicHTTPHasNoUnlockOrEnrollment(t *testing.T) {
	for _, path := range []string{"/healthz", "/unlock", "/enroll", "/owner/challenge", "/.well-known/tinfoil-attestation"} {
		rec := httptest.NewRecorder()
		healthHandler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		expected := http.StatusNotFound
		if path == "/healthz" {
			expected = http.StatusNoContent
		}
		if rec.Code != expected {
			t.Fatalf("%s: %d", path, rec.Code)
		}
	}
	for _, path := range []string{"/unlock", "/enroll"} {
		rec := httptest.NewRecorder()
		healthHandler().ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader(`{"volume":"secret"}`)))
		if rec.Code != http.StatusNotFound {
			t.Fatal("public unlock exposed")
		}
	}
}
