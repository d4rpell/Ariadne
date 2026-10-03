package prismaacquire

import (
	"strings"
	"testing"
	"time"
)

// Incremento 6 de A2-08-F2: autenticación (ADR-0028 §5). Dos modos cerrados, una
// única petición de intercambio y un parser exclusivo del protocolo de token.

func TestA208F2AuthRequestExactBody(t *testing.T) {
	body, err := authRequestBody("alice", "s3cr3t")
	if err != nil {
		t.Fatalf("authRequestBody failed: %v", err)
	}
	if got, want := string(body), `{"username":"alice","password":"s3cr3t"}`; got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	escaped, err := authRequestBody(`a"b\c`, "p")
	if err != nil {
		t.Fatalf("escaping failed: %v", err)
	}
	if got, want := string(escaped), `{"username":"a\"b\\c","password":"p"}`; got != want {
		t.Fatalf("escaped body = %s, want %s", got, want)
	}
}

func TestA208F2AuthRequestRejectsForbiddenBytes(t *testing.T) {
	cases := []string{"a\x00b", "a\rb", "a\nb"}
	for _, u := range cases {
		if _, err := authRequestBody(u, "p"); err == nil {
			t.Fatalf("username %q accepted", u)
		}
		if _, err := authRequestBody("u", u); err == nil {
			t.Fatalf("password %q accepted", u)
		}
	}
	if _, err := authRequestBody("", "p"); err == nil || err.Code != CodeCredentialUnavailable {
		t.Fatalf("empty username: err = %v, want %s", err, CodeCredentialUnavailable)
	}
	if _, err := authRequestBody(strings.Repeat("u", maxUsernameBytes+1), "p"); err == nil {
		t.Fatal("oversize username accepted")
	}
	if _, err := authRequestBody("u", strings.Repeat("p", maxPasswordBytes+1)); err == nil {
		t.Fatal("oversize password accepted")
	}
}

func TestA208F2AuthResponseClosedSchema(t *testing.T) {
	oversizeToken := `{"token":"` + strings.Repeat("a", maxTokenBytes+1) + `"}`
	cases := []struct {
		name  string
		input string
		ok    string
	}{
		{"valid", `{"token":"abc.def-_~+/="}`, "abc.def-_~+/="},
		{"empty_object", `{}`, ""},
		{"null", `{"token":null}`, ""},
		{"empty_string", `{"token":""}`, ""},
		{"number", `{"token":123}`, ""},
		{"bool", `{"token":true}`, ""},
		{"unknown_member", `{"token":"a","extra":1}`, ""},
		{"duplicate", `{"token":"a","token":"b"}`, ""},
		{"trailing", `{"token":"a"} {}`, ""},
		{"truncated", `{"token":"a"`, ""},
		{"array_root", `["a"]`, ""},
		{"space_in_token", `{"token":"a b"}`, ""},
		{"control_in_token", `{"token":"a\nb"}`, ""},
		{"equals_not_suffix", `{"token":"a=b"}`, ""},
		{"oversize_token", oversizeToken, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAuthResponse([]byte(tc.input))
			if tc.ok != "" {
				if err != nil {
					t.Fatalf("valid response rejected: %v", err)
				}
				if got != tc.ok {
					t.Fatalf("token = %q, want %q", got, tc.ok)
				}
				return
			}
			if err == nil || err.Code != CodeAuthResponseInvalid {
				t.Fatalf("err = %v, want %s", err, CodeAuthResponseInvalid)
			}
		})
	}
}

func TestA208F2AuthResponseRejectsOversize(t *testing.T) {
	// A response over 64 KiB is rejected before any parsing.
	big := append([]byte(`{"token":"`), []byte(strings.Repeat("a", maxAuthResponseBytes))...)
	big = append(big, []byte(`"}`)...)
	if _, err := parseAuthResponse(big); err == nil || err.Code != CodeAuthResponseInvalid {
		t.Fatalf("oversize response: err = %v, want %s", err, CodeAuthResponseInvalid)
	}
}

func TestA208F2CredentialExpiry(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	if tokenExpired(nil, now) {
		t.Fatal("nil expiry must be unknown, not expired")
	}
	if tokenExpired(&future, now) {
		t.Fatal("future expiry reported expired")
	}
	if !tokenExpired(&past, now) {
		t.Fatal("past expiry not reported expired")
	}
	if !tokenExpired(&now, now) {
		t.Fatal("reached expiry must abort before the next request")
	}
}
