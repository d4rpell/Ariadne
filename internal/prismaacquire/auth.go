package prismaacquire

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
)

// Authentication of ADR-0028 §5. Two modes are admitted and selected before the
// acquisition starts: bearer_supplied (zero POST) and password_exchange (at most
// one POST before any image read). There is no negotiation, no renewal on 401
// and no fallback format. The authentication response parser is exclusive to
// this small token protocol; it does not replace or modify the native admission
// lexer of F1 (§5.5).

// authRequest is the closed request body of §5.4. Exactly two members; the
// encoding/json encoder escapes the values, so no concatenated template carries
// credential data.
type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// hasForbiddenCredentialByte reports whether s contains NUL, CR or LF (§5.4).
func hasForbiddenCredentialByte(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 0x00, '\r', '\n':
			return true
		}
	}
	return false
}

// authRequestBody builds the exact POST body of §5.4. It rejects forbidden
// control bytes and a body over the request budget.
func authRequestBody(username, password string) ([]byte, *AcquisitionError) {
	if username == "" || password == "" {
		return nil, acquireErr(CodeCredentialUnavailable, PhaseAuth)
	}
	if len(username) > maxUsernameBytes || len(password) > maxPasswordBytes {
		return nil, acquireErr(CodeInvalidConfig, PhaseAuth)
	}
	if hasForbiddenCredentialByte(username) || hasForbiddenCredentialByte(password) {
		return nil, acquireErr(CodeInvalidConfig, PhaseAuth)
	}
	body, err := json.Marshal(authRequest{Username: username, Password: password})
	if err != nil || len(body) > maxAuthRequestBytes {
		// The encoder never returns a partial body; an over-budget body is a
		// configuration failure, not a remote one.
		return nil, acquireErr(CodeInvalidConfig, PhaseAuth)
	}
	return body, nil
}

// parseAuthResponse admits the §5.5 response: one JSON object with exactly the
// string member `token`. Unknown members, duplicates, absent/null/empty/wrong
// type, trailing or truncated content and oversize responses are rejected with
// auth_response_invalid. The token is validated against the §5.2 grammar.
func parseAuthResponse(data []byte) (string, *AcquisitionError) {
	if len(data) == 0 || len(data) > maxAuthResponseBytes {
		return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	open, err := dec.Token()
	if err != nil {
		return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
	}
	if d, ok := open.(json.Delim); !ok || d != '{' {
		return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
	}
	var token string
	seen := false
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
		}
		key, ok := keyTok.(string)
		if !ok || key != "token" || seen {
			return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
		}
		valueTok, err := dec.Token()
		if err != nil {
			return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
		}
		value, ok := valueTok.(string)
		if !ok {
			return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
		}
		token = value
		seen = true
	}
	closeTok, err := dec.Token()
	if err != nil {
		return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
	}
	if d, ok := closeTok.(json.Delim); !ok || d != '}' {
		return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
	}
	if _, err := dec.Token(); err != io.EOF {
		// Any trailing token, truncation or decode error is a rejection.
		return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
	}
	if !seen || token == "" || len(token) > maxTokenBytes || !validBearerToken(token) {
		return "", acquireErr(CodeAuthResponseInvalid, PhaseAuth)
	}
	return token, nil
}

// tokenExpired reports whether a declared expiry has already been reached at
// now (§5.3). A nil expiry means unknown, never "never".
func tokenExpired(expiresAt *time.Time, now time.Time) bool {
	return expiresAt != nil && !now.Before(*expiresAt)
}
