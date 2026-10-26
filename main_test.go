package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestServer() *authorizationServer {
	return &authorizationServer{
		externalURL: "http://test.example",
		authCodes:   make(map[string]codeEntry),
		tokens:      make(map[string]tokenEntry),
	}
}

func TestDiscovery_BothWellKnownPathsReturnSamePayload(t *testing.T) {
	s := newTestServer()

	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			s.handleDiscovery(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}

			var body map[string]any
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}

			if got := body["issuer"]; got != "http://test.example" {
				t.Errorf("issuer = %v, want http://test.example", got)
			}
			if got := body["authorization_endpoint"]; got != "http://test.example/authorize" {
				t.Errorf("authorization_endpoint = %v", got)
			}
			if got := body["token_endpoint"]; got != "http://test.example/token" {
				t.Errorf("token_endpoint = %v", got)
			}
			if got := body["jwks_uri"]; got != "http://test.example/jwks" {
				t.Errorf("jwks_uri = %v", got)
			}

			grants, _ := body["grant_types_supported"].([]any)
			if len(grants) != 1 || grants[0] != "authorization_code" {
				t.Errorf("grant_types_supported = %v, want [authorization_code]", grants)
			}

			responseTypes, _ := body["response_types_supported"].([]any)
			if len(responseTypes) != 1 || responseTypes[0] != "code" {
				t.Errorf("response_types_supported = %v, want [code]", responseTypes)
			}
		})
	}
}

func TestJWKS_ReturnsEmptyKeyset(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	w := httptest.NewRecorder()
	s.handleJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	keys, ok := body["keys"].([]any)
	if !ok {
		t.Fatalf("keys field missing or wrong type")
	}
	if len(keys) != 0 {
		t.Errorf("keys = %v, want []", keys)
	}
}

func TestAuthorize_NoRedirectURI_ReturnsJSON(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/authorize?state=client-state-123&issuer_state=issuer-state-456", nil)
	w := httptest.NewRecorder()
	s.handleAuthorize(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["state"] != "client-state-123" {
		t.Errorf("state = %q, want client-state-123", body["state"])
	}
	code := body["code"]
	if code == "" {
		t.Fatalf("code is empty")
	}

	entry, ok := s.authCodes[code]
	if !ok {
		t.Fatalf("code %q was not stored in authCodes", code)
	}
	if entry.issuerState != "issuer-state-456" {
		t.Errorf("stored issuerState = %q, want issuer-state-456", entry.issuerState)
	}
	if entry.clientState != "client-state-123" {
		t.Errorf("stored clientState = %q, want client-state-123", entry.clientState)
	}
}

func TestAuthorize_WithRedirectURI_Returns302(t *testing.T) {
	s := newTestServer()
	q := url.Values{}
	q.Set("redirect_uri", "https://wallet.example/cb")
	q.Set("state", "client-state")
	q.Set("issuer_state", "my-issuer-state")
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	s.handleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", w.Code, w.Body.String())
	}

	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatalf("Location header missing")
	}

	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	if parsed.Scheme != "https" || parsed.Host != "wallet.example" || parsed.Path != "/cb" {
		t.Errorf("Location target = %q, want https://wallet.example/cb", loc)
	}
	if got := parsed.Query().Get("state"); got != "client-state" {
		t.Errorf("state in Location = %q, want client-state", got)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("code missing from Location query")
	}

	entry, ok := s.authCodes[code]
	if !ok {
		t.Fatalf("code %q was not stored in authCodes", code)
	}
	if entry.issuerState != "my-issuer-state" {
		t.Errorf("stored issuerState = %q, want my-issuer-state", entry.issuerState)
	}
}

func TestAuthorize_RedirectURI_PreservesExistingQueryParams(t *testing.T) {
	s := newTestServer()
	q := url.Values{}
	// Wallets may pass a redirect_uri that already has query params (e.g. session-correlation).
	q.Set("redirect_uri", "https://wallet.example/cb?session=abc")
	q.Set("state", "cs")
	q.Set("issuer_state", "is")
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	s.handleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	parsed, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	if got := parsed.Query().Get("session"); got != "abc" {
		t.Errorf("existing query param session = %q, want abc", got)
	}
	if got := parsed.Query().Get("state"); got != "cs" {
		t.Errorf("state = %q, want cs", got)
	}
	if parsed.Query().Get("code") == "" {
		t.Errorf("code missing from Location query")
	}
}

func TestAuthorize_InvalidRedirectURI_Returns400(t *testing.T) {
	s := newTestServer()
	// Unclosed IPv6 bracket — Go's url.Parse rejects this.
	req := httptest.NewRequest(http.MethodGet, "/authorize?redirect_uri=http://[::1&state=x&issuer_state=y", nil)
	w := httptest.NewRecorder()
	s.handleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestToken_ExchangesCodeForToken(t *testing.T) {
	s := newTestServer()

	// First, /authorize to mint a code.
	authReq := httptest.NewRequest(http.MethodGet, "/authorize?state=cs&issuer_state=my-issuer-state", nil)
	authW := httptest.NewRecorder()
	s.handleAuthorize(authW, authReq)
	var authResp map[string]string
	_ = json.NewDecoder(authW.Body).Decode(&authResp)
	code := authResp["code"]
	if code == "" {
		t.Fatalf("/authorize did not return a code")
	}

	// Exchange the code for a token.
	form := url.Values{"code": {code}}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenW := httptest.NewRecorder()
	s.handleToken(tokenW, tokenReq)

	if tokenW.Code != http.StatusOK {
		t.Fatalf("/token status = %d, want 200; body=%s", tokenW.Code, tokenW.Body.String())
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(tokenW.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode /token body: %v", err)
	}
	if tokenResp["token_type"] != "bearer" {
		t.Errorf("token_type = %v, want bearer", tokenResp["token_type"])
	}
	token, ok := tokenResp["access_token"].(string)
	if !ok || token == "" {
		t.Fatalf("access_token missing or empty: %v", tokenResp["access_token"])
	}

	// Code is consumed.
	if _, ok := s.authCodes[code]; ok {
		t.Errorf("code was not deleted from authCodes after exchange")
	}

	// Token maps back to the same issuer_state.
	entry, ok := s.tokens[token]
	if !ok {
		t.Fatalf("token %q was not stored", token)
	}
	if entry.issuerState != "my-issuer-state" {
		t.Errorf("token's issuerState = %q, want my-issuer-state", entry.issuerState)
	}
}

func TestToken_InvalidCode_Returns400(t *testing.T) {
	s := newTestServer()
	form := url.Values{"code": {"does-not-exist"}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}

	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", body["error"])
	}
}

func TestToken_CodeIsOneTimeUse(t *testing.T) {
	s := newTestServer()
	authReq := httptest.NewRequest(http.MethodGet, "/authorize?state=cs&issuer_state=is", nil)
	authW := httptest.NewRecorder()
	s.handleAuthorize(authW, authReq)
	var authResp map[string]string
	_ = json.NewDecoder(authW.Body).Decode(&authResp)
	code := authResp["code"]

	form := url.Values{"code": {code}}

	// First exchange succeeds.
	firstReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	firstReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	firstW := httptest.NewRecorder()
	s.handleToken(firstW, firstReq)
	if firstW.Code != http.StatusOK {
		t.Fatalf("first /token = %d, want 200", firstW.Code)
	}

	// Second exchange with the same code fails.
	secondReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	secondReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	secondW := httptest.NewRecorder()
	s.handleToken(secondW, secondReq)
	if secondW.Code != http.StatusBadRequest {
		t.Errorf("second /token = %d, want 400 (code already used)", secondW.Code)
	}
}

func TestIntrospect_KnownToken_ReturnsIssuerStateAndUserInfo(t *testing.T) {
	s := newTestServer()

	// Provision a token via the full /authorize → /token flow.
	authReq := httptest.NewRequest(http.MethodGet, "/authorize?state=cs&issuer_state=preserved-issuer-state", nil)
	authW := httptest.NewRecorder()
	s.handleAuthorize(authW, authReq)
	var authResp map[string]string
	_ = json.NewDecoder(authW.Body).Decode(&authResp)

	tokenForm := url.Values{"code": {authResp["code"]}}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenW := httptest.NewRecorder()
	s.handleToken(tokenW, tokenReq)
	var tokenResp map[string]any
	_ = json.NewDecoder(tokenW.Body).Decode(&tokenResp)
	token := tokenResp["access_token"].(string)

	// Introspect.
	form := url.Values{"access-token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleIntrospect(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	tokenDetails, ok := body["token_details"].(map[string]any)
	if !ok {
		t.Fatalf("token_details missing or wrong type: %v", body["token_details"])
	}
	if tokenDetails["issuer_state"] != "preserved-issuer-state" {
		t.Errorf("issuer_state = %v, want preserved-issuer-state", tokenDetails["issuer_state"])
	}
	if tokenDetails["active"] != true {
		t.Errorf("active = %v, want true", tokenDetails["active"])
	}

	userInfo, ok := body["user_info"].(map[string]any)
	if !ok {
		t.Fatalf("user_info missing or wrong type")
	}
	if userInfo["sub"] != "test-user" {
		t.Errorf("user_info.sub = %v, want test-user", userInfo["sub"])
	}
}

func TestIntrospect_UnknownToken_ReturnsEmpty(t *testing.T) {
	s := newTestServer()
	form := url.Values{"access-token": {"not-a-real-token"}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleIntrospect(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "{}" {
		t.Errorf("body = %q, want {}", got)
	}
}

func TestIntrospect_EmptyToken_ReturnsEmpty(t *testing.T) {
	s := newTestServer()
	form := url.Values{"access-token": {""}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleIntrospect(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "{}" {
		t.Errorf("body = %q, want {}", got)
	}
}

func TestToken_MalformedForm_Returns400(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("code=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}

	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
}

func TestIntrospect_MalformedForm_Returns400(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader("access-token=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleIntrospect(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}

	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
}
