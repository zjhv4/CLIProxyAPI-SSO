package management

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestCloudflareAccessValidatorVerifiesApplicationJWT(t *testing.T) {
	privateKey, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("generate RSA key: %v", errKey)
	}

	const keyID = "access-test-key"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": keyID,
				"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			}},
		})
	}))
	defer server.Close()

	ctx := oidc.ClientContext(context.Background(), server.Client())
	validator, errValidator := newCloudflareAccessValidatorWithContext(ctx, server.URL, "management-audience")
	if errValidator != nil {
		t.Fatalf("create validator: %v", errValidator)
	}

	validToken := signAccessTestJWT(t, privateKey, keyID, map[string]any{
		"iss":   server.URL,
		"aud":   []string{"management-audience"},
		"sub":   "owner-id",
		"email": "owner@example.com",
		"type":  "app",
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	identity, errVerify := validator.Verify(context.Background(), validToken)
	if errVerify != nil {
		t.Fatalf("verify valid token: %v", errVerify)
	}
	if identity.Email != "owner@example.com" || identity.Subject != "owner-id" {
		t.Fatalf("identity = %+v, want owner identity", identity)
	}

	wrongAudienceToken := signAccessTestJWT(t, privateKey, keyID, map[string]any{
		"iss":   server.URL,
		"aud":   []string{"different-application"},
		"sub":   "owner-id",
		"email": "owner@example.com",
		"type":  "app",
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if _, errVerify = validator.Verify(context.Background(), wrongAudienceToken); errVerify == nil {
		t.Fatal("expected wrong audience to be rejected")
	}

	serviceToken := signAccessTestJWT(t, privateKey, keyID, map[string]any{
		"iss":  server.URL,
		"aud":  []string{"management-audience"},
		"sub":  "",
		"type": "app",
		"iat":  time.Now().Add(-time.Minute).Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	if _, errVerify = validator.Verify(context.Background(), serviceToken); errVerify == nil {
		t.Fatal("expected token without user email to be rejected")
	}
}

func signAccessTestJWT(t *testing.T, privateKey *rsa.PrivateKey, keyID string, claims map[string]any) string {
	t.Helper()
	headerJSON, errHeader := json.Marshal(map[string]string{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	if errHeader != nil {
		t.Fatalf("marshal JWT header: %v", errHeader)
	}
	claimsJSON, errClaims := json.Marshal(claims)
	if errClaims != nil {
		t.Fatalf("marshal JWT claims: %v", errClaims)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := fmt.Sprintf("%s.%s", encodedHeader, encodedClaims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, errSign := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if errSign != nil {
		t.Fatalf("sign JWT: %v", errSign)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
