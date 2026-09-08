package management

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
)

func TestMiddlewareCloudflareAccessSSO(t *testing.T) {
	t.Run("accepts verified application token without management key", func(t *testing.T) {
		h := &Handler{
			cfg: &config.Config{RemoteManagement: config.RemoteManagement{
				AllowRemote:      true,
				CloudflareAccess: config.CloudflareAccessSSO{Enabled: true},
			}},
			failedAttempts: make(map[string]*attemptInfo),
			cloudflareAccessVerify: func(_ context.Context, token string) (cloudflareAccessIdentity, error) {
				if token != "valid-access-token" {
					t.Fatalf("token = %q, want valid-access-token", token)
				}
				return cloudflareAccessIdentity{Email: "owner@example.com", Subject: "owner-id"}, nil
			},
		}
		engine := gin.New()
		engine.GET("/v0/management/config", h.Middleware(), func(c *gin.Context) {
			email, _ := c.Get(cloudflareAccessEmailContextKey)
			c.String(http.StatusOK, "%v", email)
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		req.Header.Set("Cf-Access-Jwt-Assertion", "valid-access-token")
		engine.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if got := rec.Body.String(); got != "owner@example.com" {
			t.Fatalf("body = %q, want owner email", got)
		}
		if got := rec.Header().Get("X-CPA-AUTH-MODE"); got != "cloudflare-access" {
			t.Fatalf("X-CPA-AUTH-MODE = %q, want cloudflare-access", got)
		}
	})

	t.Run("accepts application token from authorization cookie when header is absent", func(t *testing.T) {
		h := &Handler{
			cfg: &config.Config{RemoteManagement: config.RemoteManagement{
				AllowRemote:      true,
				CloudflareAccess: config.CloudflareAccessSSO{Enabled: true},
			}},
			failedAttempts: make(map[string]*attemptInfo),
			cloudflareAccessVerify: func(_ context.Context, token string) (cloudflareAccessIdentity, error) {
				if token != "valid-cookie-token" {
					t.Fatalf("token = %q, want valid-cookie-token", token)
				}
				return cloudflareAccessIdentity{Email: "owner@example.com", Subject: "owner-id"}, nil
			},
		}
		engine := gin.New()
		engine.GET("/v0/management/config", h.Middleware(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		req.AddCookie(&http.Cookie{Name: "CF_Authorization", Value: "valid-cookie-token"})
		engine.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("rejects invalid application token without key fallback", func(t *testing.T) {
		h := &Handler{
			cfg: &config.Config{RemoteManagement: config.RemoteManagement{
				CloudflareAccess: config.CloudflareAccessSSO{Enabled: true},
			}},
			failedAttempts: make(map[string]*attemptInfo),
			envSecret:      "emergency-key",
			cloudflareAccessVerify: func(context.Context, string) (cloudflareAccessIdentity, error) {
				return cloudflareAccessIdentity{}, errors.New("bad signature")
			},
		}
		engine := gin.New()
		engine.GET("/v0/management/config", h.Middleware(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		req.Header.Set("Cf-Access-Jwt-Assertion", "invalid-access-token")
		req.Header.Set("X-Management-Key", "emergency-key")
		engine.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("keeps management key as emergency fallback", func(t *testing.T) {
		h := &Handler{
			cfg: &config.Config{RemoteManagement: config.RemoteManagement{
				AllowRemote:      true,
				CloudflareAccess: config.CloudflareAccessSSO{Enabled: true},
			}},
			failedAttempts: make(map[string]*attemptInfo),
			envSecret:      "emergency-key",
		}
		engine := gin.New()
		engine.GET("/v0/management/config", h.Middleware(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		req.Header.Set("X-Management-Key", "emergency-key")
		engine.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})
}

func TestNewCloudflareAccessValidatorRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		teamDomain string
		audience   string
	}{
		{name: "missing domain", audience: "audience"},
		{name: "missing audience", teamDomain: "https://team.cloudflareaccess.com"},
		{name: "non HTTPS domain", teamDomain: "http://team.cloudflareaccess.com", audience: "audience"},
		{name: "relative domain", teamDomain: "team.cloudflareaccess.com", audience: "audience"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newCloudflareAccessValidator(test.teamDomain, test.audience); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}

func TestAuthenticateManagementKey_LocalhostIPBan_BlocksCorrectKeyDuringBan(t *testing.T) {
	h := &Handler{
		cfg:            &config.Config{},
		failedAttempts: make(map[string]*attemptInfo),
		envSecret:      "test-secret",
	}

	for i := 0; i < 5; i++ {
		allowed, statusCode, errMsg := h.AuthenticateManagementKey("127.0.0.1", true, "wrong-secret")
		if allowed {
			t.Fatalf("expected auth to be denied at attempt %d", i+1)
		}
		if statusCode != http.StatusUnauthorized || errMsg != "invalid management key" {
			t.Fatalf("unexpected auth failure at attempt %d: status=%d msg=%q", i+1, statusCode, errMsg)
		}
	}

	allowed, statusCode, errMsg := h.AuthenticateManagementKey("127.0.0.1", true, "test-secret")
	if allowed {
		t.Fatalf("expected correct key to be denied while banned")
	}
	if statusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden status while banned, got %d", statusCode)
	}
	if !strings.HasPrefix(errMsg, "IP banned due to too many failed attempts. Try again in") {
		t.Fatalf("unexpected banned message: %q", errMsg)
	}
}

func TestMiddlewareSetsSupportPluginHeader(t *testing.T) {

	h := &Handler{
		cfg:            &config.Config{},
		failedAttempts: make(map[string]*attemptInfo),
		envSecret:      "test-secret",
	}
	middleware := h.Middleware()

	t.Run("invalid key", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		c.Request.RemoteAddr = "127.0.0.1:12345"
		c.Request.Header.Set("X-Management-Key", "wrong-secret")

		middleware(c)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if got := rec.Header().Get("X-CPA-SUPPORT-PLUGIN"); got != pluginhost.SupportPluginHeaderValue() {
			t.Fatalf("X-CPA-SUPPORT-PLUGIN = %q, want %q", got, pluginhost.SupportPluginHeaderValue())
		}
	})

	t.Run("valid key", func(t *testing.T) {
		engine := gin.New()
		engine.GET("/v0/management/config", middleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Management-Key", "test-secret")
		engine.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if got := rec.Header().Get("X-CPA-SUPPORT-PLUGIN"); got != pluginhost.SupportPluginHeaderValue() {
			t.Fatalf("X-CPA-SUPPORT-PLUGIN = %q, want %q", got, pluginhost.SupportPluginHeaderValue())
		}
	})
}
