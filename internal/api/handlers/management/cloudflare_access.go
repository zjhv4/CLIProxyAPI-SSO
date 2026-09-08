package management

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	cloudflareAccessEmailContextKey   = "cloudflare_access_email"
	cloudflareAccessSubjectContextKey = "cloudflare_access_subject"
)

type cloudflareAccessIdentity struct {
	Email   string
	Subject string
}

type cloudflareAccessClaims struct {
	Email string `json:"email"`
	Type  string `json:"type"`
}

type cloudflareAccessVerifyFunc func(context.Context, string) (cloudflareAccessIdentity, error)

type cloudflareAccessValidator struct {
	verifier *oidc.IDTokenVerifier
}

func newCloudflareAccessValidator(teamDomain string, audience string) (*cloudflareAccessValidator, error) {
	return newCloudflareAccessValidatorWithContext(context.Background(), teamDomain, audience)
}

func newCloudflareAccessValidatorWithContext(ctx context.Context, teamDomain string, audience string) (*cloudflareAccessValidator, error) {
	issuer := strings.TrimRight(strings.TrimSpace(teamDomain), "/")
	audience = strings.TrimSpace(audience)
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("team domain and audience are required")
	}

	issuerURL, errParse := url.Parse(issuer)
	if errParse != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" {
		return nil, fmt.Errorf("team domain must be an absolute HTTPS URL")
	}

	keySet := oidc.NewRemoteKeySet(ctx, issuer+"/cdn-cgi/access/certs")
	verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: []string{oidc.RS256},
	})
	return &cloudflareAccessValidator{verifier: verifier}, nil
}

func (v *cloudflareAccessValidator) Verify(ctx context.Context, rawToken string) (cloudflareAccessIdentity, error) {
	if v == nil || v.verifier == nil {
		return cloudflareAccessIdentity{}, fmt.Errorf("Cloudflare Access verifier is not configured")
	}

	token, errVerify := v.verifier.Verify(ctx, rawToken)
	if errVerify != nil {
		return cloudflareAccessIdentity{}, fmt.Errorf("verify application token: %w", errVerify)
	}

	var claims cloudflareAccessClaims
	if errClaims := token.Claims(&claims); errClaims != nil {
		return cloudflareAccessIdentity{}, fmt.Errorf("decode application token claims: %w", errClaims)
	}
	if claims.Type != "app" {
		return cloudflareAccessIdentity{}, fmt.Errorf("unexpected token type %q", claims.Type)
	}
	email := strings.TrimSpace(claims.Email)
	if email == "" {
		return cloudflareAccessIdentity{}, fmt.Errorf("application token does not contain a user email")
	}

	return cloudflareAccessIdentity{Email: email, Subject: token.Subject}, nil
}

func (h *Handler) cloudflareAccessEnabled() bool {
	return h != nil && h.cfg != nil && h.cfg.RemoteManagement.CloudflareAccess.Enabled
}

func (h *Handler) verifyCloudflareAccess(ctx context.Context, rawToken string) (cloudflareAccessIdentity, error) {
	if h == nil || h.cfg == nil {
		return cloudflareAccessIdentity{}, fmt.Errorf("Cloudflare Access is not configured")
	}
	if h.cloudflareAccessVerify != nil {
		return h.cloudflareAccessVerify(ctx, rawToken)
	}

	accessConfig := h.cfg.RemoteManagement.CloudflareAccess
	cacheKey := strings.TrimRight(strings.TrimSpace(accessConfig.TeamDomain), "/") + "\x00" + strings.TrimSpace(accessConfig.Audience)

	h.cloudflareAccessMu.Lock()
	if h.cloudflareAccess == nil || h.cloudflareAccessKey != cacheKey {
		validator, errValidator := newCloudflareAccessValidator(accessConfig.TeamDomain, accessConfig.Audience)
		if errValidator != nil {
			h.cloudflareAccessMu.Unlock()
			return cloudflareAccessIdentity{}, errValidator
		}
		h.cloudflareAccess = validator
		h.cloudflareAccessKey = cacheKey
	}
	validator := h.cloudflareAccess
	h.cloudflareAccessMu.Unlock()

	return validator.Verify(ctx, rawToken)
}
