package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigCloudflareAccessEnvironmentOverride(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if errWrite := os.WriteFile(configPath, []byte("port: 8317\n"), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}
	t.Setenv("MANAGEMENT_CLOUDFLARE_ACCESS_TEAM_DOMAIN", " team.cloudflareaccess.com/ ")
	t.Setenv("MANAGEMENT_CLOUDFLARE_ACCESS_AUDIENCE", " management-audience ")

	cfg, errLoad := LoadConfig(configPath)
	if errLoad != nil {
		t.Fatalf("load config: %v", errLoad)
	}
	access := cfg.RemoteManagement.CloudflareAccess
	if !access.Enabled {
		t.Fatal("Cloudflare Access SSO was not enabled")
	}
	if access.TeamDomain != "https://team.cloudflareaccess.com" {
		t.Fatalf("team domain = %q", access.TeamDomain)
	}
	if access.Audience != "management-audience" {
		t.Fatalf("audience = %q", access.Audience)
	}
}

func TestLoadConfigCloudflareAccessEnvironmentRequiresBothValues(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if errWrite := os.WriteFile(configPath, []byte("port: 8317\n"), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}
	t.Setenv("MANAGEMENT_CLOUDFLARE_ACCESS_TEAM_DOMAIN", "https://team.cloudflareaccess.com")
	t.Setenv("MANAGEMENT_CLOUDFLARE_ACCESS_AUDIENCE", "")

	if _, errLoad := LoadConfig(configPath); errLoad == nil {
		t.Fatal("expected incomplete Cloudflare Access environment configuration to fail")
	}
}
