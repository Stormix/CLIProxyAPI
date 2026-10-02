package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigOptional_CodexHeaderDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
codex-header-defaults:
  user-agent: "  my-codex-client/1.0  "
  beta-features: "  feature-a,feature-b  "
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}

	if got := cfg.CodexHeaderDefaults.UserAgent; got != "my-codex-client/1.0" {
		t.Fatalf("UserAgent = %q, want %q", got, "my-codex-client/1.0")
	}
	if got := cfg.CodexHeaderDefaults.BetaFeatures; got != "feature-a,feature-b" {
		t.Fatalf("BetaFeatures = %q, want %q", got, "feature-a,feature-b")
	}
	if cfg.Codex.DisableCodexCloaking {
		t.Fatal("DisableCodexCloaking = true, want default false")
	}
}

func TestLoadConfigOptional_CodexOptions(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
codex:
  disable-codex-cloaking: true
  optimize-multi-agent-v2: true
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}

	if !cfg.Codex.DisableCodexCloaking {
		t.Fatal("DisableCodexCloaking = false, want true")
	}
	if !cfg.Client.Codex.OptimizeMultiAgentV2 {
		t.Fatalf("OptimizeMultiAgentV2 = false, want true")
	}
}

func TestLoadConfigOptional_CodexModelLevelCooling(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := []byte(`
codex:
  model-level-cooling: true
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cfg, err := LoadConfigOptional(configPath, false)
	if err != nil {
		t.Fatalf("LoadConfigOptional() error = %v", err)
	}

	if !cfg.Codex.ModelLevelCooling {
		t.Fatalf("ModelLevelCooling = false, want true")
	}

	defaultCfg, errDefault := ParseConfigBytes([]byte(`{}`))
	if errDefault != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errDefault)
	}
	if defaultCfg.Codex.ModelLevelCooling {
		t.Fatalf("default ModelLevelCooling = true, want false")
	}
}

func TestLoadConfigOptional_CodexWebsocketsForHTTPClients(t *testing.T) {
	for name, configYAML := range map[string]string{
		"legacy": "codex:\n  websockets-for-http-clients: true\n",
		"v8":     "oauth:\n  providers:\n    codex:\n      websockets-for-http-clients: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
				t.Fatalf("failed to write config: %v", err)
			}
			cfg, err := LoadConfigOptional(configPath, false)
			if err != nil {
				t.Fatalf("LoadConfigOptional() error = %v", err)
			}
			if !cfg.Codex.WebsocketsForHTTPClients {
				t.Fatal("WebsocketsForHTTPClients = false, want true")
			}
		})
	}

	defaultCfg, errDefault := ParseConfigBytes([]byte(`{}`))
	if errDefault != nil {
		t.Fatalf("ParseConfigBytes() error = %v", errDefault)
	}
	if defaultCfg.Codex.WebsocketsForHTTPClients {
		t.Fatal("default WebsocketsForHTTPClients = true, want false")
	}
}
