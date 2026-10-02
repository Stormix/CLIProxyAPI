package cliproxy

import (
	"context"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"gopkg.in/yaml.v3"
)

func TestSoonestResetRoutingSelector_ParsesStrategyAndBlock(t *testing.T) {
	raw := []byte(`
routing:
  strategy: soonest-reset
  soonest-reset:
    window: secondary
    skip-exhausted-above: 80
    stale-after: "15m"
    unknown-policy: last
`)
	var cfg internalconfig.Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	state := normalizedRoutingRuntimeState(&cfg)
	if state.strategy != "soonest-reset" {
		t.Fatalf("strategy = %q, want soonest-reset", state.strategy)
	}
	want := coreauth.SoonestResetConfig{
		Window:             "secondary",
		SkipExhaustedAbove: 80,
		StaleAfter:         15 * time.Minute,
		UnknownPolicy:      "last",
	}
	if state.soonestReset != want {
		t.Fatalf("soonestReset = %+v, want %+v", state.soonestReset, want)
	}
	if _, ok := newRoutingSelector(state).(*coreauth.SoonestResetSelector); !ok {
		t.Fatalf("selector type = %T, want *auth.SoonestResetSelector", newRoutingSelector(state))
	}

	for _, alias := range []string{"sr", "SoonestReset", " soonest-reset "} {
		aliasState := normalizedRoutingRuntimeState(&internalconfig.Config{Routing: internalconfig.RoutingConfig{Strategy: alias}})
		if aliasState.strategy != "soonest-reset" {
			t.Fatalf("alias %q: strategy = %q, want soonest-reset", alias, aliasState.strategy)
		}
		if aliasState.soonestReset != (coreauth.SoonestResetConfig{}) {
			t.Fatalf("alias %q: expected zero config, got %+v", alias, aliasState.soonestReset)
		}
	}

	// Other strategies ignore the block, so a config reload only rebuilds the selector
	// when the active strategy depends on it.
	cfg.Routing.Strategy = "fill-first"
	if other := normalizedRoutingRuntimeState(&cfg); other.soonestReset != (coreauth.SoonestResetConfig{}) {
		t.Fatalf("fill-first carried soonest-reset config: %+v", other.soonestReset)
	}
}

func TestSoonestResetRoutingSelector_WrappedBySessionAffinity(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{Routing: internalconfig.RoutingConfig{
		Strategy:        "soonest-reset",
		SessionAffinity: true,
	}})
	selector := newRoutingSelector(state)
	affinity, ok := selector.(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.SessionAffinitySelector", selector)
	}
	defer affinity.Stop()

	now := time.Now()
	codexAuth := func(id string, resetAfter string) *coreauth.Auth {
		return &coreauth.Auth{ID: id, Provider: "codex", Quota: coreauth.QuotaState{ObservedAt: now, Signals: map[string]string{
			"X-Codex-Primary-Used-Percent":        "10",
			"X-Codex-Primary-Reset-After-Seconds": resetAfter,
		}}}
	}
	far := codexAuth("far", "7200")
	soon := codexAuth("soon", "600")
	auths := []*coreauth.Auth{far, soon}
	session := func(id string) cliproxyexecutor.Options {
		return cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.DerivedSessionIDMetadataKey: id}}
	}

	got, err := affinity.Pick(context.Background(), "codex", "gpt-5", session("s1"), auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "soon" {
		t.Fatalf("cold Pick() = %q, want soon", got.ID)
	}

	// The soonest reset moves to "far"; the established session stays bound to "soon"
	// while a new session follows the fallback ordering.
	far.Quota.Signals["X-Codex-Primary-Reset-After-Seconds"] = "60"
	got, err = affinity.Pick(context.Background(), "codex", "gpt-5", session("s1"), auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "soon" {
		t.Fatalf("bound Pick() = %q, want soon", got.ID)
	}
	got, err = affinity.Pick(context.Background(), "codex", "gpt-5", session("s2"), auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "far" {
		t.Fatalf("new session Pick() = %q, want far", got.ID)
	}
}
