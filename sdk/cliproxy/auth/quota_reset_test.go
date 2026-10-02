package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func codexSignalAuth(id string, observedAt time.Time, primaryUsed, primaryResetAfter, secondaryUsed, secondaryResetAfter string) *Auth {
	signals := map[string]string{}
	if primaryResetAfter != "" {
		signals["X-Codex-Primary-Used-Percent"] = primaryUsed
		signals["X-Codex-Primary-Window-Minutes"] = "300"
		signals["X-Codex-Primary-Reset-After-Seconds"] = primaryResetAfter
	}
	if secondaryResetAfter != "" {
		signals["X-Codex-Secondary-Used-Percent"] = secondaryUsed
		signals["X-Codex-Secondary-Window-Minutes"] = "10080"
		signals["X-Codex-Secondary-Reset-After-Seconds"] = secondaryResetAfter
	}
	return &Auth{ID: id, Provider: "codex", Quota: QuotaState{ObservedAt: observedAt, Signals: signals}}
}

func claudeSignalAuth(id string, observedAt time.Time, util5h string, reset5h time.Time, util7d string, reset7d time.Time) *Auth {
	return &Auth{ID: id, Provider: "claude", Quota: QuotaState{ObservedAt: observedAt, Signals: map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization": util5h,
		"Anthropic-Ratelimit-Unified-5h-Reset":       strconv.FormatInt(reset5h.Unix(), 10),
		"Anthropic-Ratelimit-Unified-7d-Utilization": util7d,
		"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(reset7d.Unix(), 10),
		"Anthropic-Ratelimit-Unified-Status":         "allowed",
	}}}
}

func TestEffectiveReset_CodexRelativeWindows(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	observed := now.Add(-5 * time.Minute)
	auth := codexSignalAuth("codex-a", observed, "40", "3600", "70", "86400")

	resetAt, used, known := effectiveReset(auth, "gpt-5", SoonestResetConfig{}, now)
	if !known {
		t.Fatalf("auto: known = false, want true")
	}
	// auto picks the window with the higher used-percent: secondary (70%).
	if want := observed.Add(86400 * time.Second); !resetAt.Equal(want) {
		t.Fatalf("auto: resetAt = %v, want %v", resetAt, want)
	}
	if used != 70 {
		t.Fatalf("auto: usedPercent = %v, want 70", used)
	}

	resetAt, used, known = effectiveReset(auth, "gpt-5", SoonestResetConfig{Window: "primary"}, now)
	if !known || used != 40 || !resetAt.Equal(observed.Add(time.Hour)) {
		t.Fatalf("primary: got (%v, %v, %v)", resetAt, used, known)
	}
	resetAt, used, known = effectiveReset(auth, "gpt-5", SoonestResetConfig{Window: "secondary"}, now)
	if !known || used != 70 || !resetAt.Equal(observed.Add(24*time.Hour)) {
		t.Fatalf("secondary: got (%v, %v, %v)", resetAt, used, known)
	}
}

func TestEffectiveReset_CodexAbsoluteResetAt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	epoch := now.Add(90 * time.Minute)
	auth := &Auth{ID: "codex-ws", Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Primary-Used-Percent": "12.5",
		"X-Codex-Primary-Reset-At":     strconv.FormatInt(epoch.Unix(), 10),
	}}}
	resetAt, used, known := effectiveReset(auth, "", SoonestResetConfig{}, now)
	if !known || used != 12.5 || !resetAt.Equal(epoch) {
		t.Fatalf("epoch reset-at: got (%v, %v, %v), want (%v, 12.5, true)", resetAt, used, known, epoch)
	}

	auth.Quota.Signals["X-Codex-Primary-Reset-At"] = epoch.Format(time.RFC3339)
	resetAt, _, known = effectiveReset(auth, "", SoonestResetConfig{}, now)
	if !known || !resetAt.Equal(epoch) {
		t.Fatalf("rfc3339 reset-at: got (%v, %v), want (%v, true)", resetAt, known, epoch)
	}

	// Relative reset wins over absolute when both are present.
	auth.Quota.Signals["X-Codex-Primary-Reset-After-Seconds"] = "60"
	resetAt, _, known = effectiveReset(auth, "", SoonestResetConfig{}, now)
	if !known || !resetAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("relative precedence: got (%v, %v)", resetAt, known)
	}
}

func TestEffectiveReset_CodexExhaustedWindowSkipped(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	// Primary is exhausted (97%) and resets soon; secondary is the only usable window.
	auth := codexSignalAuth("codex-x", now, "97", "600", "30", "86400")
	resetAt, used, known := effectiveReset(auth, "", SoonestResetConfig{}, now)
	if !known || used != 30 || !resetAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("skip primary: got (%v, %v, %v)", resetAt, used, known)
	}

	// Lower threshold makes both exhausted: unknown, with resetAt/usedPercent describing the
	// window that keeps the credential blocked longest.
	resetAt, used, known = effectiveReset(auth, "", SoonestResetConfig{SkipExhaustedAbove: 25}, now)
	if known {
		t.Fatalf("all exhausted: known = true, want false")
	}
	if used != 30 || !resetAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("all exhausted: got (%v, %v), want (%v, 30)", resetAt, used, now.Add(24*time.Hour))
	}

	// Explicit window on an exhausted window is also unknown.
	if _, _, known = effectiveReset(auth, "", SoonestResetConfig{Window: "primary"}, now); known {
		t.Fatalf("primary exhausted: known = true, want false")
	}
}

func TestEffectiveReset_StaleAndMissingSignals(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

	stale := codexSignalAuth("stale", now.Add(-31*time.Minute), "10", "3600", "", "")
	if _, _, known := effectiveReset(stale, "", SoonestResetConfig{}, now); known {
		t.Fatalf("stale default: known = true, want false")
	}
	if _, _, known := effectiveReset(stale, "", SoonestResetConfig{StaleAfter: time.Hour}, now); !known {
		t.Fatalf("stale custom: known = false, want true")
	}

	passed := codexSignalAuth("passed", now.Add(-10*time.Minute), "80", "60", "", "")
	if _, _, known := effectiveReset(passed, "", SoonestResetConfig{}, now); known {
		t.Fatalf("reset already passed: known = true, want false")
	}

	empty := &Auth{ID: "empty", Provider: "codex"}
	if _, used, known := effectiveReset(empty, "", SoonestResetConfig{}, now); known || used != 0 {
		t.Fatalf("no signals: got (%v, %v), want (0, false)", used, known)
	}

	garbage := &Auth{ID: "garbage", Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Primary-Reset-After-Seconds": "soon",
		"X-Codex-Primary-Reset-At":            "tomorrow",
	}}}
	if _, _, known := effectiveReset(garbage, "", SoonestResetConfig{}, now); known {
		t.Fatalf("unparseable: known = true, want false")
	}
	if _, _, known := effectiveReset(nil, "", SoonestResetConfig{}, now); known {
		t.Fatalf("nil auth: known = true, want false")
	}
}

func TestEffectiveReset_ClaudeWindows(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	reset5h := now.Add(2 * time.Hour)
	reset7d := now.Add(3 * 24 * time.Hour)
	auth := claudeSignalAuth("claude-a", now.Add(-time.Minute), "0.25", reset5h, "0.60", reset7d)

	resetAt, used, known := effectiveReset(auth, "claude-sonnet-4-5", SoonestResetConfig{}, now)
	if !known || used != 60 || !resetAt.Equal(reset7d) {
		t.Fatalf("auto: got (%v, %v, %v), want (%v, 60, true)", resetAt, used, known, reset7d)
	}
	resetAt, used, known = effectiveReset(auth, "", SoonestResetConfig{Window: "primary"}, now)
	if !known || used != 25 || !resetAt.Equal(reset5h) {
		t.Fatalf("primary: got (%v, %v, %v)", resetAt, used, known)
	}

	// Utilization already expressed as a percentage is accepted as-is.
	auth.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Utilization"] = "85"
	auth.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.1"
	resetAt, used, known = effectiveReset(auth, "", SoonestResetConfig{}, now)
	if !known || used != 85 || !resetAt.Equal(reset5h) {
		t.Fatalf("percent util: got (%v, %v, %v)", resetAt, used, known)
	}

	// 5h at 1.0 (100%) is exhausted; auto falls through to the 7d window.
	auth.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Utilization"] = "1.0"
	resetAt, used, known = effectiveReset(auth, "", SoonestResetConfig{}, now)
	if !known || used != 10 || !resetAt.Equal(reset7d) {
		t.Fatalf("exhausted 5h: got (%v, %v, %v)", resetAt, used, known)
	}
}

func TestEffectiveReset_PrefersModelStateSignals(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	auth := codexSignalAuth("codex-m", now, "10", "7200", "", "")
	auth.ModelStates = map[string]*ModelState{
		"gpt-5": {Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
			"X-Codex-Primary-Used-Percent":        "50",
			"X-Codex-Primary-Reset-After-Seconds": "600",
		}}},
		"gpt-5-mini": {Quota: QuotaState{}},
	}
	resetAt, used, known := effectiveReset(auth, "gpt-5", SoonestResetConfig{}, now)
	if !known || used != 50 || !resetAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("model state: got (%v, %v, %v)", resetAt, used, known)
	}
	// Thinking suffix resolves to the same model state.
	if resetAt, _, known = effectiveReset(auth, "gpt-5(high)", SoonestResetConfig{}, now); !known || !resetAt.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("model state via suffix: got (%v, %v)", resetAt, known)
	}
	// A model state without signals falls back to the credential snapshot.
	if resetAt, used, known = effectiveReset(auth, "gpt-5-mini", SoonestResetConfig{}, now); !known || used != 10 || !resetAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("fallback to auth quota: got (%v, %v, %v)", resetAt, used, known)
	}
}

func TestSoonestResetSelectorPick_OrdersKnownBeforeUnknownLast(t *testing.T) {
	t.Parallel()
	now := time.Now()
	auths := []*Auth{
		{ID: "unknown-a", Provider: "codex"},
		codexSignalAuth("far", now, "10", "7200", "", ""),
		codexSignalAuth("soon", now, "10", "600", "", ""),
		codexSignalAuth("exhausted", now, "99", "60", "", ""),
	}
	selector := NewSoonestResetSelector(SoonestResetConfig{UnknownPolicy: "last"})
	got, err := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "soon" {
		t.Fatalf("Pick() = %q, want soon", got.ID)
	}

	// Remove known candidates: unknown precedes exhausted.
	got, err = selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, []*Auth{auths[3], auths[0]})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "unknown-a" {
		t.Fatalf("Pick() = %q, want unknown-a", got.ID)
	}

	// Only exhausted candidates: earliest reset first.
	later := codexSignalAuth("exhausted-later", now, "99", "3600", "", "")
	got, err = selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, []*Auth{later, auths[3]})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "exhausted" {
		t.Fatalf("Pick() = %q, want exhausted", got.ID)
	}
}

func TestSoonestResetSelectorPick_ProbeRotatesUnknownsFirst(t *testing.T) {
	t.Parallel()
	now := time.Now()
	auths := []*Auth{
		codexSignalAuth("soon", now, "10", "600", "", ""),
		{ID: "unknown-b", Provider: "codex"},
		{ID: "unknown-a", Provider: "codex"},
	}
	selector := NewSoonestResetSelector(SoonestResetConfig{})
	want := []string{"unknown-a", "unknown-b", "unknown-a"}
	for i, id := range want {
		got, err := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() #%d error = %v", i, err)
		}
		if got.ID != id {
			t.Fatalf("Pick() #%d = %q, want %q", i, got.ID, id)
		}
	}

	// Once every credential has a known reset, the soonest one wins.
	auths[1] = codexSignalAuth("unknown-b", now, "10", "3600", "", "")
	auths[2] = codexSignalAuth("unknown-a", now, "10", "7200", "", "")
	got, err := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "soon" {
		t.Fatalf("Pick() = %q, want soon", got.ID)
	}
}

func TestSoonestResetSelectorPick_TieBreakAndFiltering(t *testing.T) {
	t.Parallel()
	now := time.Now()
	auths := []*Auth{
		codexSignalAuth("b", now, "10", "600", "", ""),
		codexSignalAuth("a", now, "10", "600", "", ""),
		codexSignalAuth("c", now, "10", "600", "", ""),
	}
	selector := NewSoonestResetSelector(SoonestResetConfig{})
	got, err := selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "a" {
		t.Fatalf("tie-break Pick() = %q, want a", got.ID)
	}

	// Cooldown filtering is unchanged: a cooling credential is never picked.
	auths[1].Quota.Exceeded = true
	auths[1].Quota.Reason = "credential_quota"
	auths[1].Quota.NextRecoverAt = now.Add(time.Hour)
	got, err = selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "b" {
		t.Fatalf("cooldown Pick() = %q, want b", got.ID)
	}

	// Priority tiers still win over reset ordering.
	auths[2].Attributes = map[string]string{"priority": "10"}
	got, err = selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "c" {
		t.Fatalf("priority Pick() = %q, want c", got.ID)
	}

	if _, err = selector.Pick(context.Background(), "codex", "gpt-5", cliproxyexecutor.Options{}, nil); err == nil {
		t.Fatalf("Pick() with no auths returned nil error")
	}
}

func TestSoonestResetSelectorIsNotBuiltIn(t *testing.T) {
	t.Parallel()
	if isBuiltInSelector(NewSoonestResetSelector(SoonestResetConfig{})) {
		t.Fatalf("SoonestResetSelector must use the custom Pick path")
	}
	if selectorStrategy(NewSoonestResetSelector(SoonestResetConfig{})) != schedulerStrategyCustom {
		t.Fatalf("SoonestResetSelector must map to the custom scheduler strategy")
	}
}
