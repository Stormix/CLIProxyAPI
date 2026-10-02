package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func sessionOpts(sessionID string) cliproxyexecutor.Options {
	return cliproxyexecutor.Options{
		Headers:         http.Header{"X-Claude-Code-Session-Id": []string{sessionID}},
		OriginalRequest: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		Metadata:        map[string]any{},
	}
}

func TestSessionAffinityScopeKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope SessionAffinityScope
		want  string
	}{
		{name: "default session-model", scope: "", want: "claude::sess::model-a"},
		{name: "explicit session-model", scope: SessionAffinityScopeSessionModel, want: "claude::sess::model-a"},
		{name: "session", scope: SessionAffinityScopeSession, want: "claude::sess"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Scope: tt.scope})
			defer selector.Stop()
			if got := selector.cacheKey("claude", "sess", "model-a"); got != tt.want {
				t.Fatalf("cacheKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// With scope=session a thread keeps one credential across models; with the default
// scope each model binds independently (upstream behaviour).
func TestSessionAffinityScopeSessionBindsAcrossModels(t *testing.T) {
	t.Parallel()

	for _, scope := range []SessionAffinityScope{SessionAffinityScopeSessionModel, SessionAffinityScopeSession} {
		t.Run(string(scope), func(t *testing.T) {
			t.Parallel()
			selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
				Fallback: &RoundRobinSelector{},
				TTL:      time.Minute,
				Scope:    scope,
			})
			defer selector.Stop()
			auths := []*Auth{
				{ID: "auth-1", Provider: "claude", Status: StatusActive},
				{ID: "auth-2", Provider: "claude", Status: StatusActive},
			}
			first, err := selector.Pick(context.Background(), "claude", "model-a", sessionOpts("thread-1"), auths)
			if err != nil {
				t.Fatalf("Pick(model-a) error = %v", err)
			}
			// Before any model-b request, the model-a binding only applies to model-b under scope=session.
			wantStatus := "unbound"
			if scope == SessionAffinityScopeSession {
				wantStatus = "bound"
			}
			if _, status := selector.LookupAffinity("claude", "model-b", "thread-1"); status != wantStatus {
				t.Fatalf("LookupAffinity(model-b) status = %q, want %q", status, wantStatus)
			}
			if scope != SessionAffinityScopeSession {
				return
			}
			second, err := selector.Pick(context.Background(), "claude", "model-b", sessionOpts("thread-1"), auths)
			if err != nil {
				t.Fatalf("Pick(model-b) error = %v", err)
			}
			if second.ID != first.ID {
				t.Fatalf("scope=session: model-b bound to %q, want %q", second.ID, first.ID)
			}
		})
	}
}

func TestSessionAffinityReturnHome(t *testing.T) {
	t.Parallel()

	const after = 10 * time.Minute
	tests := []struct {
		name          string
		returnHome    bool
		homeRecovers  bool
		idle          time.Duration
		wantAuth      string
		wantHomeAfter string
	}{
		{name: "disabled stays on failover", returnHome: false, homeRecovers: true, idle: after + time.Minute, wantAuth: "b-failover", wantHomeAfter: ""},
		{name: "home still unavailable", returnHome: true, homeRecovers: false, idle: after + time.Minute, wantAuth: "b-failover", wantHomeAfter: "a-home"},
		{name: "not idle long enough", returnHome: true, homeRecovers: true, idle: after - time.Minute, wantAuth: "b-failover", wantHomeAfter: "a-home"},
		{name: "returns home", returnHome: true, homeRecovers: true, idle: after + time.Minute, wantAuth: "a-home", wantHomeAfter: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
				Fallback:        &RoundRobinSelector{},
				TTL:             time.Hour,
				ReturnHome:      tt.returnHome,
				ReturnHomeAfter: after,
			})
			defer selector.Stop()
			now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
			selector.cache.now = func() time.Time { return now }

			home := &Auth{ID: "a-home", Provider: "claude", Status: StatusActive}
			failover := &Auth{ID: "b-failover", Provider: "claude", Status: StatusActive}
			auths := []*Auth{home, failover}
			opts := sessionOpts("thread-rh")
			key := selector.cacheKey("claude", "claude:thread-rh", "model")

			if got, err := selector.Pick(context.Background(), "claude", "model", opts, auths); err != nil || got.ID != home.ID {
				t.Fatalf("initial Pick() = %v, %v; want auth-home", got, err)
			}

			home.Unavailable = true
			if got, err := selector.Pick(context.Background(), "claude", "model", opts, auths); err != nil || got.ID != failover.ID {
				t.Fatalf("failover Pick() = %v, %v; want auth-failover", got, err)
			}
			binding, ok := selector.cache.Binding(key)
			if !ok || binding.AuthID != failover.ID {
				t.Fatalf("binding after failover = %+v, %v", binding, ok)
			}
			if tt.returnHome && binding.HomeAuthID != home.ID {
				t.Fatalf("home not recorded: %+v", binding)
			}
			if !tt.returnHome && binding.HomeAuthID != "" {
				t.Fatalf("home recorded while disabled: %+v", binding)
			}

			// While still active, the session keeps the failover credential even if home recovers.
			home.Unavailable = false
			now = now.Add(time.Minute)
			if got, err := selector.Pick(context.Background(), "claude", "model", opts, auths); err != nil || got.ID != failover.ID {
				t.Fatalf("active Pick() = %v, %v; want auth-failover", got, err)
			}

			home.Unavailable = !tt.homeRecovers
			now = now.Add(tt.idle)
			got, err := selector.Pick(context.Background(), "claude", "model", opts, auths)
			if err != nil {
				t.Fatalf("final Pick() error = %v", err)
			}
			if got.ID != tt.wantAuth {
				t.Fatalf("final Pick() = %q, want %q", got.ID, tt.wantAuth)
			}
			binding, ok = selector.cache.Binding(key)
			if !ok || binding.AuthID != tt.wantAuth || binding.HomeAuthID != tt.wantHomeAfter {
				t.Fatalf("final binding = %+v, %v; want auth=%q home=%q", binding, ok, tt.wantAuth, tt.wantHomeAfter)
			}
		})
	}
}

// A second failover keeps the original home rather than the intermediate credential.
func TestSessionAffinityReturnHomeKeepsOriginalHomeAcrossFailovers(t *testing.T) {
	t.Parallel()

	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:   &RoundRobinSelector{},
		TTL:        time.Hour,
		ReturnHome: true,
	})
	defer selector.Stop()

	home := &Auth{ID: "a-home", Provider: "claude", Status: StatusActive}
	second := &Auth{ID: "b-second", Provider: "claude", Status: StatusActive}
	third := &Auth{ID: "c-third", Provider: "claude", Status: StatusActive}
	auths := []*Auth{home, second, third}
	opts := sessionOpts("thread-chain")
	key := selector.cacheKey("claude", "claude:thread-chain", "model")

	if got, _ := selector.Pick(context.Background(), "claude", "model", opts, auths); got.ID != home.ID {
		t.Fatalf("initial = %q", got.ID)
	}
	home.Unavailable = true
	first, _ := selector.Pick(context.Background(), "claude", "model", opts, auths)
	if first.ID == home.ID {
		t.Fatalf("expected failover away from home")
	}
	first.Unavailable = true
	got, _ := selector.Pick(context.Background(), "claude", "model", opts, auths)
	if got.ID == home.ID || got.ID == first.ID {
		t.Fatalf("expected second failover, got %q", got.ID)
	}
	if binding, ok := selector.cache.Binding(key); !ok || binding.HomeAuthID != home.ID {
		t.Fatalf("home after second failover = %+v, %v; want auth-home", binding, ok)
	}
}
