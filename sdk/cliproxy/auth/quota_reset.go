package auth

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// SoonestResetWindowAuto picks the quota window that is closest to exhaustion.
	SoonestResetWindowAuto = "auto"
	// SoonestResetWindowPrimary only considers the Codex primary or Claude 5h window.
	// Codex plans with a single weekly limit report it as the primary window.
	SoonestResetWindowPrimary = "primary"
	// SoonestResetWindowSecondary only considers the Codex secondary or Claude 7d window.
	SoonestResetWindowSecondary = "secondary"

	// SoonestResetUnknownProbe orders credentials without a usable reset signal first so
	// they are used once and their quota headers get captured.
	SoonestResetUnknownProbe = "probe"
	// SoonestResetUnknownLast orders credentials without a usable reset signal after every
	// credential with a known reset.
	SoonestResetUnknownLast = "last"

	defaultSoonestResetSkipExhaustedAbove = 95.0
	defaultSoonestResetStaleAfter         = 30 * time.Minute
)

// SoonestResetConfig tunes how SoonestResetSelector derives a reset time from the
// passive quota signals captured on each credential.
type SoonestResetConfig struct {
	// Window selects which quota window drives ordering: auto, primary or secondary.
	Window string
	// SkipExhaustedAbove is the used-percent at or above which a window is treated as
	// exhausted and no longer considered a "use it or lose it" opportunity.
	SkipExhaustedAbove float64
	// StaleAfter is the maximum age of a quota snapshot before it is treated as unknown.
	StaleAfter time.Duration
	// UnknownPolicy places credentials without a usable reset: probe or last.
	UnknownPolicy string
}

func (c SoonestResetConfig) normalized() SoonestResetConfig {
	switch strings.ToLower(strings.TrimSpace(c.Window)) {
	case SoonestResetWindowPrimary:
		c.Window = SoonestResetWindowPrimary
	case SoonestResetWindowSecondary:
		c.Window = SoonestResetWindowSecondary
	default:
		c.Window = SoonestResetWindowAuto
	}
	if c.SkipExhaustedAbove <= 0 || math.IsNaN(c.SkipExhaustedAbove) || math.IsInf(c.SkipExhaustedAbove, 0) {
		c.SkipExhaustedAbove = defaultSoonestResetSkipExhaustedAbove
	}
	if c.StaleAfter <= 0 {
		c.StaleAfter = defaultSoonestResetStaleAfter
	}
	if strings.EqualFold(strings.TrimSpace(c.UnknownPolicy), SoonestResetUnknownLast) {
		c.UnknownPolicy = SoonestResetUnknownLast
	} else {
		c.UnknownPolicy = SoonestResetUnknownProbe
	}
	return c
}

// quotaWindow is one rate-limit window decoded from a credential's quota signals.
type quotaWindow struct {
	resetAt     time.Time
	usedPercent float64
}

// effectiveReset derives the rate-limit window reset that currently constrains auth for
// model. It prefers the per-model quota snapshot when one carries signals and falls back
// to the credential-level snapshot.
//
// known is false when no fresh, parseable reset signal exists or when every candidate
// window is already exhausted (usedPercent >= cfg.SkipExhaustedAbove). In the exhausted
// case resetAt and usedPercent still describe the exhausted window that resets last (the
// one that keeps the credential blocked longest) so callers can order exhausted
// credentials after everything else; usedPercent stays 0 for truly unknown credentials.
func effectiveReset(auth *Auth, model string, cfg SoonestResetConfig, now time.Time) (resetAt time.Time, usedPercent float64, known bool) {
	if auth == nil {
		return time.Time{}, 0, false
	}
	cfg = cfg.normalized()
	quota := quotaSnapshotForModel(auth, model)
	if len(quota.Signals) == 0 || quota.ObservedAt.IsZero() {
		return time.Time{}, 0, false
	}
	if now.Sub(quota.ObservedAt) > cfg.StaleAfter {
		return time.Time{}, 0, false
	}
	signals := lowerCaseSignals(quota.Signals)
	primary, hasPrimary := parseQuotaWindow(signals, quota.ObservedAt,
		"x-codex-primary-reset-after-seconds", "x-codex-primary-reset-at", "x-codex-primary-used-percent",
		"anthropic-ratelimit-unified-5h-reset", "anthropic-ratelimit-unified-5h-utilization")
	secondary, hasSecondary := parseQuotaWindow(signals, quota.ObservedAt,
		"x-codex-secondary-reset-after-seconds", "x-codex-secondary-reset-at", "x-codex-secondary-used-percent",
		"anthropic-ratelimit-unified-7d-reset", "anthropic-ratelimit-unified-7d-utilization")

	candidates := make([]quotaWindow, 0, 2)
	switch cfg.Window {
	case SoonestResetWindowPrimary:
		if hasPrimary {
			candidates = append(candidates, primary)
		}
	case SoonestResetWindowSecondary:
		if hasSecondary {
			candidates = append(candidates, secondary)
		}
	default:
		if hasPrimary {
			candidates = append(candidates, primary)
		}
		if hasSecondary {
			candidates = append(candidates, secondary)
		}
	}
	if len(candidates) == 0 {
		return time.Time{}, 0, false
	}

	// A reset that already passed means the window was refreshed after the snapshot:
	// the real usage is unknown until the next response, so drop the window.
	live := candidates[:0]
	for _, window := range candidates {
		if window.resetAt.After(now) {
			live = append(live, window)
		}
	}
	if len(live) == 0 {
		return time.Time{}, 0, false
	}

	var exhausted *quotaWindow
	var binding *quotaWindow
	for i := range live {
		window := &live[i]
		if window.usedPercent >= cfg.SkipExhaustedAbove {
			if exhausted == nil || window.resetAt.After(exhausted.resetAt) {
				exhausted = window
			}
			continue
		}
		// auto: the window closest to exhaustion is the one that actually constrains;
		// on equal usage prefer the earlier reset.
		if binding == nil || window.usedPercent > binding.usedPercent ||
			(window.usedPercent == binding.usedPercent && window.resetAt.Before(binding.resetAt)) {
			binding = window
		}
	}
	if binding != nil {
		return binding.resetAt, binding.usedPercent, true
	}
	return exhausted.resetAt, exhausted.usedPercent, false
}

// quotaSnapshotForModel returns the per-model quota snapshot when it carries signals,
// otherwise the credential-level snapshot.
func quotaSnapshotForModel(auth *Auth, model string) QuotaState {
	if model != "" && len(auth.ModelStates) > 0 {
		modelKey := canonicalModelKey(model)
		if state := auth.ModelStates[model]; state != nil && len(state.Quota.Signals) > 0 {
			return state.Quota
		}
		for stateModel, state := range auth.ModelStates {
			if state == nil || len(state.Quota.Signals) == 0 || canonicalModelKey(stateModel) != modelKey {
				continue
			}
			return state.Quota
		}
	}
	return auth.Quota
}

func lowerCaseSignals(signals map[string]string) map[string]string {
	lowered := make(map[string]string, len(signals))
	for key, value := range signals {
		lowered[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return lowered
}

// parseQuotaWindow decodes one window from either the Codex header triple or the Claude
// header pair. Codex relative resets are anchored at observedAt; Claude resets are
// absolute epoch seconds. usedPercent is normalised to 0..100.
func parseQuotaWindow(signals map[string]string, observedAt time.Time, codexResetAfter, codexResetAt, codexUsed, claudeReset, claudeUtil string) (quotaWindow, bool) {
	if raw, ok := signals[codexResetAfter]; ok {
		if seconds, errParse := strconv.ParseFloat(raw, 64); errParse == nil && seconds >= 0 && !math.IsInf(seconds, 0) {
			return quotaWindow{
				resetAt:     observedAt.Add(time.Duration(seconds * float64(time.Second))),
				usedPercent: parsePercent(signals[codexUsed], false),
			}, true
		}
	}
	if raw, ok := signals[codexResetAt]; ok {
		if resetAt, okParse := parseAbsoluteReset(raw); okParse {
			return quotaWindow{resetAt: resetAt, usedPercent: parsePercent(signals[codexUsed], false)}, true
		}
	}
	if raw, ok := signals[claudeReset]; ok {
		if resetAt, okParse := parseAbsoluteReset(raw); okParse {
			return quotaWindow{resetAt: resetAt, usedPercent: parsePercent(signals[claudeUtil], true)}, true
		}
	}
	return quotaWindow{}, false
}

// parsePercent returns a 0..100 usage figure. Claude utilization is a 0..1 fraction;
// a value above 1 is assumed to already be a percentage.
func parsePercent(raw string, fraction bool) float64 {
	value, errParse := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if errParse != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}
	if fraction && value <= 1 {
		value *= 100
	}
	if value > 100 {
		value = 100
	}
	return value
}

// parseAbsoluteReset accepts epoch seconds (integer or fractional), RFC3339, or an
// HTTP-date; it mirrors the executor-side parser without importing it.
func parseAbsoluteReset(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if seconds, errParse := strconv.ParseFloat(raw, 64); errParse == nil {
		if seconds <= 0 || math.IsInf(seconds, 0) {
			return time.Time{}, false
		}
		whole := int64(seconds)
		return time.Unix(whole, int64((seconds-float64(whole))*1e9)), true
	}
	if parsed, errParse := time.Parse(time.RFC3339, raw); errParse == nil {
		return parsed, true
	}
	if parsed, errParse := http.ParseTime(raw); errParse == nil {
		return parsed, true
	}
	return time.Time{}, false
}
