// Package executor provides runtime execution capabilities for various AI service providers.
// This file implements a Codex executor that uses the Responses API WebSocket transport.
package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

// CodexWebsocketsExecutor executes Codex Responses requests using a WebSocket transport.
//
// It preserves the existing CodexExecutor HTTP implementation as a fallback for endpoints
// not available over WebSocket (e.g. /responses/compact) and for websocket upgrade failures.
type CodexWebsocketsExecutor struct {
	*CodexExecutor

	store *codexWebsocketSessionStore
}

func NewCodexWebsocketsExecutor(cfg *config.Config) *CodexWebsocketsExecutor {
	return &CodexWebsocketsExecutor{
		CodexExecutor: NewCodexExecutor(cfg),
		store:         globalCodexWebsocketSessionStore,
	}
}

// codexTransport is the request-execution subset of the executor contract that
// CodexAutoExecutor routes between.
type codexTransport interface {
	Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error)
	ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error)
}

// CodexAutoExecutor routes Codex requests to the websocket transport only when:
//  1. The selected auth enables websockets, and
//  2. The downstream transport is websocket, or
//     codex.websockets-for-http-clients is enabled.
//
// Otherwise it uses the legacy HTTP implementation. HTTP downstream requests that
// were routed over websocket fall back to HTTP when the websocket transport proves
// unusable before any output reached the client.
type CodexAutoExecutor struct {
	cfg      *config.Config
	httpExec *CodexExecutor
	wsExec   *CodexWebsocketsExecutor

	// httpTransport and wsTransport default to httpExec and wsExec; tests swap them.
	httpTransport codexTransport
	wsTransport   codexTransport

	// fallbackLogged records auth IDs for which the websocket->HTTP fallback was already reported.
	fallbackLogged *sync.Map
}

func NewCodexAutoExecutor(cfg *config.Config) *CodexAutoExecutor {
	httpExec := NewCodexExecutor(cfg)
	wsExec := NewCodexWebsocketsExecutor(cfg)
	return &CodexAutoExecutor{
		cfg:            cfg,
		httpExec:       httpExec,
		wsExec:         wsExec,
		httpTransport:  httpExec,
		wsTransport:    wsExec,
		fallbackLogged: &sync.Map{},
	}
}

func (e *CodexAutoExecutor) Identifier() string { return "codex" }

func (e *CodexAutoExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if e == nil || e.httpExec == nil {
		return nil
	}
	return e.httpExec.PrepareRequest(req, auth)
}

func (e *CodexAutoExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if e == nil || e.httpExec == nil {
		return nil, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.HttpRequest(ctx, auth, req)
}

func (e *CodexAutoExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e == nil || e.httpTransport == nil || e.wsTransport == nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex auto executor: executor is nil")
	}
	if e.useWebsockets(ctx, auth) {
		resp, err := e.wsTransport.Execute(ctx, auth, req, opts)
		if err != nil && e.shouldFallbackToHTTP(ctx, auth, opts, err) {
			return e.httpTransport.Execute(ctx, auth, req, opts)
		}
		return resp, err
	}
	if cliproxyexecutor.RequiredUpstreamWebsocket(ctx) {
		return cliproxyexecutor.Response{}, cliproxyexecutor.NewUpstreamWebsocketReplayRequiredError()
	}
	return e.httpTransport.Execute(ctx, auth, req, opts)
}

func (e *CodexAutoExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if e == nil || e.httpTransport == nil || e.wsTransport == nil {
		return nil, fmt.Errorf("codex auto executor: executor is nil")
	}
	if e.useWebsockets(ctx, auth) {
		result, err := e.wsTransport.ExecuteStream(ctx, auth, req, opts)
		if err != nil {
			if e.shouldFallbackToHTTP(ctx, auth, opts, err) {
				return e.httpTransport.ExecuteStream(ctx, auth, req, opts)
			}
			return nil, err
		}
		if result == nil || result.Chunks == nil || !e.httpFallbackAllowed(ctx, opts) {
			return result, nil
		}
		return e.streamWithHTTPFallback(ctx, auth, req, opts, result), nil
	}
	if cliproxyexecutor.RequiredUpstreamWebsocket(ctx) {
		return nil, cliproxyexecutor.NewUpstreamWebsocketReplayRequiredError()
	}
	return e.httpTransport.ExecuteStream(ctx, auth, req, opts)
}

// useWebsockets reports whether the request should be executed over the websocket transport.
func (e *CodexAutoExecutor) useWebsockets(ctx context.Context, auth *cliproxyauth.Auth) bool {
	if !codexWebsocketsEnabled(auth) {
		return false
	}
	return cliproxyexecutor.DownstreamWebsocket(ctx) || e.websocketsForHTTPClients()
}

func (e *CodexAutoExecutor) websocketsForHTTPClients() bool {
	return e != nil && e.cfg != nil && e.cfg.Codex.WebsocketsForHTTPClients
}

// httpFallbackAllowed reports whether a websocket failure may be retried over HTTP.
// Websocket downstream clients keep their existing semantics, and execution lifecycles
// stay bound to the transport they were established on.
func (e *CodexAutoExecutor) httpFallbackAllowed(ctx context.Context, opts cliproxyexecutor.Options) bool {
	return !cliproxyexecutor.DownstreamWebsocket(ctx) && opts.ExecutionLifecycle == nil
}

func (e *CodexAutoExecutor) shouldFallbackToHTTP(ctx context.Context, auth *cliproxyauth.Auth, opts cliproxyexecutor.Options, err error) bool {
	if !e.httpFallbackAllowed(ctx, opts) || !codexWebsocketFallbackEligible(err) {
		return false
	}
	authID := ""
	if auth != nil {
		authID = auth.ID
	}
	if e.fallbackLogged != nil {
		if _, loaded := e.fallbackLogged.LoadOrStore(authID, struct{}{}); loaded {
			log.Debugf("codex auto executor: websocket transport unusable for HTTP client, falling back to HTTP (auth=%s): %v", authID, err)
			return true
		}
	}
	log.Warnf("codex auto executor: websocket transport unusable for HTTP client, falling back to HTTP (auth=%s): %v", authID, err)
	return true
}

// codexWebsocketFallbackEligible reports whether err means the websocket transport is
// unusable for this request while the equivalent HTTP request may still succeed.
func codexWebsocketFallbackEligible(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if cliproxyexecutor.IsUpstreamWebsocketReplayRequired(err) {
		return true
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		return true
	}
	var netErr net.Error
	if errors.Is(err, websocket.ErrBadHandshake) || errors.As(err, &netErr) {
		return true
	}
	if statusErr, ok := err.(interface{ StatusCode() int }); ok && statusErr.StatusCode() == http.StatusUpgradeRequired {
		return true
	}
	return isCodexWebsocketConnectionLimitError([]byte(err.Error()))
}

// streamWithHTTPFallback forwards the websocket stream, except when its very first chunk is a
// fallback-eligible error: nothing has reached the client yet, so the request is replayed over HTTP.
func (e *CodexAutoExecutor) streamWithHTTPFallback(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, wsResult *cliproxyexecutor.StreamResult) *cliproxyexecutor.StreamResult {
	out := make(chan cliproxyexecutor.StreamChunk)
	forward := func(chunk cliproxyexecutor.StreamChunk) bool {
		select {
		case out <- chunk:
			return true
		case <-ctx.Done():
			return false
		}
	}
	go func() {
		defer close(out)
		first, ok := <-wsResult.Chunks
		if !ok {
			return
		}
		if first.Err != nil && e.shouldFallbackToHTTP(ctx, auth, opts, first.Err) {
			go func() {
				for range wsResult.Chunks {
				}
			}()
			httpResult, errHTTP := e.httpTransport.ExecuteStream(ctx, auth, req, opts)
			if errHTTP != nil {
				forward(cliproxyexecutor.StreamChunk{Err: errHTTP})
				return
			}
			if httpResult == nil || httpResult.Chunks == nil {
				return
			}
			for chunk := range httpResult.Chunks {
				if !forward(chunk) {
					return
				}
			}
			return
		}
		if !forward(first) {
			return
		}
		for chunk := range wsResult.Chunks {
			if !forward(chunk) {
				return
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: wsResult.Headers, Chunks: out}
}

func (e *CodexAutoExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if e == nil || e.httpExec == nil {
		return nil, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.Refresh(ctx, auth)
}

func (e *CodexAutoExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e == nil || e.httpExec == nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.CountTokens(ctx, auth, req, opts)
}

func (e *CodexAutoExecutor) CloseExecutionSession(sessionID string) {
	if e == nil || e.wsExec == nil {
		return
	}
	e.wsExec.CloseExecutionSession(sessionID)
}

func (e *CodexAutoExecutor) UpstreamDisconnectChan(sessionID string) <-chan error {
	if e == nil || e.wsExec == nil {
		return nil
	}
	return e.wsExec.UpstreamDisconnectChan(sessionID)
}

func codexWebsocketsEnabled(auth *cliproxyauth.Auth) bool {
	if auth == nil {
		return false
	}
	if len(auth.Attributes) > 0 {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed
			}
		}
	}
	if len(auth.Metadata) == 0 {
		return false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed
		}
	default:
	}
	return false
}

// SupportsApplyPatch requires both selectable transports to support the tool.
func (e *CodexAutoExecutor) SupportsApplyPatch() bool {
	return e != nil && e.httpExec != nil && e.wsExec != nil && e.httpExec.SupportsApplyPatch() && e.wsExec.SupportsApplyPatch()
}
