package executor

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type recordingCodexTransport struct {
	calls  atomic.Int32
	err    error
	chunks []cliproxyexecutor.StreamChunk
}

func (t *recordingCodexTransport) Execute(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	t.calls.Add(1)
	if t.err != nil {
		return cliproxyexecutor.Response{}, t.err
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"ok":true}`)}, nil
}

func (t *recordingCodexTransport) ExecuteStream(context.Context, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	t.calls.Add(1)
	if t.err != nil {
		return nil, t.err
	}
	out := make(chan cliproxyexecutor.StreamChunk, len(t.chunks))
	for _, chunk := range t.chunks {
		out <- chunk
	}
	close(out)
	return &cliproxyexecutor.StreamResult{Chunks: out}, nil
}

func newGateTestExecutor(flag bool, wsT, httpT codexTransport) *CodexAutoExecutor {
	exec := NewCodexAutoExecutor(&config.Config{Codex: config.CodexConfig{WebsocketsForHTTPClients: flag}})
	exec.wsTransport = wsT
	exec.httpTransport = httpT
	return exec
}

func gateTestAuth(websockets bool) *cliproxyauth.Auth {
	auth := &cliproxyauth.Auth{ID: "codex-gate", Provider: "codex", Attributes: map[string]string{"api_key": "sk-test"}}
	if websockets {
		auth.Attributes["websockets"] = "true"
	}
	return auth
}

func collectChunks(t *testing.T, result *cliproxyexecutor.StreamResult) []cliproxyexecutor.StreamChunk {
	t.Helper()
	var chunks []cliproxyexecutor.StreamChunk
	timeout := time.After(5 * time.Second)
	for {
		select {
		case chunk, ok := <-result.Chunks:
			if !ok {
				return chunks
			}
			chunks = append(chunks, chunk)
		case <-timeout:
			t.Fatal("timed out waiting for stream chunks")
		}
	}
}

func TestCodexAutoExecutorTransportSelection(t *testing.T) {
	tests := []struct {
		name          string
		flag          bool
		downstreamWS  bool
		authWS        bool
		wantWebsocket bool
	}{
		{name: "flag off/http/attr off", wantWebsocket: false},
		{name: "flag off/http/attr on", authWS: true, wantWebsocket: false},
		{name: "flag off/ws/attr off", downstreamWS: true, wantWebsocket: false},
		{name: "flag off/ws/attr on", downstreamWS: true, authWS: true, wantWebsocket: true},
		{name: "flag on/http/attr off", flag: true, wantWebsocket: false},
		{name: "flag on/http/attr on", flag: true, authWS: true, wantWebsocket: true},
		{name: "flag on/ws/attr off", flag: true, downstreamWS: true, wantWebsocket: false},
		{name: "flag on/ws/attr on", flag: true, downstreamWS: true, authWS: true, wantWebsocket: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.downstreamWS {
				ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)
			}
			wsT, httpT := &recordingCodexTransport{}, &recordingCodexTransport{}
			exec := newGateTestExecutor(tt.flag, wsT, httpT)
			auth := gateTestAuth(tt.authWS)

			if _, err := exec.Execute(ctx, auth, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if _, err := exec.ExecuteStream(ctx, auth, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err != nil {
				t.Fatalf("ExecuteStream() error = %v", err)
			}

			wantWS, wantHTTP := int32(0), int32(2)
			if tt.wantWebsocket {
				wantWS, wantHTTP = 2, 0
			}
			if got := wsT.calls.Load(); got != wantWS {
				t.Fatalf("websocket transport calls = %d, want %d", got, wantWS)
			}
			if got := httpT.calls.Load(); got != wantHTTP {
				t.Fatalf("http transport calls = %d, want %d", got, wantHTTP)
			}
		})
	}
}

func TestCodexAutoExecutorHTTPClientFallsBackToHTTPOnWebsocketError(t *testing.T) {
	policyClose := &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "policy"}
	tests := []struct {
		name         string
		wsErr        error
		downstreamWS bool
		lifecycle    cliproxyexecutor.ExecutionLifecycle
		wantFallback bool
	}{
		{name: "replay required", wsErr: cliproxyexecutor.NewUpstreamWebsocketReplayRequiredError(), wantFallback: true},
		{name: "policy close", wsErr: policyClose, wantFallback: true},
		{name: "upgrade required", wsErr: statusErr{code: http.StatusUpgradeRequired, msg: "upgrade"}, wantFallback: true},
		{name: "connection limit", wsErr: statusErr{code: http.StatusTooManyRequests, msg: `{"error":{"code":"websocket_connection_limit_reached"}}`}, wantFallback: true},
		{name: "bad handshake", wsErr: websocket.ErrBadHandshake, wantFallback: true},
		{name: "usage limit stays", wsErr: statusErr{code: http.StatusTooManyRequests, msg: `{"error":{"code":"usage_limit_reached"}}`}, wantFallback: false},
		{name: "generic error stays", wsErr: errors.New("boom"), wantFallback: false},
		{name: "context canceled stays", wsErr: context.Canceled, wantFallback: false},
		{name: "websocket downstream unchanged", wsErr: policyClose, downstreamWS: true, wantFallback: false},
		{name: "execution lifecycle unchanged", wsErr: policyClose, lifecycle: newTerminalFailureLifecycle(), wantFallback: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.downstreamWS {
				ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)
			}
			opts := cliproxyexecutor.Options{ExecutionLifecycle: tt.lifecycle}
			auth := gateTestAuth(true)

			// Non-streaming: the websocket error surfaces from Execute directly.
			wsT, httpT := &recordingCodexTransport{err: tt.wsErr}, &recordingCodexTransport{}
			exec := newGateTestExecutor(true, wsT, httpT)
			_, err := exec.Execute(ctx, auth, cliproxyexecutor.Request{}, opts)
			if tt.wantFallback {
				if err != nil {
					t.Fatalf("Execute() error = %v, want HTTP fallback success", err)
				}
			} else if !errors.Is(err, tt.wsErr) && err != tt.wsErr {
				t.Fatalf("Execute() error = %v, want websocket error %v", err, tt.wsErr)
			}
			if got, want := httpT.calls.Load(), boolToCalls(tt.wantFallback); got != want {
				t.Fatalf("Execute() http transport calls = %d, want %d", got, want)
			}

			// Streaming: the websocket error surfaces as the first stream chunk.
			wsT = &recordingCodexTransport{chunks: []cliproxyexecutor.StreamChunk{{Err: tt.wsErr}}}
			httpT = &recordingCodexTransport{chunks: []cliproxyexecutor.StreamChunk{{Payload: []byte("data: http")}}}
			exec = newGateTestExecutor(true, wsT, httpT)
			result, err := exec.ExecuteStream(ctx, auth, cliproxyexecutor.Request{}, opts)
			if err != nil {
				t.Fatalf("ExecuteStream() error = %v", err)
			}
			chunks := collectChunks(t, result)
			if len(chunks) != 1 {
				t.Fatalf("ExecuteStream() chunks = %d, want 1", len(chunks))
			}
			if tt.wantFallback {
				if chunks[0].Err != nil || string(chunks[0].Payload) != "data: http" {
					t.Fatalf("ExecuteStream() chunk = %+v, want HTTP payload", chunks[0])
				}
			} else if chunks[0].Err != tt.wsErr {
				t.Fatalf("ExecuteStream() chunk error = %v, want %v", chunks[0].Err, tt.wsErr)
			}
			if got, want := httpT.calls.Load(), boolToCalls(tt.wantFallback); got != want {
				t.Fatalf("ExecuteStream() http transport calls = %d, want %d", got, want)
			}
		})
	}
}

func TestCodexAutoExecutorHTTPClientStreamDoesNotFallBackAfterOutput(t *testing.T) {
	wsErr := &websocket.CloseError{Code: websocket.ClosePolicyViolation}
	wsT := &recordingCodexTransport{chunks: []cliproxyexecutor.StreamChunk{{Payload: []byte("data: ws")}, {Err: wsErr}}}
	httpT := &recordingCodexTransport{}
	exec := newGateTestExecutor(true, wsT, httpT)

	result, err := exec.ExecuteStream(context.Background(), gateTestAuth(true), cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("ExecuteStream() error = %v", err)
	}
	chunks := collectChunks(t, result)
	if len(chunks) != 2 || string(chunks[0].Payload) != "data: ws" || chunks[1].Err != wsErr {
		t.Fatalf("ExecuteStream() chunks = %+v, want websocket payload then error", chunks)
	}
	if got := httpT.calls.Load(); got != 0 {
		t.Fatalf("http transport calls = %d, want 0 after output was emitted", got)
	}
}

func TestCodexAutoExecutorFlagOffUsesHTTPWithoutTouchingWebsocket(t *testing.T) {
	wsT := &recordingCodexTransport{err: errors.New("must not be called")}
	httpT := &recordingCodexTransport{}
	exec := newGateTestExecutor(false, wsT, httpT)

	if _, err := exec.Execute(context.Background(), gateTestAuth(true), cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := wsT.calls.Load(); got != 0 {
		t.Fatalf("websocket transport calls = %d, want 0", got)
	}
}

func boolToCalls(v bool) int32 {
	if v {
		return 1
	}
	return 0
}

func TestCodexAutoExecutorForAPIKeyRebindsTransports(t *testing.T) {
	exec := NewCodexAutoExecutor(&config.Config{Codex: config.CodexConfig{WebsocketsForHTTPClients: true}})
	scoped, ok := exec.ForAPIKey().(*CodexAutoExecutor)
	if !ok {
		t.Fatalf("ForAPIKey() = %T, want *CodexAutoExecutor", exec.ForAPIKey())
	}
	if scoped.httpTransport != codexTransport(scoped.httpExec) || scoped.wsTransport != codexTransport(scoped.wsExec) {
		t.Fatal("ForAPIKey() transports do not point at the scoped executors")
	}
	if scoped.fallbackLogged != exec.fallbackLogged {
		t.Fatal("ForAPIKey() should share the fallback log set")
	}
}
