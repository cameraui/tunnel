package tunnel

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/nats-io/nats.go"

	"github.com/seydx/cameraui.com/cloud-client/internal/app"
	"github.com/seydx/cameraui.com/cloud-client/internal/proxy"
	"github.com/seydx/cameraui.com/cloud-client/pkg/log"
)

type TunnelConnection struct {
	ServerID     string
	ServerSecret string
	Endpoint     string
	LocalPort    string

	SessionID   string
	conn        net.Conn
	session     *yamux.Session
	connected   atomic.Bool
	ConnectedAt time.Time
	mu          sync.Mutex
}

type NonceFrame struct {
	Nonce     string `json:"nonce"`
	SessionID string `json:"session_id"`
}

type AuthFrame struct {
	Type      string `json:"type"`
	ServerID  string `json:"server_id"`
	SessionID string `json:"session_id"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

var ErrAuthFailed = errors.New("authentication failed")

const (
	StatusSubject         = "cloud.agent.status"
	ShutdownSubject       = "cloud.agent.shutdown"
	ForceReconnectSubject = "cloud.agent.force-reconnect"
	AuthFailedSubject     = "cloud.agent.auth-failed"
	ConnectedSubject      = "cloud.agent.connected"
)

var (
	currentTunnel    *TunnelConnection
	currentTunnelMu  sync.Mutex
	loopCancel       context.CancelFunc
	forceReconnectCh = make(chan struct{}, 1)
)

func Init() {
	proxyClient := proxy.GetClient()
	if proxyClient == nil {
		log.Logger.Fatal().Msg("Proxy client is not initialized")
	}

	if err := proxyClient.RegisterHandler(StatusSubject, handleStatus); err != nil {
		log.Logger.Fatal().Err(err).Str("subject", StatusSubject).Msg("Failed to register handler")
	}

	if err := proxyClient.RegisterHandler(ShutdownSubject, handleShutdown); err != nil {
		log.Logger.Fatal().Err(err).Str("subject", ShutdownSubject).Msg("Failed to register handler")
	}

	if err := proxyClient.RegisterHandler(ForceReconnectSubject, handleForceReconnect); err != nil {
		log.Logger.Fatal().Err(err).Str("subject", ForceReconnectSubject).Msg("Failed to register handler")
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopCancel = cancel
	go connectLoop(ctx)
}

func NewTunnelConnection() *TunnelConnection {
	cfg := app.GetConfig()
	return &TunnelConnection{
		ServerID:     cfg.ServerID,
		ServerSecret: cfg.ServerSecret,
		Endpoint:     cfg.CloudEndpoint,
		LocalPort:    cfg.LocalPort,
	}
}

func (t *TunnelConnection) Connect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	host, address := resolveAddress(t.Endpoint)

	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	if app.GetConfig().IsDevelopment() {
		tlsConfig.InsecureSkipVerify = true
	}

	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %w", address, err)
	}

	t.conn = conn

	reader := bufio.NewReader(conn)

	// Cloud sends nonce first.
	nonceLine, err := reader.ReadString('\n')
	if err != nil {
		closeConnLog(conn, "nonce read failure")
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	var nf NonceFrame
	if err := json.Unmarshal([]byte(strings.TrimSpace(nonceLine)), &nf); err != nil {
		closeConnLog(conn, "nonce decode failure")
		return fmt.Errorf("failed to decode nonce: %w", err)
	}
	if nf.Nonce == "" || nf.SessionID == "" {
		closeConnLog(conn, "nonce empty")
		return errors.New("cloud sent empty nonce frame")
	}

	t.SessionID = nf.SessionID

	// Sign nonce:sessionID:timestamp and respond.
	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%s:%s:%d", nf.Nonce, nf.SessionID, timestamp)

	auth := AuthFrame{
		Type:      "AUTH",
		ServerID:  t.ServerID,
		SessionID: nf.SessionID,
		Timestamp: timestamp,
		Signature: t.calculateHMAC(payload),
	}

	authJSON, err := json.Marshal(auth)
	if err != nil {
		closeConnLog(conn, "auth marshal failure")
		return fmt.Errorf("failed to marshal auth frame: %w", err)
	}

	if _, err := conn.Write(append(authJSON, '\n')); err != nil {
		closeConnLog(conn, "auth write failure")
		return fmt.Errorf("failed to send auth frame: %w", err)
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		closeConnLog(conn, "auth response read failure")
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	response = strings.TrimSpace(response)
	if response != "OK" {
		closeConnLog(conn, "auth rejected")
		if strings.HasPrefix(response, "AUTH_FAIL") {
			return fmt.Errorf("%w: %s", ErrAuthFailed, response)
		}
		return fmt.Errorf("authentication failed: %s", response)
	}

	yamuxConfig := yamux.DefaultConfig()
	yamuxConfig.AcceptBacklog = 256
	yamuxConfig.EnableKeepAlive = true
	yamuxConfig.KeepAliveInterval = 30 * time.Second
	yamuxConfig.MaxStreamWindowSize = 256 * 1024
	yamuxConfig.LogOutput = io.Discard

	session, err := yamux.Client(conn, yamuxConfig)
	if err != nil {
		closeConnLog(conn, "yamux session failure")
		return fmt.Errorf("failed to create yamux session: %w", err)
	}

	t.session = session
	t.connected.Store(true)
	t.ConnectedAt = time.Now()

	go t.acceptStreams(session)

	return nil
}

func (t *TunnelConnection) Done() <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.session == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return t.session.CloseChan()
}

func (t *TunnelConnection) Close() {
	t.disconnect("closed by user")
}

func (t *TunnelConnection) IsConnected() bool {
	return t.connected.Load()
}

func (t *TunnelConnection) StatusSnapshot() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := map[string]any{
		"status":       "connected",
		"connected_at": t.ConnectedAt.UnixMilli(),
	}

	if t.session != nil {
		result["active_streams"] = t.session.NumStreams()
	}

	return result
}

func (t *TunnelConnection) acceptStreams(session *yamux.Session) {
	defer t.disconnect("session closed")

	for {
		stream, err := session.Accept()
		if err != nil {
			return
		}
		go t.handleStream(stream)
	}
}

func (t *TunnelConnection) handleStream(stream net.Conn) {
	defer closeQuiet(stream)

	dialer := &tls.Dialer{
		Config: &tls.Config{InsecureSkipVerify: true},
	}

	localConn, err := dialer.Dial("tcp", "localhost:"+t.LocalPort)
	if err != nil {
		log.Logger.Error().Err(err).Msg("Failed to dial local backend")
		writeBadGateway(stream)
		return
	}
	defer closeQuiet(localConn)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, stream)
		closeWriteQuiet(localConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, localConn)
		closeWriteQuiet(stream)
	}()

	wg.Wait()
}

func (t *TunnelConnection) calculateHMAC(payload string) string {
	h := hmac.New(sha256.New, []byte(t.ServerSecret))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func (t *TunnelConnection) disconnect(reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected.Load() {
		return
	}

	t.connected.Store(false)

	if t.session != nil {
		if err := t.session.Close(); err != nil {
			log.Logger.Warn().Err(err).Msg("Failed to close yamux session")
		}
		t.session = nil
	}

	if t.conn != nil {
		if err := t.conn.Close(); err != nil {
			log.Logger.Warn().Err(err).Msg("Failed to close tunnel connection")
		}
		t.conn = nil
	}

	log.Logger.Debug().Str("reason", reason).Msg("Tunnel disconnected")
}

func connectLoop(ctx context.Context) {
	const (
		baseBackoff = time.Second
		maxBackoff  = 5 * time.Minute
	)

	backoff := baseBackoff

	for {
		if ctx.Err() != nil {
			return
		}

		tunnel := NewTunnelConnection()
		if old := swapCurrentTunnel(tunnel); old != nil {
			old.Close()
		}

		err := tunnel.Connect()
		if err != nil {
			log.Logger.Warn().Err(err).Msg("Tunnel connect failed")

			if errors.Is(err, ErrAuthFailed) {
				log.Logger.Error().Msg("Authentication permanently failed — stopping reconnect loop")
				if pubErr := proxy.GetClient().Publish(AuthFailedSubject, map[string]any{
					"error": err.Error(),
				}); pubErr != nil {
					log.Logger.Error().Err(pubErr).Msg("Failed to publish auth-failed event")
				}
				return
			}

			if !sleepOrCancel(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}

		// Connected — reset backoff and signal up.
		backoff = baseBackoff
		log.Logger.Info().Msg("Tunnel connected")
		if pubErr := proxy.GetClient().Publish(ConnectedSubject, map[string]any{
			"connected_at": tunnel.ConnectedAt.UnixMilli(),
		}); pubErr != nil {
			log.Logger.Warn().Err(pubErr).Msg("Failed to publish connected event")
		}

		// Wait for disconnect, force-reconnect, or shutdown.
		select {
		case <-ctx.Done():
			tunnel.Close()
			return
		case <-forceReconnectCh:
			log.Logger.Info().Msg("Force-reconnect requested")
			tunnel.Close()
			// loop around immediately, no backoff
		case <-tunnel.Done():
			log.Logger.Info().Msg("Tunnel session ended")
			// brief delay before reconnecting
			if !sleepOrCancel(ctx, baseBackoff) {
				return
			}
		}
	}
}

func sleepOrCancel(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-forceReconnectCh:
		return true
	case <-time.After(d):
		return true
	}
}

func nextBackoff(current, max time.Duration) time.Duration {
	next := min(current*2, max)
	// ±20% jitter to avoid thundering herd if many agents reconnect together.
	jitter := time.Duration(rand.Int63n(int64(next / 5)))
	if rand.Intn(2) == 0 {
		return next - jitter
	}
	return next + jitter
}

func handleStatus(msg *nats.Msg) {
	t := getCurrentTunnel()
	if t == nil || !t.IsConnected() {
		respondSuccess(msg, map[string]any{"status": "disconnected"})
		return
	}
	respondSuccess(msg, t.StatusSnapshot())
}

func handleShutdown(msg *nats.Msg) {
	if loopCancel != nil {
		loopCancel()
	}
	if old := swapCurrentTunnel(nil); old != nil {
		old.Close()
	}
	respondSuccess(msg, map[string]any{"status": "shutdown"})
}

func handleForceReconnect(msg *nats.Msg) {
	select {
	case forceReconnectCh <- struct{}{}:
	default:
		// signal already queued
	}
	respondSuccess(msg, map[string]any{"status": "force-reconnect-queued"})
}

func respondSuccess(msg *nats.Msg, data any) {
	client := proxy.GetClient()
	if err := client.RespondSuccess(msg, data); err != nil {
		log.Logger.Error().Err(err).Str("subject", msg.Subject).Msg("Failed to send success response")
	}
}

func swapCurrentTunnel(next *TunnelConnection) *TunnelConnection {
	currentTunnelMu.Lock()
	defer currentTunnelMu.Unlock()
	previous := currentTunnel
	currentTunnel = next
	return previous
}

func getCurrentTunnel() *TunnelConnection {
	currentTunnelMu.Lock()
	defer currentTunnelMu.Unlock()
	return currentTunnel
}

func resolveAddress(endpoint string) (host, address string) {
	if hostOnly, _, splitErr := net.SplitHostPort(endpoint); splitErr == nil {
		return hostOnly, endpoint
	}

	if u, parseErr := url.Parse(endpoint); parseErr == nil && u.Scheme != "" && u.Host != "" {
		host = u.Hostname()
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		return host, net.JoinHostPort(host, port)
	}

	return endpoint, net.JoinHostPort(endpoint, "9092")
}

func writeBadGateway(stream net.Conn) {
	if _, err := stream.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); err != nil && !isBenignCloseError(err) {
		log.Logger.Warn().Err(err).Msg("Failed to write 502 response")
	}
}

func closeConnLog(conn net.Conn, reason string) {
	if err := conn.Close(); err != nil && !isBenignCloseError(err) {
		log.Logger.Warn().Err(err).Str("reason", reason).Msg("Failed to close connection")
	}
}

func closeQuiet(c net.Conn) {
	if err := c.Close(); err != nil && !isBenignCloseError(err) {
		log.Logger.Debug().Err(err).Msg("Close error")
	}
}

func closeWriteQuiet(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func isBenignCloseError(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
