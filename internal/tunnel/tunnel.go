package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"

	"github.com/cameraui/tunnel/internal/app"
	"github.com/cameraui/tunnel/internal/proxy"
	"github.com/cameraui/tunnel/pkg/log"
)

type TunnelConnection struct {
	Endpoint  string
	LocalPort string

	SessionID   string
	conn        net.Conn
	session     *yamux.Session
	connected   atomic.Bool
	closed      bool
	ConnectedAt time.Time
	mu          sync.Mutex

	broker           broker
	rootCAs          *x509.CertPool
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
}

type HelloFrame struct {
	SessionID string `json:"session_id"`
}

const (
	credentialsTimeout      = 10 * time.Second
	defaultDialTimeout      = 10 * time.Second
	defaultHandshakeTimeout = 15 * time.Second
	defaultForceGrace       = 3 * time.Second
	dialKeepAlive           = 15 * time.Second
)

type AuthFrame struct {
	Type        string `json:"type"`
	SessionID   string `json:"session_id"`
	AccessToken string `json:"access_token"`
}

var (
	ErrAuthFailed   = errors.New("authentication failed")
	errTunnelClosed = errors.New("tunnel closed")
	errPingTimeout  = errors.New("ping timed out")
)

const (
	StatusSubject         = "tunnel.client.status"
	ShutdownSubject       = "tunnel.client.shutdown"
	ForceReconnectSubject = "tunnel.client.force-reconnect"
	AuthFailedSubject     = "tunnel.client.auth-failed"
	ConnectedSubject      = "tunnel.client.connected"
	CredentialsSubject    = "tunnel.server.credentials"
)

var (
	currentTunnel    *TunnelConnection
	currentTunnelMu  sync.Mutex
	loopCancel       context.CancelFunc
	forceReconnectCh = make(chan struct{}, 1)
)

type broker interface {
	RequestWithContext(ctx context.Context, subject string, data any) (*proxy.Response, error)
	Publish(subject string, data any) error
}

type authFailure struct {
	response string
	reason   string
}

type connector struct {
	broker     broker
	newTunnel  func() *TunnelConnection
	force      chan struct{}
	backoff    *backoff
	forceGrace time.Duration
}

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

	c := &connector{
		broker:     proxyClient,
		newTunnel:  NewTunnelConnection,
		force:      forceReconnectCh,
		backoff:    newBackoff(),
		forceGrace: defaultForceGrace,
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopCancel = cancel
	go c.run(ctx)
}

func NewTunnelConnection() *TunnelConnection {
	cfg := app.GetConfig()
	t := &TunnelConnection{
		Endpoint:         cfg.TunnelEndpoint,
		LocalPort:        cfg.LocalPort,
		dialTimeout:      defaultDialTimeout,
		handshakeTimeout: defaultHandshakeTimeout,
	}
	if client := proxy.GetClient(); client != nil {
		t.broker = client
	}
	return t
}

func (t *TunnelConnection) Connect(ctx context.Context) error {
	token, err := t.requestAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain access token: %w", err)
	}

	host, address := resolveAddress(t.Endpoint)

	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		RootCAs:    t.rootCAs,
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: t.dialTimeout, KeepAlive: dialKeepAlive},
		Config:    tlsConfig,
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %w", address, err)
	}

	if err := conn.SetDeadline(time.Now().Add(t.handshakeTimeout)); err != nil {
		closeConnLog(conn, "set deadline failure")
		return fmt.Errorf("failed to set handshake deadline: %w", err)
	}

	// cancelling ctx expires the deadline, so a blocked handshake read returns at once
	stopAbort := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopAbort()

	reader := bufio.NewReader(conn)

	helloLine, err := reader.ReadString('\n')
	if err != nil {
		closeConnLog(conn, "hello read failure")
		return fmt.Errorf("failed to read hello frame: %w", err)
	}

	var hf HelloFrame
	if err := json.Unmarshal([]byte(strings.TrimSpace(helloLine)), &hf); err != nil {
		closeConnLog(conn, "hello decode failure")
		return fmt.Errorf("failed to decode hello frame: %w", err)
	}
	if hf.SessionID == "" {
		closeConnLog(conn, "hello empty")
		return errors.New("tunnel sent empty hello frame")
	}

	t.SessionID = hf.SessionID

	auth := AuthFrame{
		Type:        "AUTH",
		SessionID:   hf.SessionID,
		AccessToken: token,
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
		if reason, ok := strings.CutPrefix(response, "AUTH_FAIL"); ok {
			return &authFailure{response: response, reason: strings.TrimSpace(strings.TrimPrefix(reason, ":"))}
		}
		return fmt.Errorf("authentication failed: %s", response)
	}

	if !stopAbort() {
		closeConnLog(conn, "handshake aborted")
		return fmt.Errorf("handshake aborted: %w", ctx.Err())
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		closeConnLog(conn, "clear deadline failure")
		return fmt.Errorf("failed to clear handshake deadline: %w", err)
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

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		_ = session.Close()
		return errTunnelClosed
	}

	t.conn = conn
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
func (t *TunnelConnection) requestAccessToken(ctx context.Context) (string, error) {
	if t.broker == nil {
		return "", errors.New("nats client not initialized")
	}
	ctx, cancel := context.WithTimeout(ctx, credentialsTimeout)
	defer cancel()
	resp, err := t.broker.RequestWithContext(ctx, CredentialsSubject, struct{}{})
	if err != nil {
		return "", fmt.Errorf("request tunnel credentials: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("request tunnel credentials: request failed: %s", resp.Error)
	}
	token, ok := resp.Data.(string)
	if !ok || token == "" {
		return "", errors.New("server returned no access token")
	}
	return token, nil
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

	localConn, err := net.Dial("tcp", "127.0.0.1:"+t.LocalPort)
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
		// a yamux stream has no CloseWrite, Close sends FIN and keeps reading
		_ = stream.Close()
	}()

	wg.Wait()
}

func (t *TunnelConnection) disconnect(reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true

	if !t.connected.Load() {
		return
	}

	t.connected.Store(false)

	if t.session != nil {
		if err := t.session.Close(); err != nil && !isBenignCloseError(err) {
			log.Logger.Warn().Err(err).Msg("Failed to close yamux session")
		}
		t.session = nil
	}

	if t.conn != nil {
		if err := t.conn.Close(); err != nil && !isBenignCloseError(err) {
			log.Logger.Warn().Err(err).Msg("Failed to close tunnel connection")
		}
		t.conn = nil
	}

	log.Logger.Debug().Str("reason", reason).Msg("Tunnel disconnected")
}

func (t *TunnelConnection) ping(ctx context.Context, timeout time.Duration) error {
	t.mu.Lock()
	session := t.session
	t.mu.Unlock()
	if session == nil {
		return errTunnelClosed
	}

	result := make(chan error, 1)
	go func() {
		_, err := session.Ping()
		result <- err
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-result:
		return err
	case <-timer.C:
		return errPingTimeout
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *connector) run(ctx context.Context) {
	attempt := 0
	lastFailure := ""
	abortable := true

	for {
		if ctx.Err() != nil {
			return
		}

		tunnel := c.newTunnel()
		if old := swapCurrentTunnel(tunnel); old != nil {
			old.Close()
		}

		aborted, err := c.attempt(ctx, tunnel, abortable)
		// never abort twice in a row, a handshake slower than the grace must still finish
		abortable = !aborted
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if aborted {
				log.Logger.Debug().Err(err).Msg("Force-reconnect restarted a stalled connect attempt")
				continue
			}

			attempt++
			delay := c.backoff.next()
			lastFailure = c.reportFailure(err, attempt, delay, lastFailure)

			if !c.sleepOrCancel(ctx, delay) {
				return
			}
			continue
		}

		c.drainForce()

		if attempt > 0 {
			log.Logger.Info().Int("attempts", attempt).Msg("Tunnel reconnected")
		} else {
			log.Logger.Info().Msg("Tunnel connected")
		}
		attempt = 0
		lastFailure = ""

		if pubErr := c.broker.Publish(ConnectedSubject, map[string]any{
			"connected_at": tunnel.ConnectedAt.UnixMilli(),
		}); pubErr != nil {
			log.Logger.Warn().Err(pubErr).Msg("Failed to publish connected event")
		}

		forced, shutdown := c.wait(ctx, tunnel)
		if shutdown {
			return
		}

		delay := c.backoff.afterSession(time.Since(tunnel.ConnectedAt))
		if forced {
			delay = 0
		}
		log.Logger.Info().Dur("retry_in", delay).Msg("Tunnel session ended, reconnecting")

		if !c.sleepOrCancel(ctx, delay) {
			return
		}
	}
}

func (c *connector) attempt(ctx context.Context, tunnel *TunnelConnection, abortable bool) (aborted bool, err error) {
	if !abortable {
		return false, tunnel.Connect(ctx)
	}

	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var requested, forced atomic.Bool
	finished := make(chan struct{})
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		select {
		case <-c.force:
			requested.Store(true)
		case <-finished:
			return
		}
		grace := time.NewTimer(c.forceGrace)
		defer grace.Stop()
		select {
		case <-grace.C:
			forced.Store(true)
			cancel()
		case <-finished:
		}
	}()

	err = tunnel.Connect(attemptCtx)
	close(finished)
	<-watching

	aborted = err != nil && forced.Load()
	// the wake was meant to skip the backoff, hand it back to sleepOrCancel
	if err != nil && !aborted && requested.Load() {
		select {
		case c.force <- struct{}{}:
		default:
		}
	}
	return aborted, err
}

func (c *connector) wait(ctx context.Context, tunnel *TunnelConnection) (forced, shutdown bool) {
	done := tunnel.Done()
	for {
		select {
		case <-ctx.Done():
			tunnel.Close()
			return false, true
		case <-done:
			return false, false
		case <-c.force:
			err := tunnel.ping(ctx, c.forceGrace)
			if ctx.Err() != nil {
				continue
			}
			if err == nil {
				log.Logger.Debug().Msg("Force-reconnect skipped, tunnel answered ping")
				continue
			}
			log.Logger.Warn().Err(err).Msg("Force-reconnect: tunnel did not answer ping, reconnecting")
			tunnel.Close()
			return true, false
		}
	}
}

func (c *connector) reportFailure(err error, attempt int, delay time.Duration, lastFailure string) string {
	failure := "connect"
	var auth *authFailure
	var verifyErr *tls.CertificateVerificationError
	switch {
	case errors.As(err, &auth):
		failure = auth.response
	case errors.As(err, &verifyErr):
		failure = "certificate"
	}

	level := zerolog.DebugLevel
	if failure != lastFailure {
		level = zerolog.WarnLevel
	}
	log.Logger.WithLevel(level).Err(err).Int("attempt", attempt).Dur("retry_in", delay).Msg("Tunnel connect failed, retrying")

	if auth != nil {
		if pubErr := c.broker.Publish(AuthFailedSubject, map[string]any{
			"error":  err.Error(),
			"reason": auth.reason,
		}); pubErr != nil {
			log.Logger.Error().Err(pubErr).Msg("Failed to publish auth-failed event")
		}
	}

	return failure
}

func (c *connector) sleepOrCancel(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-c.force:
		return true
	case <-timer.C:
		return true
	}
}

func (c *connector) drainForce() {
	select {
	case <-c.force:
	default:
	}
}

func (e *authFailure) Error() string {
	return ErrAuthFailed.Error() + ": " + e.response
}

func (e *authFailure) Is(target error) bool {
	return target == ErrAuthFailed
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
