package tunnel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/rs/zerolog"

	"github.com/cameraui/tunnel/internal/app"
	"github.com/cameraui/tunnel/internal/proxy"
	"github.com/cameraui/tunnel/pkg/log"
)

type cloudMode int

const (
	cloudServes cloudMode = iota
	cloudSilent
	cloudMute
)

const (
	testToken     = "test-access-token"
	testSessionID = "test-session"
)

var logs = &logCapture{}

type logCapture struct {
	mu      sync.Mutex
	entries []map[string]any
}

type fakeBroker struct {
	mu        sync.Mutex
	published map[string][]any
}

type fakeCloud struct {
	mode         cloudMode
	okDelay      time.Duration
	reply        string
	dropSessions bool
	cert         tls.Certificate

	ln         net.Listener
	roots      *x509.CertPool
	accepts    atomic.Int32
	auths      atomic.Int32
	mu         sync.Mutex
	conns      []net.Conn
	sessions   []*yamux.Session
	acceptedAt []time.Time
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func TestMain(m *testing.M) {
	log.Logger = zerolog.New(logs)
	os.Exit(m.Run())
}

func TestConnectRejectsUntrustedCertificateByDefault(t *testing.T) {
	fc := startCloud(t, &fakeCloud{cert: selfSigned(t)})
	tc := fc.tunnel(&fakeBroker{})

	err := awaitConnect(t, connectAsync(context.Background(), tc), 2*time.Second)
	var verifyErr *tls.CertificateVerificationError
	if !errors.As(err, &verifyErr) {
		t.Fatalf("Connect error = %v, want a certificate verification error", err)
	}
	if n := fc.auths.Load(); n != 0 {
		t.Fatalf("untrusted server received %d auth frames, want 0", n)
	}
}

func TestConnectTrustsInjectedRoots(t *testing.T) {
	cert := selfSigned(t)
	fc := startCloud(t, &fakeCloud{cert: cert})
	tc := fc.tunnel(&fakeBroker{})
	tc.rootCAs = poolOf(t, &cert)
	t.Cleanup(tc.Close)

	if err := awaitConnect(t, connectAsync(context.Background(), tc), 2*time.Second); err != nil {
		t.Fatalf("Connect with the server certificate as root failed: %v", err)
	}
}

func TestConnectRejectsExpiredCertificate(t *testing.T) {
	ca := newTestCA(t)
	fc := startCloud(t, &fakeCloud{cert: ca.issue(t, time.Now().Add(-time.Minute), "127.0.0.1")})
	tc := fc.tunnel(&fakeBroker{})
	tc.rootCAs = ca.pool()

	err := awaitConnect(t, connectAsync(context.Background(), tc), 2*time.Second)
	var invalid x509.CertificateInvalidError
	if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
		t.Fatalf("Connect error = %v, want an expired certificate error", err)
	}
	if n := fc.auths.Load(); n != 0 {
		t.Fatalf("server with an expired certificate received %d auth frames, want 0", n)
	}
}

func TestConnectRejectsCertificateForAnotherHost(t *testing.T) {
	ca := newTestCA(t)
	fc := startCloud(t, &fakeCloud{cert: ca.issue(t, time.Now().Add(time.Hour), "tunnel.example.invalid")})
	tc := fc.tunnel(&fakeBroker{})
	tc.rootCAs = ca.pool()

	err := awaitConnect(t, connectAsync(context.Background(), tc), 2*time.Second)
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Fatalf("Connect error = %v, want a host name mismatch", err)
	}
	if n := fc.auths.Load(); n != 0 {
		t.Fatalf("server for another host received %d auth frames, want 0", n)
	}
}

func TestConnectVerifiesEndpointHostName(t *testing.T) {
	ca := newTestCA(t)
	fc := startCloud(t, &fakeCloud{cert: ca.issue(t, time.Now().Add(time.Hour), "localhost")})
	tc := fc.tunnel(&fakeBroker{})
	tc.Endpoint = net.JoinHostPort("localhost", portOf(t, fc.ln.Addr().String()))
	tc.rootCAs = ca.pool()
	t.Cleanup(tc.Close)

	if err := awaitConnect(t, connectAsync(context.Background(), tc), 2*time.Second); err != nil {
		t.Fatalf("Connect to a certificate issued for the endpoint host failed: %v", err)
	}
}

func TestDevelopmentModeAloneKeepsCertificateVerification(t *testing.T) {
	fc := startCloud(t, &fakeCloud{cert: selfSigned(t)})
	initApp(t, fc.ln.Addr().String(), map[string]string{"ENV_MODE": "development"})
	tc := NewTunnelConnection()
	tc.broker = &fakeBroker{}
	t.Cleanup(tc.Close)

	if err := awaitConnect(t, connectAsync(context.Background(), tc), 2*time.Second); err == nil {
		t.Fatal("Connect accepted an untrusted certificate in development mode")
	}
	if n := fc.auths.Load(); n != 0 {
		t.Fatalf("untrusted server received %d auth frames, want 0", n)
	}
}

func TestTunnelInsecureNoLongerSkipsCertificateVerification(t *testing.T) {
	fc := startCloud(t, &fakeCloud{cert: selfSigned(t)})
	initApp(t, fc.ln.Addr().String(), map[string]string{"TUNNEL_INSECURE": "1"})
	tc := NewTunnelConnection()
	tc.broker = &fakeBroker{}
	t.Cleanup(tc.Close)

	if err := awaitConnect(t, connectAsync(context.Background(), tc), 2*time.Second); err == nil {
		t.Fatal("Connect accepted an untrusted certificate with TUNNEL_INSECURE=1")
	}
	if n := fc.auths.Load(); n != 0 {
		t.Fatalf("untrusted server received %d auth frames, want 0", n)
	}
}

func TestConnectGivesUpOnSilentListener(t *testing.T) {
	fc := startCloud(t, &fakeCloud{mode: cloudSilent})
	tc := fc.tunnel(&fakeBroker{})
	tc.dialTimeout = 200 * time.Millisecond

	if err := awaitConnect(t, connectAsync(context.Background(), tc), tc.dialTimeout+time.Second); err == nil {
		t.Fatal("Connect succeeded against a listener that never speaks TLS")
	}
}

func TestConnectGivesUpWhenHelloNeverArrives(t *testing.T) {
	fc := startCloud(t, &fakeCloud{mode: cloudMute})
	tc := fc.tunnel(&fakeBroker{})
	tc.handshakeTimeout = 200 * time.Millisecond

	if err := awaitConnect(t, connectAsync(context.Background(), tc), tc.handshakeTimeout+time.Second); err == nil {
		t.Fatal("Connect succeeded without a hello frame")
	}
}

func TestConnectStopsWhenCancelledDuringDial(t *testing.T) {
	fc := startCloud(t, &fakeCloud{mode: cloudSilent})
	tc := fc.tunnel(&fakeBroker{})
	tc.dialTimeout = time.Minute

	ctx, cancel := context.WithCancel(context.Background())
	done := connectAsync(ctx, tc)
	waitFor(t, time.Second, "the dial to reach the listener", func() bool { return fc.accepts.Load() == 1 })
	cancel()

	if err := awaitConnect(t, done, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect error = %v, want context.Canceled", err)
	}
}

func TestConnectStopsWhenCancelledDuringHandshake(t *testing.T) {
	fc := startCloud(t, &fakeCloud{mode: cloudMute})
	tc := fc.tunnel(&fakeBroker{})
	tc.handshakeTimeout = time.Minute

	ctx, cancel := context.WithCancel(context.Background())
	done := connectAsync(ctx, tc)
	waitFor(t, time.Second, "the dial to reach the listener", func() bool { return fc.accepts.Load() == 1 })
	time.Sleep(50 * time.Millisecond)
	cancel()

	if err := awaitConnect(t, done, time.Second); err == nil {
		t.Fatal("Connect succeeded after its context was cancelled")
	}
}

func TestCloseDoesNotWaitForPendingConnect(t *testing.T) {
	fc := startCloud(t, &fakeCloud{mode: cloudSilent})
	tc := fc.tunnel(&fakeBroker{})
	tc.dialTimeout = time.Second

	done := connectAsync(context.Background(), tc)
	waitFor(t, time.Second, "the dial to reach the listener", func() bool { return fc.accepts.Load() == 1 })

	closed := make(chan struct{})
	go func() {
		tc.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close blocked while Connect was pending")
	}

	if err := awaitConnect(t, done, 3*time.Second); err == nil {
		t.Fatal("Connect succeeded on a closed tunnel")
	}
}

func TestCloseDuringHandshakeDiscardsNewSession(t *testing.T) {
	fc := startCloud(t, &fakeCloud{okDelay: 200 * time.Millisecond})
	tc := fc.tunnel(&fakeBroker{})

	done := connectAsync(context.Background(), tc)
	waitFor(t, time.Second, "the handshake to start", func() bool { return fc.accepts.Load() == 1 })
	tc.Close()

	if err := awaitConnect(t, done, 2*time.Second); err == nil {
		t.Fatal("Connect published a session on a closed tunnel")
	}
	if tc.IsConnected() {
		t.Fatal("closed tunnel reports connected")
	}
	waitFor(t, time.Second, "the cloud session to close", func() bool { return fc.openSessions() == 0 })
}

func TestForceReconnectKeepsHealthySession(t *testing.T) {
	fc := startCloud(t, &fakeCloud{})
	b := &fakeBroker{}
	c := runConnector(t, fc.tunnelFactory(b, nil), b, nil)
	waitFor(t, 2*time.Second, "the tunnel to connect", func() bool { return fc.openSessions() == 1 })

	forceReconnect(c)
	time.Sleep(c.forceGrace + 200*time.Millisecond)

	if n := fc.accepts.Load(); n != 1 {
		t.Fatalf("force-reconnect on a healthy tunnel opened %d connections, want 1", n)
	}
	if n := fc.openSessions(); n != 1 {
		t.Fatalf("open sessions = %d, want 1", n)
	}
}

func TestForceReconnectDuringHandshakeKeepsNewSession(t *testing.T) {
	fc := startCloud(t, &fakeCloud{okDelay: 150 * time.Millisecond})
	b := &fakeBroker{}
	c := runConnector(t, fc.tunnelFactory(b, nil), b, func(c *connector) { c.forceGrace = time.Second })
	waitFor(t, time.Second, "the handshake to start", func() bool { return fc.accepts.Load() == 1 })

	forceReconnect(c)
	waitFor(t, 2*time.Second, "the tunnel to connect", func() bool { return fc.openSessions() == 1 })
	time.Sleep(300 * time.Millisecond)

	if n := fc.accepts.Load(); n != 1 {
		t.Fatalf("force-reconnect during the handshake opened %d connections, want 1", n)
	}
	if n := fc.openSessions(); n != 1 {
		t.Fatalf("open sessions = %d, want 1", n)
	}
}

func TestForceReconnectRestartsStalledAttempt(t *testing.T) {
	fc := startCloud(t, &fakeCloud{mode: cloudSilent})
	b := &fakeBroker{}
	slowDial := func(tc *TunnelConnection) { tc.dialTimeout = time.Minute }
	c := runConnector(t, fc.tunnelFactory(b, slowDial), b, func(c *connector) { c.forceGrace = 100 * time.Millisecond })
	waitFor(t, time.Second, "the first dial", func() bool { return fc.accepts.Load() == 1 })

	forceReconnect(c)

	waitFor(t, time.Second, "a fresh dial after force-reconnect", func() bool { return fc.accepts.Load() == 2 })
}

func TestForceReconnectDuringFailingAttemptSkipsBackoff(t *testing.T) {
	fc := startCloud(t, &fakeCloud{okDelay: 150 * time.Millisecond, reply: "AUTH_FAIL: invalid token"})
	b := &fakeBroker{}
	c := runConnector(t, fc.tunnelFactory(b, nil), b, func(c *connector) {
		c.forceGrace = time.Second
		c.backoff = &backoff{base: 5 * time.Second, limit: 5 * time.Second, rnd: func(int64) int64 { return 0 }}
	})
	waitFor(t, time.Second, "the handshake to start", func() bool { return fc.accepts.Load() == 1 })

	forceReconnect(c)

	waitFor(t, time.Second, "a fresh dial after the failed attempt", func() bool { return fc.accepts.Load() == 2 })
}

func TestShortSessionBacksOffBeforeReconnecting(t *testing.T) {
	fc := startCloud(t, &fakeCloud{dropSessions: true})
	b := &fakeBroker{}
	base := 150 * time.Millisecond
	runConnector(t, fc.tunnelFactory(b, nil), b, func(c *connector) {
		c.backoff = &backoff{base: base, limit: time.Second, rnd: func(int64) int64 { return 0 }}
	})

	waitFor(t, 3*time.Second, "three connections", func() bool { return fc.accepts.Load() >= 3 })

	at := fc.acceptTimes()
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < base {
			t.Fatalf("reconnect %d came %v after the previous connection, want at least %v", i, gap, base)
		}
	}
}

func TestAuthFailurePublishesReason(t *testing.T) {
	fc := startCloud(t, &fakeCloud{reply: "AUTH_FAIL: invalid token"})
	b := &fakeBroker{}
	runConnector(t, fc.tunnelFactory(b, nil), b, nil)

	var payload map[string]any
	waitFor(t, 2*time.Second, "an auth-failed event", func() bool {
		data, ok := b.last(AuthFailedSubject)
		payload, _ = data.(map[string]any)
		return ok
	})

	if payload["reason"] != "invalid token" {
		t.Fatalf("auth-failed reason = %v, want %q", payload["reason"], "invalid token")
	}
	if msg, _ := payload["error"].(string); !strings.Contains(msg, "AUTH_FAIL: invalid token") {
		t.Fatalf("auth-failed error = %q, want it to carry the proxy reply", msg)
	}
}

func TestRepeatedConnectFailuresWarnOnce(t *testing.T) {
	addr := closedPort(t)
	b := &fakeBroker{}
	logs.reset()
	runConnector(t, func() *TunnelConnection {
		return &TunnelConnection{Endpoint: addr, LocalPort: "1", broker: b, dialTimeout: time.Second, handshakeTimeout: time.Second}
	}, b, nil)

	waitFor(t, 2*time.Second, "four failed attempts", func() bool { return len(logs.retryLevels()) >= 4 })

	levels := logs.retryLevels()
	if levels[0] != "warn" {
		t.Fatalf("first retry logged at %q, want warn", levels[0])
	}
	for i, level := range levels[1:] {
		if level != "debug" {
			t.Fatalf("retry %d logged at %q, want debug", i+2, level)
		}
	}
}

func TestCertificateFailureWarnsAfterConnectFailures(t *testing.T) {
	c := &connector{broker: &fakeBroker{}}
	logs.reset()

	last := c.reportFailure(errors.New("dial tcp: connection refused"), 1, time.Second, "")
	last = c.reportFailure(errors.New("dial tcp: connection refused"), 2, time.Second, last)
	certErr := fmt.Errorf("failed to dial: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
	c.reportFailure(certErr, 3, time.Second, last)

	levels := logs.retryLevels()
	if want := []string{"warn", "debug", "warn"}; !slices.Equal(levels, want) {
		t.Fatalf("retry levels = %v, want %v", levels, want)
	}
}

func TestBackendCloseEndsTunnelStream(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Read(make([]byte, 1024))
				_, _ = io.WriteString(c, "HTTP/1.0 200 OK\r\n\r\nhello")
			}()
		}
	}()
	cloud, agent := yamuxPair(t)
	tc := &TunnelConnection{LocalPort: portOf(t, backend.Addr().String())}
	go func() {
		stream, err := agent.Accept()
		if err != nil {
			return
		}
		tc.handleStream(stream)
	}()

	stream, err := cloud.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	if _, err := io.WriteString(stream, "GET / HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))

	body, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("response did not end when the backend closed: %v", err)
	}
	if !strings.HasSuffix(string(body), "hello") {
		t.Fatalf("response = %q, want the backend body", body)
	}
}

func TestUnreachableBackendAnswersBadGateway(t *testing.T) {
	cloud, agent := yamuxPair(t)
	tc := &TunnelConnection{LocalPort: portOf(t, closedPort(t))}
	go func() {
		stream, err := agent.Accept()
		if err != nil {
			return
		}
		tc.handleStream(stream)
	}()

	stream, err := cloud.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	if _, err := io.WriteString(stream, "GET /tunnel/check HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))

	status, err := bufio.NewReader(stream).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 502") {
		t.Fatalf("status line = %q, want 502", status)
	}
}

func (l *logCapture) Write(p []byte) (int, error) {
	var entry map[string]any
	if err := json.Unmarshal(p, &entry); err == nil {
		l.mu.Lock()
		l.entries = append(l.entries, entry)
		l.mu.Unlock()
	}
	return len(p), nil
}

func (l *logCapture) reset() {
	l.mu.Lock()
	l.entries = nil
	l.mu.Unlock()
}

func (l *logCapture) retryLevels() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var levels []string
	for _, e := range l.entries {
		_, hasAttempt := e["attempt"]
		_, hasDelay := e["retry_in"]
		if hasAttempt && hasDelay {
			level, _ := e["level"].(string)
			levels = append(levels, level)
		}
	}
	return levels
}

func (b *fakeBroker) RequestWithContext(_ context.Context, subject string, _ any) (*proxy.Response, error) {
	if subject != CredentialsSubject {
		return nil, errors.New("unexpected request to " + subject)
	}
	return &proxy.Response{Success: true, Data: testToken}, nil
}

func (b *fakeBroker) Publish(subject string, data any) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.published == nil {
		b.published = make(map[string][]any)
	}
	b.published[subject] = append(b.published[subject], data)
	return nil
}

func (b *fakeBroker) last(subject string) (any, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	events := b.published[subject]
	if len(events) == 0 {
		return nil, false
	}
	return events[len(events)-1], true
}

func (fc *fakeCloud) tunnel(b broker) *TunnelConnection {
	return &TunnelConnection{
		Endpoint:         fc.ln.Addr().String(),
		LocalPort:        "1",
		broker:           b,
		rootCAs:          fc.roots,
		dialTimeout:      time.Second,
		handshakeTimeout: time.Second,
	}
}

func (fc *fakeCloud) tunnelFactory(b broker, tune func(*TunnelConnection)) func() *TunnelConnection {
	return func() *TunnelConnection {
		tc := fc.tunnel(b)
		if tune != nil {
			tune(tc)
		}
		return tc
	}
}

func (fc *fakeCloud) openSessions() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	n := 0
	for _, s := range fc.sessions {
		if !s.IsClosed() {
			n++
		}
	}
	return n
}

func (fc *fakeCloud) acceptTimes() []time.Time {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return append([]time.Time(nil), fc.acceptedAt...)
}

func (fc *fakeCloud) acceptLoop() {
	for {
		c, err := fc.ln.Accept()
		if err != nil {
			return
		}
		fc.mu.Lock()
		fc.conns = append(fc.conns, c)
		fc.acceptedAt = append(fc.acceptedAt, time.Now())
		fc.mu.Unlock()
		fc.accepts.Add(1)

		switch fc.mode {
		case cloudServes:
			go fc.serve(c)
		case cloudMute:
			go func() { _ = c.(*tls.Conn).Handshake() }()
		case cloudSilent:
		}
	}
}

func (fc *fakeCloud) serve(c net.Conn) {
	if _, err := io.WriteString(c, `{"session_id":"`+testSessionID+`"}`+"\n"); err != nil {
		return
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	var auth AuthFrame
	if json.Unmarshal([]byte(line), &auth) != nil || auth.Type != "AUTH" || auth.SessionID != testSessionID || auth.AccessToken != testToken {
		_, _ = io.WriteString(c, "AUTH_FAIL: invalid frame\n")
		_ = c.Close()
		return
	}
	fc.auths.Add(1)

	time.Sleep(fc.okDelay)

	reply := fc.reply
	if reply == "" {
		reply = "OK"
	}
	if _, err := io.WriteString(c, reply+"\n"); err != nil || reply != "OK" {
		_ = c.Close()
		return
	}

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	s, err := yamux.Server(c, cfg)
	if err != nil {
		return
	}
	fc.mu.Lock()
	fc.sessions = append(fc.sessions, s)
	fc.mu.Unlock()
	if fc.dropSessions {
		_ = s.Close()
	}
}

func (fc *fakeCloud) close() {
	_ = fc.ln.Close()
	fc.mu.Lock()
	defer fc.mu.Unlock()
	for _, s := range fc.sessions {
		_ = s.Close()
	}
	for _, c := range fc.conns {
		_ = c.Close()
	}
}

func startCloud(t *testing.T, fc *fakeCloud) *fakeCloud {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fc.ln = raw
	if len(fc.cert.Certificate) == 0 {
		ca := newTestCA(t)
		fc.cert = ca.issue(t, time.Now().Add(time.Hour), "127.0.0.1")
		fc.roots = ca.pool()
	}
	if fc.mode != cloudSilent {
		fc.ln = tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{fc.cert}, MinVersion: tls.VersionTLS12})
	}
	go fc.acceptLoop()
	t.Cleanup(fc.close)
	return fc
}

func initApp(t *testing.T, endpoint string, env map[string]string) {
	t.Helper()
	saved := *app.GetConfig()
	t.Cleanup(func() { *app.GetConfig() = saved })

	base := map[string]string{
		"TUNNEL_ENDPOINT": endpoint,
		"LOCAL_PORT":      "1",
		"NATS_ENDPOINTS":  "nats://127.0.0.1:1",
		"NATS_USER":       "test",
		"NATS_PASSWORD":   "test",
		"ENV_MODE":        "",
		"TUNNEL_INSECURE": "",
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	app.Init()
}

func runConnector(t *testing.T, newTunnel func() *TunnelConnection, b broker, tune func(*connector)) *connector {
	t.Helper()
	c := &connector{
		broker:     b,
		newTunnel:  newTunnel,
		force:      make(chan struct{}, 1),
		backoff:    &backoff{base: 20 * time.Millisecond, limit: 100 * time.Millisecond, rnd: func(int64) int64 { return 0 }},
		forceGrace: 300 * time.Millisecond,
	}
	if tune != nil {
		tune(c)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		c.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("connect loop did not stop after cancel")
		}
	})
	return c
}

func forceReconnect(c *connector) {
	select {
	case c.force <- struct{}{}:
	default:
	}
}

func connectAsync(ctx context.Context, tc *TunnelConnection) <-chan error {
	done := make(chan error, 1)
	go func() { done <- tc.Connect(ctx) }()
	return done
}

func awaitConnect(t *testing.T, done <-chan error, within time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(within):
		t.Fatalf("Connect still blocked after %v", within)
		return nil
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func yamuxPair(t *testing.T) (cloud, agent *yamux.Session) {
	t.Helper()
	cloudSide, agentSide := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cloud, err := yamux.Server(cloudSide, cfg)
	if err != nil {
		t.Fatal(err)
	}
	agent, err = yamux.Client(agentSide, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cloud.Close()
		_ = agent.Close()
	})
	return cloud, agent
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

func (ca *testCA) issue(t *testing.T, notAfter time.Time, hosts ...string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    notAfter.Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (ca *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

func poolOf(t *testing.T, cert *tls.Certificate) *x509.CertPool {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return pool
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
