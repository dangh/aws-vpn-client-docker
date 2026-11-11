package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

const (
	port = "35001"
	// savedProfilePath holds a profile persisted from a web UI upload (see
	// SAVE_PROFILE). Mount /data as a volume to keep it across container recreation.
	savedProfilePath = "/data/profile.ovpn"
	eventFifo        = "/tmp/vpn-events"
)

var statusMessages = map[string]string{
	"idle":         "Disconnected",
	"connecting":   "Connecting...",
	"connected":    "Connected",
	"disconnected": "Disconnected",
	"error":        "Container's down",
}

var statusEmojis = map[string]string{
	"idle":         "\U0001F513",
	"connecting":   "⏳",
	"connected":    "\U0001F510",
	"disconnected": "\U0001F513",
	"error":        "⛓️‍\U0001F4A5",
}

var (
	// saveProfileEnabled persists an uploaded profile to savedProfilePath for
	// one-click reconnect. Controlled by the SAVE_PROFILE env var (see main).
	saveProfileEnabled bool
	// autoReconnectEnabled re-runs auth automatically when a user visits the web UI
	// after a dropped session. Controlled by the AUTO_RECONNECT env var (see main).
	autoReconnectEnabled bool
)

// profile is one VPN connection with its own web UI. The single-profile modes run
// one; profile mode (AWSVPN_CONFIG, see profiles.go) runs one per configured profile.
type profile struct {
	id          string // profile mode: stable id (data and run folders); "" otherwise
	name        string
	profilePath string   // saved profile (savedProfilePath in single-profile mode)
	eventFifo   string   // the openvpn hooks write connected/disconnected here
	hookArgs    []string // openvpn hook and device flags for the connected session
	onAuth      func()   // called when SAML auth begins (routes the 35001 callback here)
	mux         *http.ServeMux

	// publicURL is where the browser is sent after the SAML callback completes.
	// With the shared 35001 dispatcher a relative "/" would strand the user on the
	// dispatcher; PUBLIC_PORT sets this to http://localhost:<port> so they land
	// back on this profile's own web UI. PUBLIC_URL sets the full URL instead (wins
	// over PUBLIC_PORT), for a UI served under its own name, e.g. a Tailscale node.
	// Defaults to "/".
	publicURL string

	fifo *os.File // event fifo, open while the profile runs
	dns  io.Closer

	// mutable VPN session state, guarded by mu
	mu             sync.Mutex
	vpnSID         string
	vpn            *vpnState
	activeCmd      *exec.Cmd
	connStatus     string
	sseClients     map[chan string]struct{}
	pendingAuthURL string
	// wasConnected is true once the VPN has reached "connected" this run. It gates
	// auto-reconnect so we only re-auth after a dropped session — never on a fresh
	// container start or when the profile is invalid (never connected).
	wasConnected bool
	// reconnecting guards the on-visit auto-reconnect path from firing concurrently.
	reconnecting bool
	// pendingProfile holds an uploaded profile that is written to savedProfilePath
	// only once the VPN reports "connected" — so a bad profile is never saved.
	pendingProfile []byte
}

// legacyHookArgs are the openvpn hooks of the single-profile modes: the tunnel
// becomes the default route and the alpine scripts rewrite /etc/resolv.conf.
var legacyHookArgs = []string{
	"--up", "/etc/openvpn/hooks/up",
	"--route-up", "/etc/openvpn/hooks/route-up",
	"--route-pre-down", "/etc/openvpn/hooks/route-pre-down",
	"--down", "/etc/openvpn/hooks/down",
}

func newProfile(name, profilePath, fifo, publicURL string, hookArgs []string, onAuth func()) *profile {
	p := &profile{
		name:        name,
		profilePath: profilePath,
		eventFifo:   fifo,
		hookArgs:    hookArgs,
		onAuth:      onAuth,
		publicURL:   publicURL,
		connStatus:  "idle",
		sseClients:  map[chan string]struct{}{},
		mux:         http.NewServeMux(),
	}
	p.mux.HandleFunc("/events", p.handleEvents)
	p.mux.HandleFunc("/upload", p.handleUpload)
	p.mux.HandleFunc("/reconnect", p.handleReconnect)
	p.mux.HandleFunc("/", p.handleRoot)
	return p
}

func (p *profile) logf(format string, args ...any) {
	if p.id != "" {
		format = "[" + p.id + "] " + format
	}
	log.Printf(format, args...)
}

type vpnState struct {
	confPath string
	srv      string
	port     string
	proto    string
}

var urlRe = regexp.MustCompile(`https://\S+`)

const indexHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>%s</title>
  <style>
    body { font-family: sans-serif; margin: 60px auto; padding: 0 16px; max-width: 560px; }
    #app { display: grid; grid-template-columns: auto 1fr; column-gap: 24px; row-gap: 20px; }
    #emoji { grid-column: 1; grid-row: 1; align-self: center; font-size: 6em; line-height: 1; }
    #top { grid-column: 2; grid-row: 1; }
    #rest { grid-column: 2; grid-row: 2; }
    h2 { margin: 0 0 12px; }
    label { display: block; margin-bottom: 8px; }
    #status { display: inline-block; padding: 6px 14px; border-radius: 4px; font-weight: bold; }
    #status.idle         { background: #f1f3f4; color: #666; }
    #status.connecting   { background: #fef9e7; color: #b45309; }
    #status.connected    { background: #e6f4ea; color: #2d6a2d; }
    #status.disconnected { background: #fce8e6; color: #c5221f; }
    #status.error        { background: #f3e8ff; color: #6b21a8; }
    #reconnect { margin-top: 20px; }
    #reconnect button { padding: 8px 16px; font-size: 1em; cursor: pointer; }
  </style>
</head>
<body>
  <div id="app">
    <span id="emoji">%s</span>
    <div id="top">
      <h2>%s</h2>
      <div id="status" class="%s">%s</div>
    </div>
    <div id="rest">
      <form method="POST" action="/upload" enctype="multipart/form-data">
        <label>Select .ovpn file to connect</label>
        <input type="file" name="ovpn" accept=".ovpn" onchange="this.form.submit()">
      </form>
      %s
    </div>
  </div>
  <script>
    const emojis = { idle: '🔓', connecting: '⏳', connected: '🔐', disconnected: '🔓', error: '⛓️‍💥' };
    const statusEl = document.getElementById('status');
    const emojiEl = document.getElementById('emoji');
    function setStatus(status, message) {
      statusEl.className = status;
      emojiEl.textContent = emojis[status] || '';
      statusEl.textContent = message;
    }
    const es = new EventSource('/events');
    es.onmessage = ({ data }) => { const { status, message } = JSON.parse(data); setStatus(status, message); };
    es.onerror = () => setStatus('error', "Container's down");
  </script>
</body>
</html>`

func ssePayload(status, message string) string {
	b, _ := json.Marshal(map[string]string{"status": status, "message": message})
	return "data: " + string(b)
}

func (p *profile) fanOut(payload string) {
	for ch := range p.sseClients {
		select {
		case ch <- payload:
		default:
		}
	}
}

func (p *profile) setConnStatus(s string) {
	p.connStatus = s
	if s == "connected" {
		p.wasConnected = true
		if saveProfileEnabled && p.pendingProfile != nil {
			if err := p.saveProfile(p.pendingProfile); err != nil {
				p.logf("save profile: %v", err)
			} else {
				p.logf("profile saved to %s", p.profilePath)
			}
			p.pendingProfile = nil
		}
	}
	if s == "connected" || s == "error" {
		p.pendingAuthURL = ""
	}
}

func (p *profile) broadcast(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.broadcastLocked(s)
}

func (p *profile) broadcastLocked(s string) {
	p.setConnStatus(s)
	p.fanOut(ssePayload(s, statusMessages[s]))
}

// loadProfile returns bytes of the profile saved from a web UI upload. ok is
// false when none has been saved yet.
func (p *profile) loadProfile() (data []byte, ok bool) {
	if b, err := os.ReadFile(p.profilePath); err == nil {
		return b, true
	}
	return nil, false
}

func (p *profile) hasProfile() bool {
	_, ok := p.loadProfile()
	return ok
}

func (p *profile) saveProfile(data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p.profilePath), 0700); err != nil {
		return err
	}
	return os.WriteFile(p.profilePath, data, 0600)
}

// clearSavedProfile drops any persisted profile and pending save. Called when a new
// upload arrives so a stale profile can't be reconnected to.
func (p *profile) clearSavedProfile() {
	p.pendingProfile = nil
	if err := os.Remove(p.profilePath); err != nil && !os.IsNotExist(err) {
		p.logf("clear saved profile: %v", err)
	}
}

// beginReconnect re-runs SAML auth from the saved profile, exactly as clicking
// the Reconnect button does, and returns the auth URL to redirect to.
func (p *profile) beginReconnect() (string, error) {
	data, ok := p.loadProfile()
	if !ok {
		return "", fmt.Errorf("no saved profile")
	}
	return p.beginAuth(data)
}

// openEvents creates the fifo the openvpn hooks report to; readEvents then reads it
// until close.
func (p *profile) openEvents() error {
	os.Remove(p.eventFifo)
	if err := syscall.Mkfifo(p.eventFifo, 0600); err != nil {
		return fmt.Errorf("mkfifo: %v", err)
	}
	// O_RDWR keeps the read end open so reads don't return EOF when no writer is connected
	f, err := os.OpenFile(p.eventFifo, os.O_RDWR, os.ModeNamedPipe)
	if err != nil {
		return fmt.Errorf("open fifo: %v", err)
	}
	p.fifo = f
	return nil
}

func (p *profile) readEvents() {
	scanner := bufio.NewScanner(p.fifo)
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s == "connected" || s == "disconnected" {
			p.logf("VPN status: %s", s)
			p.broadcast(s)
		}
	}
}

func processOVPN(data []byte) (*vpnState, error) {
	var vpnHost, vpnPort, vpnProto string
	var lines []string

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			lines = append(lines, line)
			continue
		}
		switch fields[0] {
		case "auth-user-pass", "auth-federate", "auth-retry", "remote-random-hostname":
			// strip
		case "remote":
			if len(fields) >= 3 {
				vpnHost = fields[1]
				vpnPort = fields[2]
			}
			// strip — server address is resolved via DNS and passed via --remote flag
		case "proto":
			if len(fields) >= 2 {
				vpnProto = fields[1]
			}
			lines = append(lines, line)
		default:
			lines = append(lines, line)
		}
	}

	if vpnHost == "" {
		return nil, fmt.Errorf("no remote directive found in config")
	}
	if vpnProto == "" {
		vpnProto = "tcp"
	}

	randBytes := make([]byte, 12)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("rand: %v", err)
	}
	lookup := hex.EncodeToString(randBytes) + "." + vpnHost
	addrs, err := net.LookupHost(lookup)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("DNS lookup for %s: %v", lookup, err)
	}

	tmp, err := os.CreateTemp("", "vpn-*.ovpn")
	if err != nil {
		return nil, err
	}
	defer tmp.Close()
	if _, err := tmp.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return nil, err
	}

	return &vpnState{
		confPath: tmp.Name(),
		srv:      addrs[0],
		port:     vpnPort,
		proto:    vpnProto,
	}, nil
}

func (p *profile) getAuthURL(v *vpnState) (authURL, sid string, err error) {
	cmd := exec.Command("/usr/sbin/openvpn",
		"--config", v.confPath,
		"--verb", "3",
		"--log", "/dev/stdout",
		"--proto", v.proto,
		"--remote", v.srv, v.port,
		"--auth-user-pass", "/dev/stdin",
	)
	cmd.Stdin = strings.NewReader("N/A\nACS::" + port + "\n")

	p.logf("running: %s", strings.Join(cmd.Args, " "))
	out, runErr := cmd.CombinedOutput()
	p.logf("openvpn output:\n%s", out)
	if runErr != nil {
		p.logf("openvpn exit: %v", runErr)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "AUTH_FAILED,CRV1") {
			authURL = urlRe.FindString(line)
			parts := strings.Split(line, ":")
			if len(parts) >= 7 {
				sid = parts[6]
			}
			return
		}
	}
	err = fmt.Errorf("AUTH_FAILED,CRV1 not found in openvpn output")
	return
}

func (p *profile) connectVPN(v *vpnState, sid, encodedSAML string) {
	args := []string{
		"--config", v.confPath,
		"--verb", "3", "--auth-nocache",
		"--mute-replay-warnings", "--mssfix", "1300",
		"--proto", v.proto, "--remote", v.srv, v.port,
		"--script-security", "2",
	}
	args = append(args, p.hookArgs...)
	args = append(args, "--fast-io", "--auth-user-pass", "/dev/stdin")
	cmd := exec.Command("/usr/sbin/openvpn", args...)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("N/A\nCRV1::%s::%s\n", sid, encodedSAML))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	p.mu.Lock()
	err := cmd.Start()
	if err == nil {
		p.activeCmd = cmd
	}
	p.mu.Unlock()
	if err == nil {
		err = cmd.Wait()
	}
	if err != nil {
		p.logf("openvpn exited: %v", err)
	}
	p.mu.Lock()
	if p.activeCmd == cmd {
		p.activeCmd = nil
	}
	p.mu.Unlock()
	p.broadcast("disconnected") // fallback if route-pre-down.sh didn't fire
}

// disconnect stops the VPN session; no auto-reconnect follows.
func (p *profile) disconnect() {
	p.mu.Lock()
	cmd := p.activeCmd
	p.wasConnected = false
	p.pendingAuthURL = ""
	p.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		p.logf("disconnecting")
		cmd.Process.Kill()
	}
}

// close disconnects and stops the profile's listeners (profile deleted).
func (p *profile) close() {
	p.disconnect()
	if p.fifo != nil {
		p.fifo.Close()
		os.Remove(p.eventFifo)
	}
	if p.dns != nil {
		p.dns.Close()
	}
}

// beginAuth runs with p.mu held.
func (p *profile) beginAuth(data []byte) (string, error) {
	state, err := processOVPN(data)
	if err != nil {
		return "", err
	}
	if p.vpn != nil {
		os.Remove(p.vpn.confPath)
	}
	if p.activeCmd != nil && p.activeCmd.Process != nil {
		p.logf("Killing existing VPN connection")
		p.activeCmd.Process.Kill()
	}
	authURL, sid, err := p.getAuthURL(state)
	if err != nil || authURL == "" {
		if err == nil {
			err = fmt.Errorf("auth URL not found in openvpn output")
		}
		return "", err
	}
	p.vpn = state
	p.vpnSID = sid
	if p.onAuth != nil {
		p.onAuth()
	}
	return authURL, nil
}

// registerACS tells the shared dispatcher (see runDispatcher) that this instance
// just began SAML auth, so the fixed 127.0.0.1:35001 callback is routed here. It
// is a no-op unless ACS_DISPATCHER and ACS_SELF are set, so single-profile
// deployments are unaffected. Auth is serialized on the host's one 35001, so
// "last to begin auth wins" is the correct routing.
func registerACS() {
	dispatcher := os.Getenv("ACS_DISPATCHER") // e.g. http://dispatcher:35001
	self := os.Getenv("ACS_SELF")             // e.g. vpn-a:35001
	if dispatcher == "" || self == "" {
		return
	}
	u := dispatcher + "/_register?target=" + url.QueryEscape(self)
	resp, err := http.Post(u, "text/plain", nil)
	if err != nil {
		log.Printf("ACS register failed: %v", err)
		return
	}
	resp.Body.Close()
	log.Printf("ACS registered with dispatcher as %s", self)
}

func (p *profile) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 1)
	p.mu.Lock()
	p.sseClients[ch] = struct{}{}
	status := p.connStatus
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.sseClients, ch)
		p.mu.Unlock()
	}()

	fmt.Fprintf(w, "%s\n\n", ssePayload(status, statusMessages[status]))
	flusher.Flush()

	for {
		select {
		case s := <-ch:
			fmt.Fprintf(w, "%s\n\n", s)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (p *profile) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		http.Error(w, "failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("ovpn")
	if err != nil {
		http.Error(w, "missing ovpn file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// A new upload supersedes any previously saved profile: drop the old file now,
	// regardless of outcome. The new one is only persisted once it connects.
	p.clearSavedProfile()

	authURL, err := p.beginAuth(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if saveProfileEnabled {
		p.pendingProfile = data // persisted only when the VPN reports "connected"
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (p *profile) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		p.handleSAML(w, r)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Method == http.MethodGet {
		// Auto-reconnect: only after a session that was connected and then dropped
		// this run. wasConnected stays false on a fresh start or an invalid profile,
		// so neither triggers this.
		if autoReconnectEnabled && p.wasConnected && p.connStatus == "disconnected" && p.pendingAuthURL == "" && !p.reconnecting {
			p.reconnecting = true
			p.wasConnected = false
			authURL, err := p.beginReconnect()
			p.reconnecting = false
			if err != nil {
				p.logf("auto-reconnect: %v", err)
			} else {
				p.pendingAuthURL = authURL
				p.logf("auto-reconnect: session dropped, re-authenticating")
				http.Redirect(w, r, authURL, http.StatusFound)
				return
			}
		}
		if p.pendingAuthURL != "" {
			http.Redirect(w, r, p.pendingAuthURL, http.StatusFound)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html")
	reconnectHTML := ""
	if p.hasProfile() {
		reconnectHTML = `<form id="reconnect" method="POST" action="/reconnect"><button type="submit">Reconnect with saved profile</button></form>`
	}
	title := "AWS VPN"
	if p.name != "" {
		title += ": " + p.name
	}
	fmt.Fprintf(w, indexHTML, title, statusEmojis[p.connStatus], title, p.connStatus, statusMessages[p.connStatus], reconnectHTML)
}

// handleSAML takes the SAML result AWS posts to the callback port and connects.
func (p *profile) handleSAML(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse error: "+err.Error(), http.StatusBadRequest)
		return
	}
	samlResponse := r.FormValue("SAMLResponse")
	if samlResponse == "" {
		http.Error(w, "missing SAMLResponse", http.StatusBadRequest)
		return
	}
	encoded := url.QueryEscape(samlResponse)
	p.logf("Received SAML response, launching VPN connection.")
	// The auth URL is consumed — clear it so GET / doesn't bounce back to SAML
	// (which would auto-POST again via an active IdP session and reload-loop).
	p.pendingAuthURL = ""
	if p.vpn != nil {
		p.broadcastLocked("connecting")
		go p.connectVPN(p.vpn, p.vpnSID, encoded)
	}
	http.Redirect(w, r, p.publicURL, http.StatusFound)
}

func (p *profile) handleReconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	p.mu.Lock()
	authURL, err := p.beginReconnect()
	p.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func envEnabled(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// runDispatcher is the shared front for the host's single 127.0.0.1:35001, used
// when running several VPN profiles at once. AWS mandates the SAML callback ACS
// URL be exactly http://127.0.0.1:35001 for every profile, so only one process
// can own that host port. This dispatcher owns it and forwards each SAML POST to
// whichever VPN instance most recently began auth (registered via /_register).
// Enabled by DISPATCHER=true. See compose.yml.
func runDispatcher() {
	var mu sync.Mutex
	var target string // host:port of the instance currently awaiting its SAML callback

	// Allow-list of upstreams the dispatcher may forward to, from
	// ACS_ALLOWED_TARGETS (space-separated, e.g. "vpn-a:35001 vpn-b:35001").
	// /_register is reachable by any local process or an in-browser page via
	// 127.0.0.1:35001, so an unconstrained target is an SSRF that would leak the
	// SAML assertion to an attacker-chosen host. Fail closed: unknown or empty
	// list rejects everything.
	allowed := map[string]bool{}
	for _, t := range strings.Fields(os.Getenv("ACS_ALLOWED_TARGETS")) {
		allowed[t] = true
	}
	if len(allowed) == 0 {
		log.Printf("dispatcher: WARNING ACS_ALLOWED_TARGETS is empty; all /_register requests will be rejected")
	}

	http.HandleFunc("/_register", func(w http.ResponseWriter, r *http.Request) {
		t := r.URL.Query().Get("target")
		if t == "" {
			http.Error(w, "missing target", http.StatusBadRequest)
			return
		}
		if !allowed[t] {
			log.Printf("dispatcher: rejected /_register for disallowed target %q", t)
			http.Error(w, "target not allowed", http.StatusForbidden)
			return
		}
		mu.Lock()
		target = t
		mu.Unlock()
		log.Printf("dispatcher: active auth target = %s", t)
		w.WriteHeader(http.StatusNoContent)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		t := target
		mu.Unlock()
		if t == "" {
			http.Error(w, "no active auth target; start a connection from a VPN web UI first", http.StatusServiceUnavailable)
			return
		}
		httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: t}).ServeHTTP(w, r)
	})

	log.Printf("dispatcher listening on :%s, forwarding SAML callback to the active target", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func main() {
	if envEnabled("DISPATCHER") {
		runDispatcher()
		return
	}

	saveProfileEnabled = envEnabled("SAVE_PROFILE")
	if saveProfileEnabled {
		log.Printf("SAVE_PROFILE enabled: uploaded profiles persisted")
	}
	autoReconnectEnabled = envEnabled("AUTO_RECONNECT")
	if autoReconnectEnabled {
		log.Printf("AUTO_RECONNECT enabled: re-authenticate on visit after a dropped session")
	}

	if _, err := os.Stat(statePath); err == nil || os.Getenv("AWSVPN_CONFIG") != "" {
		runProfiles(os.Getenv("AWSVPN_CONFIG"))
		return
	}

	publicURL := "/"
	if u := os.Getenv("PUBLIC_URL"); u != "" {
		publicURL = u
		log.Printf("PUBLIC_URL set: redirecting to %s after auth", publicURL)
	} else if p := os.Getenv("PUBLIC_PORT"); p != "" {
		publicURL = "http://localhost:" + p
		log.Printf("PUBLIC_PORT set: redirecting to %s after auth", publicURL)
	}

	p := newProfile("", savedProfilePath, eventFifo, publicURL, legacyHookArgs, registerACS)
	if err := p.openEvents(); err != nil {
		log.Fatal(err)
	}
	go p.readEvents()

	log.Printf("Listening at http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, p.mux); err != nil {
		log.Fatal(err)
	}
}
