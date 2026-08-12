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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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
	"connecting":   "\u23F3",
	"connected":    "\U0001F510",
	"disconnected": "\U0001F513",
	"error":        "\u26D3\uFE0F\u200D\U0001F4A5",
}

// mutable VPN session state — all mutations happen on the HTTP server goroutine
var (
	vpnSID         string
	vpn            *vpnState
	activeCmd      *exec.Cmd
	connStatus     = "idle"
	sseClients     = map[chan string]struct{}{}
	pendingAuthURL string
	// wasConnected is true once the VPN has reached "connected" this run. It gates
	// auto-reconnect so we only re-auth after a dropped session — never on a fresh
	// container start or when the profile is invalid (never connected).
	wasConnected bool
	// reconnecting guards the on-visit auto-reconnect path from firing concurrently.
	reconnecting bool
	// saveProfileEnabled persists an uploaded profile to savedProfilePath for
	// one-click reconnect. Controlled by the SAVE_PROFILE env var (see main).
	saveProfileEnabled bool
	// pendingProfile holds an uploaded profile that is written to savedProfilePath
	// only once the VPN reports "connected" — so a bad profile is never saved.
	pendingProfile []byte
	// autoReconnectEnabled re-runs auth automatically when a user visits the web UI
	// after a dropped session. Controlled by the AUTO_RECONNECT env var (see main).
	autoReconnectEnabled bool
)

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
  <title>AWS VPN</title>
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
      <h2>AWS VPN</h2>
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

func fanOut(payload string) {
	for ch := range sseClients {
		select {
		case ch <- payload:
		default:
		}
	}
}

func setConnStatus(s string) {
	connStatus = s
	if s == "connected" {
		wasConnected = true
		if saveProfileEnabled && pendingProfile != nil {
			if err := saveProfile(pendingProfile); err != nil {
				log.Printf("save profile: %v", err)
			} else {
				log.Printf("profile saved to %s", savedProfilePath)
			}
			pendingProfile = nil
		}
	}
	if s == "connected" || s == "error" {
		pendingAuthURL = ""
	}
}

func broadcast(s string) {
	setConnStatus(s)
	fanOut(ssePayload(s, statusMessages[s]))
}

// loadProfile returns bytes of the profile saved from a web UI upload. ok is
// false when none has been saved yet.
func loadProfile() (data []byte, ok bool) {
	if b, err := os.ReadFile(savedProfilePath); err == nil {
		return b, true
	}
	return nil, false
}

func hasProfile() bool {
	_, ok := loadProfile()
	return ok
}

func saveProfile(data []byte) error {
	if err := os.MkdirAll(filepath.Dir(savedProfilePath), 0700); err != nil {
		return err
	}
	return os.WriteFile(savedProfilePath, data, 0600)
}

// clearSavedProfile drops any persisted profile and pending save. Called when a new
// upload arrives so a stale profile can't be reconnected to.
func clearSavedProfile() {
	pendingProfile = nil
	if err := os.Remove(savedProfilePath); err != nil && !os.IsNotExist(err) {
		log.Printf("clear saved profile: %v", err)
	}
}

// beginReconnect re-runs SAML auth from the saved profile, exactly as clicking
// the Reconnect button does, and returns the auth URL to redirect to.
func beginReconnect() (string, error) {
	data, ok := loadProfile()
	if !ok {
		return "", fmt.Errorf("no saved profile")
	}
	return beginAuth(data)
}

func listenEvents() {
	os.Remove(eventFifo)
	if err := syscall.Mkfifo(eventFifo, 0600); err != nil {
		log.Fatalf("mkfifo: %v", err)
	}
	// O_RDWR keeps the read end open so reads don't return EOF when no writer is connected
	f, err := os.OpenFile(eventFifo, os.O_RDWR, os.ModeNamedPipe)
	if err != nil {
		log.Fatalf("open fifo: %v", err)
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s == "connected" || s == "disconnected" {
			log.Printf("VPN status: %s", s)
			broadcast(s)
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

func getAuthURL(v *vpnState) (authURL, sid string, err error) {
	cmd := exec.Command("/usr/sbin/openvpn",
		"--config", v.confPath,
		"--verb", "3",
		"--log", "/dev/stdout",
		"--proto", v.proto,
		"--remote", v.srv, v.port,
		"--auth-user-pass", "/dev/stdin",
	)
	cmd.Stdin = strings.NewReader("N/A\nACS::" + port + "\n")

	log.Printf("running: %s", strings.Join(cmd.Args, " "))
	out, runErr := cmd.CombinedOutput()
	log.Printf("openvpn output:\n%s", out)
	if runErr != nil {
		log.Printf("openvpn exit: %v", runErr)
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

func connectVPN(v *vpnState, sid, encodedSAML string) {
	cmd := exec.Command("/usr/sbin/openvpn",
		"--config", v.confPath,
		"--verb", "3", "--auth-nocache",
		"--mute-replay-warnings", "--mssfix", "1300",
		"--proto", v.proto, "--remote", v.srv, v.port,
		"--script-security", "2",
		"--up", "/etc/openvpn/hooks/up",
		"--route-up", "/etc/openvpn/hooks/route-up",
		"--route-pre-down", "/etc/openvpn/hooks/route-pre-down",
		"--down", "/etc/openvpn/hooks/down",
		"--fast-io",
		"--auth-user-pass", "/dev/stdin",
	)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("N/A\nCRV1::%s::%s\n", sid, encodedSAML))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	activeCmd = cmd
	if err := cmd.Run(); err != nil {
		log.Printf("openvpn exited: %v", err)
	}
	activeCmd = nil
	broadcast("disconnected") // fallback if route-pre-down.sh didn't fire
}

func beginAuth(data []byte) (string, error) {
	state, err := processOVPN(data)
	if err != nil {
		return "", err
	}
	if vpn != nil {
		os.Remove(vpn.confPath)
	}
	if activeCmd != nil && activeCmd.Process != nil {
		log.Printf("Killing existing VPN connection")
		activeCmd.Process.Kill()
	}
	authURL, sid, err := getAuthURL(state)
	if err != nil || authURL == "" {
		if err == nil {
			err = fmt.Errorf("auth URL not found in openvpn output")
		}
		return "", err
	}
	vpn = state
	vpnSID = sid
	return authURL, nil
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 1)
	sseClients[ch] = struct{}{}
	defer delete(sseClients, ch)

	fmt.Fprintf(w, "%s\n\n", ssePayload(connStatus, statusMessages[connStatus]))
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

func handleUpload(w http.ResponseWriter, r *http.Request) {
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

	// A new upload supersedes any previously saved profile: drop the old file now,
	// regardless of outcome. The new one is only persisted once it connects.
	clearSavedProfile()

	authURL, err := beginAuth(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if saveProfileEnabled {
		pendingProfile = data // persisted only when the VPN reports "connected"
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Auto-reconnect: only after a session that was connected and then dropped
		// this run. wasConnected stays false on a fresh start or an invalid profile,
		// so neither triggers this.
		if autoReconnectEnabled && wasConnected && connStatus == "disconnected" && pendingAuthURL == "" && !reconnecting {
			reconnecting = true
			wasConnected = false
			authURL, err := beginReconnect()
			reconnecting = false
			if err != nil {
				log.Printf("auto-reconnect: %v", err)
			} else {
				pendingAuthURL = authURL
				log.Printf("auto-reconnect: session dropped, re-authenticating")
				http.Redirect(w, r, authURL, http.StatusFound)
				return
			}
		}
		if pendingAuthURL != "" {
			http.Redirect(w, r, pendingAuthURL, http.StatusFound)
			return
		}
	}
	if r.Method == http.MethodPost {
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
		log.Printf("Received SAML response, launching VPN connection.")
		if vpn != nil {
			broadcast("connecting")
			go connectVPN(vpn, vpnSID, encoded)
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	reconnectHTML := ""
	if hasProfile() {
		reconnectHTML = `<form id="reconnect" method="POST" action="/reconnect"><button type="submit">Reconnect with saved profile</button></form>`
	}
	fmt.Fprintf(w, indexHTML, statusEmojis[connStatus], connStatus, statusMessages[connStatus], reconnectHTML)
}

func handleReconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	authURL, err := beginReconnect()
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

func main() {
	saveProfileEnabled = envEnabled("SAVE_PROFILE")
	if saveProfileEnabled {
		log.Printf("SAVE_PROFILE enabled: uploaded profiles persisted to %s", savedProfilePath)
	}
	autoReconnectEnabled = envEnabled("AUTO_RECONNECT")
	if autoReconnectEnabled {
		log.Printf("AUTO_RECONNECT enabled: re-authenticate on visit after a dropped session")
	}

	go listenEvents()

	http.HandleFunc("/events", handleEvents)
	http.HandleFunc("/upload", handleUpload)
	http.HandleFunc("/reconnect", handleReconnect)
	http.HandleFunc("/", handleRoot)

	log.Printf("Listening at http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
