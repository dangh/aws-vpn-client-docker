package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const port = "35001"
const eventFifo = "/tmp/vpn-events"

var statusMessages = map[string]string{
	"idle":         "Disconnected \U0001F513",
	"connecting":   "Tunneling...",
	"connected":    "Connected \U0001F510",
	"disconnected": "Disconnected \U0001F513",
	"error":        "Server not found \u26D3\uFE0F\u200D\U0001F4A5",
}

var connectingVerbs = []string{
	"Tunneling...", "Encrypting...", "Negotiating...",
	"Authenticating...", "Routing...", "Securing...",
	"Handshaking...", "Cloaking...",
}

var stopConnecting chan struct{}

var (
	vpnSID     string
	vpn        *vpnState
	activeCmd  *exec.Cmd
	connStatus = "idle"
	sseClients = map[chan string]struct{}{}
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
    body { font-family: sans-serif; max-width: 480px; margin: 60px auto; padding: 0 16px; }
    h2 { margin-bottom: 24px; }
    label { display: block; margin-bottom: 8px; }
    #status { margin-bottom: 20px; padding: 10px 14px; border-radius: 4px; font-weight: bold; }
    #status.idle         { background: #f1f3f4; color: #666; }
    #status.connecting   { background: #fef9e7; color: #b45309; }
    #status.connected    { background: #e6f4ea; color: #2d6a2d; }
    #status.disconnected { background: #fce8e6; color: #c5221f; }
    #status.error        { background: #f3e8ff; color: #6b21a8; }
  </style>
</head>
<body>
  <h2>AWS VPN</h2>
  <div id="status" class="%s">%s</div>
  <form method="POST" action="/upload" enctype="multipart/form-data">
    <label>Select .ovpn file to connect</label>
    <input type="file" name="ovpn" accept=".ovpn" onchange="this.form.submit()">
  </form>
  <script>
    const el = document.getElementById('status');
    function setStatus(status, message) {
      el.className = status;
      el.textContent = message;
    }
    const es = new EventSource('/events');
    es.onmessage = ({ data }) => { const [s, m] = data.split('\n'); setStatus(s, m); };
    es.onerror = () => setStatus('error', 'Server not found \u26D3\uFE0F\u200D\uD83D\uDCA5');
  </script>
</body>
</html>`

func ssePayload(s string) string {
	return "data: " + s + "\ndata: " + statusMessages[s]
}

func fanOut(payload string) {
	for ch := range sseClients {
		select {
		case ch <- payload:
		default:
		}
	}
}

func broadcast(s string) {
	if stopConnecting != nil {
		close(stopConnecting)
		stopConnecting = nil
	}
	connStatus = s
	fanOut(ssePayload(s))
	if s == "connecting" {
		stopConnecting = make(chan struct{})
		go func(stop chan struct{}) {
			t := time.NewTicker(800 * time.Millisecond)
			defer t.Stop()
			i := 1
			for {
				select {
				case <-t.C:
					fanOut("data: connecting\ndata: " + connectingVerbs[i%len(connectingVerbs)])
					i++
				case <-stop:
					return
				}
			}
		}(stopConnecting)
	}
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
		default:
			if fields[0] == "proto" && len(fields) >= 2 {
				vpnProto = fields[1]
			}
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
		"--verb", "3", "--auth-nocache", "--inactive", "3600",
		"--proto", v.proto, "--remote", v.srv, v.port,
		"--script-security", "2",
		"--up", "/etc/openvpn/up.sh",
		"--route-up", "/etc/openvpn/route-up.sh",
		"--route-pre-down", "/etc/openvpn/route-pre-down.sh",
		"--down", "/etc/openvpn/down.sh",
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

func main() {
	go listenEvents()

	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
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

		fmt.Fprintf(w, "%s\n\n", ssePayload(connStatus))
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
	})

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
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

		state, err := processOVPN(data)
		if err != nil {
			http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
			return
		}

		if vpn != nil {
			os.Remove(vpn.confPath)
		}
		vpn = state

		if activeCmd != nil && activeCmd.Process != nil {
			log.Printf("Killing existing VPN connection for new profile")
			activeCmd.Process.Kill()
		}

		log.Printf("Config uploaded, resolved server %s:%s (%s)", state.srv, state.port, state.proto)

		authURL, sid, err := getAuthURL(state)
		if err != nil || authURL == "" {
			log.Printf("Failed to get auth URL: %v", err)
			http.Error(w, "Failed to get auth URL from openvpn", http.StatusInternalServerError)
			return
		}

		vpnSID = sid

		log.Printf("Redirecting to auth URL")
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				fmt.Fprintf(w, "ParseForm() err: %v", err)
				return
			}
			samlResponse := r.FormValue("SAMLResponse")
			if samlResponse == "" {
				log.Printf("SAMLResponse field is empty or not exists")
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
		fmt.Fprintf(w, indexHTML, connStatus, statusMessages[connStatus])
	})

	log.Printf("Listening at http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
