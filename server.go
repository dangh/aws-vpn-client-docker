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
	"sync"
)

const port = "35001"

var (
	mu     sync.Mutex
	vpnSID string
	vpn    *vpnState
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
  </style>
</head>
<body>
  <h2>AWS VPN</h2>
  <form method="POST" action="/upload" enctype="multipart/form-data">
    <label>Select .ovpn file to connect</label>
    <input type="file" name="ovpn" accept=".ovpn" onchange="this.form.submit()">
  </form>
</body>
</html>`

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
		"--down", "/etc/openvpn/down.sh",
		"--fast-io",
		"--auth-user-pass", "/dev/stdin",
	)
	cmd.Stdin = strings.NewReader(fmt.Sprintf("N/A\nCRV1::%s::%s\n", sid, encodedSAML))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("openvpn exited: %v", err)
	}
}

func main() {
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

		mu.Lock()
		if vpn != nil {
			os.Remove(vpn.confPath)
		}
		vpn = state
		mu.Unlock()

		log.Printf("Config uploaded, resolved server %s:%s (%s)", state.srv, state.port, state.proto)

		authURL, sid, err := getAuthURL(state)
		if err != nil || authURL == "" {
			log.Printf("Failed to get auth URL: %v", err)
			http.Error(w, "Failed to get auth URL from openvpn", http.StatusInternalServerError)
			return
		}

		mu.Lock()
		vpnSID = sid
		mu.Unlock()

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
			mu.Lock()
			sid := vpnSID
			v := vpn
			mu.Unlock()
			encoded := url.QueryEscape(samlResponse)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "Connecting to VPN...<script>window.close()</script>")
			log.Printf("Received SAML response, launching VPN connection.")
			if v != nil {
				go connectVPN(v, sid, encoded)
			}
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, indexHTML)
	})

	log.Printf("Listening at http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
