package main

// Profile mode: one container runs every VPN profile in AWSVPN_CONFIG, a JSON file:
//
//	{
//	  "tailnet": "example.ts.net",
//	  "domains": [".amazonaws.com", ".aws"],
//	  "profiles": [
//	    {"name": "corp", "hostname": "corp-proxy"},
//	    {"name": "prod", "hostname": "prod-proxy", "domains": [".amazonaws.com"]}
//	  ]
//	}
//
// Profile n (1-based, in file order) gets openvpn on device tun<n> with none of its
// pushed routes, and routing table and firewall mark 100+n: only sockets with that
// mark leave through the tunnel. sing-box (started from here) makes each profile a
// tailnet node <hostname>: port 80 is an HTTP proxy that sends the profile's domains
// (default: the top-level "domains") into its tunnel, resolved by the DNS server the
// VPN pushed, and everything else direct; port 8080 is the profile's web UI. The
// SAML callback port 35001 serves the profile that began auth last.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	dataDir       = "/data"
	runDir        = "/run/awsvpn"
	profileHook   = "/etc/openvpn/hooks/profile"
	tailnetUIPort = 8080
)

// Per-profile ports, on 127.0.0.1 only: sing-box reaches them, nothing else does.
func proxyPort(n int) int { return 8000 + n }
func uiPort(n int) int    { return 35100 + n }
func dnsPort(n int) int   { return 5300 + n }
func vpnMark(n int) int   { return 100 + n } // also the routing table id

type config struct {
	Tailnet  string          `json:"tailnet"`
	Domains  []string        `json:"domains"`
	Profiles []profileConfig `json:"profiles"`
}

type profileConfig struct {
	Name     string   `json:"name"`
	Hostname string   `json:"hostname"`
	Domains  []string `json:"domains"`
}

// DNS-label shaped: names become paths, tags and tailnet host names.
var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var cfg config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(cfg.Profiles) == 0 {
		return nil, errors.New("no profiles")
	}
	seen := map[string]bool{}
	for i := range cfg.Profiles {
		pc := &cfg.Profiles[i]
		if !labelRe.MatchString(pc.Name) || !labelRe.MatchString(pc.Hostname) {
			return nil, fmt.Errorf("profile %d: name and hostname must be lowercase letters, digits and dashes", i+1)
		}
		if seen["n:"+pc.Name] || seen["h:"+pc.Hostname] {
			return nil, fmt.Errorf("profile %q: duplicate name or hostname", pc.Name)
		}
		seen["n:"+pc.Name], seen["h:"+pc.Hostname] = true, true
		if len(pc.Domains) == 0 {
			pc.Domains = cfg.Domains
		}
		if len(pc.Domains) == 0 {
			return nil, fmt.Errorf("profile %q: no domains", pc.Name)
		}
	}
	return &cfg, nil
}

func runProfiles(path string) {
	cfg, err := loadConfig(path)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	var active atomic.Pointer[profile] // the profile awaiting its SAML callback
	for i, pc := range cfg.Profiles {
		n := i + 1
		run := filepath.Join(runDir, pc.Name)
		if err := os.MkdirAll(run, 0700); err != nil {
			log.Fatal(err)
		}
		if err := setupRouting(vpnMark(n)); err != nil {
			log.Fatalf("[%s] routing: %v", pc.Name, err)
		}

		publicURL := fmt.Sprintf("http://%s:%d/", pc.Hostname, tailnetUIPort)
		if cfg.Tailnet != "" {
			publicURL = fmt.Sprintf("http://%s.%s:%d/", pc.Hostname, cfg.Tailnet, tailnetUIPort)
		}
		hookArgs := []string{
			"--dev", "tun" + strconv.Itoa(n), "--dev-type", "tun", "--route-noexec",
			"--setenv", "AWSVPN_RUN", run, "--setenv", "AWSVPN_TABLE", strconv.Itoa(vpnMark(n)),
			"--up", profileHook, "--route-up", profileHook, "--route-pre-down", profileHook,
		}
		p := newProfile(pc.Name, filepath.Join(dataDir, pc.Name, "profile.ovpn"), filepath.Join(run, "events"), publicURL, hookArgs, nil)
		p.onAuth = func() {
			active.Store(p)
			p.logf("SAML callback on :%s now goes to this profile", port)
		}
		go p.listenEvents()
		go serveDNS(p, fmt.Sprintf("127.0.0.1:%d", dnsPort(n)), filepath.Join(run, "dns"), vpnMark(n))
		go func() {
			log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", uiPort(n)), p.mux))
		}()
		p.logf("web UI %s, tailnet node %s", publicURL, pc.Hostname)
	}

	if err := startSingBox(cfg); err != nil {
		log.Fatalf("sing-box: %v", err)
	}

	log.Printf("SAML callback listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := active.Load()
		if p == nil {
			http.Error(w, "no active auth target; start a connection from a VPN web UI first", http.StatusServiceUnavailable)
			return
		}
		p.mux.ServeHTTP(w, r)
	})))
}

// setupRouting sends sockets with this mark to table mark. The table's fallback
// route is unreachable, so while the tunnel is down they fail instead of leaving
// direct; the hook adds the tunnel as the preferred default on route-up.
func setupRouting(mark int) error {
	m := strconv.Itoa(mark)
	for exec.Command("ip", "rule", "del", "fwmark", m).Run() == nil {
	}
	for _, args := range [][]string{
		{"rule", "add", "fwmark", m, "lookup", m, "priority", m},
		{"route", "replace", "unreachable", "default", "table", m, "metric", "4294967295"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

// serveDNS forwards DNS queries to the servers the VPN pushed (dnsFile, written by
// the up hook), through the tunnel. The VPC resolver drops some lookups over the
// tunnel, so each query is resent every second, across the pushed servers, up to 5
// times. No cache: sing-box caches.
func serveDNS(p *profile, addr, dnsFile string, mark int) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("[%s] dns: %v", p.name, err)
	}
	dialer := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return serr
	}}
	buf := make([]byte, 65535)
	for {
		n, client, err := pc.ReadFrom(buf)
		if err != nil {
			p.logf("dns: %v", err)
			continue
		}
		query := bytes.Clone(buf[:n])
		go func() {
			b, _ := os.ReadFile(dnsFile)
			servers := strings.Fields(string(b))
			if len(servers) == 0 {
				return // not connected yet: let the client time out
			}
			resp := make([]byte, 65535)
			for try := 0; try < 5; try++ {
				conn, err := dialer.Dial("udp", net.JoinHostPort(servers[try%len(servers)], "53"))
				if err != nil {
					return
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				_, err = conn.Write(query)
				if err == nil {
					var m int
					if m, err = conn.Read(resp); err == nil {
						conn.Close()
						pc.WriteTo(resp[:m], client)
						return
					}
				}
				conn.Close()
			}
		}()
	}
}

func startSingBox(cfg *config) error {
	b, err := json.MarshalIndent(singBoxConfig(cfg), "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(runDir, "sing-box.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		return err
	}
	cmd := exec.Command("sing-box", "run", "-c", path)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { log.Fatalf("sing-box exited: %v", cmd.Wait()) }()
	return nil
}

type obj = map[string]any

var blockedCIDRs = []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "::/128", "::1/128", "fe80::/10"}

func singBoxConfig(cfg *config) obj {
	servers := []any{obj{"type": "local", "tag": "local"}}
	outbounds := []any{obj{"type": "direct", "tag": "direct"}}
	var endpoints, inbounds, rules []any
	for i, pc := range cfg.Profiles {
		n, name := i+1, pc.Name
		servers = append(servers, obj{"type": "udp", "tag": "dns-" + name, "server": "127.0.0.1", "server_port": dnsPort(n)})
		endpoints = append(endpoints, obj{
			"type": "tailscale", "tag": "ts-" + name, "hostname": pc.Hostname,
			"state_directory": filepath.Join(dataDir, name, "tailscale"),
		})
		inbounds = append(inbounds, obj{"type": "http", "tag": "proxy-" + name, "listen": "127.0.0.1", "listen_port": proxyPort(n)})
		outbounds = append(outbounds, obj{
			"type": "direct", "tag": "vpn-" + name, "routing_mark": vpnMark(n),
			// the tunnel carries IPv4 only
			"domain_resolver": obj{"server": "dns-" + name, "strategy": "ipv4_only"},
		})
		rules = append(rules,
			// tailnet node: 80 = proxy, 8080 = web UI, nothing else
			obj{"inbound": "ts-" + name, "port": 80, "outbound": "direct", "override_address": "127.0.0.1", "override_port": proxyPort(n)},
			obj{"inbound": "ts-" + name, "port": tailnetUIPort, "outbound": "direct", "override_address": "127.0.0.1", "override_port": uiPort(n)},
			obj{"inbound": "ts-" + name, "action": "reject"},
			// The proxy must not reach this container's loopback (the other profiles'
			// proxies, web UIs and DNS forwarders) or link-local addresses; the direct
			// path must not reach private networks (the NAS LAN, Docker networks).
			// VPN domains may resolve to private VPC addresses.
			obj{"inbound": "proxy-" + name, "ip_cidr": blockedCIDRs, "action": "reject"},
			obj{"inbound": "proxy-" + name, "domain_suffix": pc.Domains, "outbound": "vpn-" + name},
			obj{"inbound": "proxy-" + name, "action": "resolve"},
			obj{"inbound": "proxy-" + name, "ip_cidr": blockedCIDRs, "action": "reject"},
			obj{"inbound": "proxy-" + name, "ip_is_private": true, "action": "reject"},
		)
	}
	return obj{
		"log":       obj{"level": "info"},
		"dns":       obj{"servers": servers, "final": "local"},
		"endpoints": endpoints,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     obj{"rules": rules, "final": "direct", "default_domain_resolver": "local"},
	}
}
