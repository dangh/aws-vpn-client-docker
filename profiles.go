package main

// Profile mode: one container runs every VPN profile, managed from a dashboard (see
// dashboard.go). The profiles live in /data/profiles.json. On first start, when that
// file does not exist, AWSVPN_CONFIG seeds it from a JSON file:
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
// The top-level "domains" are the default for a profile without its own (and for
// profiles added in the dashboard). Profile number n (kept for the profile's life)
// gets openvpn on device tun<n> with none of its pushed routes, and routing table and
// firewall mark 100+n: only sockets with that mark leave through the tunnel. sing-box
// (started from here, reloaded on change) makes each profile a tailnet node
// <hostname>: port 80 is an HTTP proxy that sends the profile's domains into its
// tunnel, resolved by the DNS server the VPN pushed, and everything else direct; port
// 8080 is the dashboard. The SAML callback port 35001 serves the dashboard too, and
// takes the SAML result for the profile that began auth last.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	dataDir       = "/data"
	statePath     = dataDir + "/profiles.json"
	runDir        = "/run/awsvpn"
	singBoxPath   = runDir + "/sing-box.json"
	profileHook   = "/etc/openvpn/hooks/profile"
	tailnetUIPort = 8080
	maxProfiles   = 99 // keeps ports and marks below in their ranges
)

// Per-profile ports, on 127.0.0.1 only: sing-box reaches them, nothing else does.
func proxyPort(n int) int { return 8000 + n }
func dnsPort(n int) int   { return 5300 + n }
func vpnMark(n int) int   { return 100 + n } // also the routing table id

// config is the seed file (AWSVPN_CONFIG).
type config struct {
	Tailnet  string          `json:"tailnet"`
	SSH      string          `json:"ssh"` // the VPN host as `ssh` takes it, for the tunnel hint
	Domains  []string        `json:"domains"`
	Profiles []profileConfig `json:"profiles"`
}

type profileConfig struct {
	Name     string   `json:"name"`
	Hostname string   `json:"hostname"`
	Domains  []string `json:"domains"`
}

// state is /data/profiles.json.
type state struct {
	Tailnet  string         `json:"tailnet,omitempty"`
	SSH      string         `json:"ssh,omitempty"`
	Domains  []string       `json:"domains,omitempty"` // default for new profiles
	Profiles []profileState `json:"profiles"`
}

type profileState struct {
	ID       string   `json:"id"` // data folder name; never changes
	N        int      `json:"n"`  // device, mark, table and ports; never changes
	Name     string   `json:"name"`
	Hostname string   `json:"hostname"`
	Domains  []string `json:"domains"`
}

var (
	// DNS-label shaped: ids and host names become paths, tags and tailnet names.
	labelRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	sshRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)
	domainRe = regexp.MustCompile(`^\.?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
)

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
	for i := range cfg.Profiles {
		pc := &cfg.Profiles[i]
		if !labelRe.MatchString(pc.Name) {
			return nil, fmt.Errorf("profile %d: name must be lowercase letters, digits and dashes", i+1)
		}
		if len(pc.Domains) == 0 {
			pc.Domains = cfg.Domains
		}
	}
	return &cfg, validate(seedState(&cfg))
}

func seedState(cfg *config) *state {
	st := &state{Tailnet: cfg.Tailnet, SSH: cfg.SSH, Domains: cfg.Domains}
	for i, pc := range cfg.Profiles {
		st.Profiles = append(st.Profiles, profileState{ID: pc.Name, N: i + 1, Name: pc.Name, Hostname: pc.Hostname, Domains: pc.Domains})
	}
	return st
}

// validate checks a whole state: what the dashboard changes is checked here too.
func validate(st *state) error {
	if len(st.Profiles) > maxProfiles {
		return fmt.Errorf("at most %d profiles", maxProfiles)
	}
	if st.SSH != "" && !sshRe.MatchString(st.SSH) {
		return fmt.Errorf("ssh %q: use a host name, optionally user@host", st.SSH)
	}
	seen := map[string]bool{}
	for _, ps := range st.Profiles {
		switch {
		case !labelRe.MatchString(ps.ID) || ps.N < 1 || ps.N > maxProfiles:
			return fmt.Errorf("profile %q: bad id or number", ps.ID)
		case strings.TrimSpace(ps.Name) == "" || len(ps.Name) > 40:
			return fmt.Errorf("profile %q: name must be 1 to 40 characters", ps.ID)
		case !labelRe.MatchString(ps.Hostname):
			return fmt.Errorf("profile %q: tailnet hostname %q: use lowercase letters, digits and dashes", ps.Name, ps.Hostname)
		case len(ps.Domains) == 0:
			return fmt.Errorf("profile %q: no domains", ps.Name)
		}
		for _, d := range ps.Domains {
			if !domainRe.MatchString(d) {
				return fmt.Errorf("profile %q: bad domain %q", ps.Name, d)
			}
		}
		for _, k := range []string{"id:" + ps.ID, "n:" + strconv.Itoa(ps.N), "name:" + ps.Name, "host:" + ps.Hostname} {
			if seen[k] {
				return fmt.Errorf("profile %q: %s is already used", ps.Name, strings.SplitN(k, ":", 2)[0])
			}
			seen[k] = true
		}
	}
	return nil
}

// manager owns the profiles: their state file, running profiles and sing-box.
type manager struct {
	mu       sync.Mutex
	st       state
	profiles map[string]*profile // by id
	active   atomic.Pointer[profile]
	singBox  *exec.Cmd

	loginMu   sync.Mutex
	loginURLs map[string]string // tailnet login URL sing-box logged, by id

	signIn *signIn // the AWS sign-in under way (m.mu)
}

// signIn is an AWS SAML sign-in the dashboard started: the browser is at the
// identity provider, and its result comes back on the one callback port.
type signIn struct {
	p   *profile
	url string
	at  time.Time
}

// An unfinished sign-in stops blocking others after this time.
const signInTimeout = 5 * time.Minute

// signingIn returns the AWS sign-in under way, or nil. m.mu held.
func (m *manager) signingIn() *signIn {
	a := m.signIn
	if a == nil || time.Since(a.at) > signInTimeout {
		return nil
	}
	a.p.mu.Lock()
	s := a.p.connStatus
	a.p.mu.Unlock()
	if s == "connected" || s == "connecting" {
		return nil
	}
	return a
}

func runProfiles(seed string) {
	m := &manager{profiles: map[string]*profile{}, loginURLs: map[string]string{}}
	if err := m.load(seed); err != nil {
		log.Fatalf("profiles: %v", err)
	}
	for _, ps := range m.st.Profiles {
		if err := m.startProfile(ps); err != nil {
			log.Fatalf("[%s] %v", ps.ID, err)
		}
	}
	if err := writeSingBoxConfig(&m.st); err != nil {
		log.Fatalf("sing-box config: %v", err)
	}
	if err := m.startSingBox(); err != nil {
		log.Fatalf("sing-box: %v", err)
	}
	log.Printf("dashboard and SAML callback on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, m.handler()))
}

func (m *manager) load(seed string) error {
	b, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		if seed == "" {
			return nil // no profiles yet: add them in the dashboard
		}
		cfg, err := loadConfig(seed)
		if err != nil {
			return err
		}
		m.st = *seedState(cfg)
		log.Printf("profiles seeded from %s", seed)
		return saveState(&m.st)
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &m.st); err != nil {
		return fmt.Errorf("%s: %w", statePath, err)
	}
	return validate(&m.st)
}

func saveState(st *state) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(statePath+".new", b, 0600); err != nil {
		return err
	}
	return os.Rename(statePath+".new", statePath)
}

// startProfile starts a profile's routing, DNS forwarder and event fifo.
func (m *manager) startProfile(ps profileState) error {
	run := filepath.Join(runDir, ps.ID)
	if err := os.MkdirAll(run, 0700); err != nil {
		return err
	}
	if err := setupRouting(vpnMark(ps.N)); err != nil {
		return fmt.Errorf("routing: %v", err)
	}
	hookArgs := []string{
		"--dev", "tun" + strconv.Itoa(ps.N), "--dev-type", "tun", "--route-noexec",
		"--setenv", "AWSVPN_RUN", run, "--setenv", "AWSVPN_TABLE", strconv.Itoa(vpnMark(ps.N)),
		"--up", profileHook, "--route-up", profileHook, "--route-pre-down", profileHook,
	}
	// After the SAML login the browser is on the callback port, which serves the dashboard.
	p := newProfile(ps.Name, filepath.Join(dataDir, ps.ID, "profile.ovpn"), filepath.Join(run, "events"), "/", hookArgs, nil)
	p.id = ps.ID
	p.onAuth = func() {
		m.active.Store(p)
		p.logf("SAML callback on :%s now goes to this profile", port)
	}
	if err := p.openEvents(); err != nil {
		return err
	}
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", dnsPort(ps.N)))
	if err != nil {
		p.close()
		return fmt.Errorf("dns: %v", err)
	}
	p.dns = pc
	go p.readEvents()
	go serveDNS(p, pc, filepath.Join(run, "dns"), vpnMark(ps.N))
	m.profiles[ps.ID] = p
	return nil
}

func (m *manager) stopProfile(ps profileState) {
	if p := m.profiles[ps.ID]; p != nil {
		p.close()
		m.active.CompareAndSwap(p, nil)
		if m.signIn != nil && m.signIn.p == p {
			m.signIn = nil
		}
		delete(m.profiles, ps.ID)
	}
	removeRouting(vpnMark(ps.N))
	os.RemoveAll(filepath.Join(runDir, ps.ID))
}

// apply checks the sing-box config of a changed state, saves the state and reloads
// sing-box. Nothing changes when the check fails.
func (m *manager) apply(st *state) error {
	if err := validate(st); err != nil {
		return err
	}
	if err := writeSingBoxConfig(st); err != nil {
		return err
	}
	if err := saveState(st); err != nil {
		writeSingBoxConfig(&m.st)
		return err
	}
	m.st = *st
	log.Printf("profiles changed: reloading sing-box")
	return m.singBox.Process.Signal(syscall.SIGHUP)
}

func (m *manager) addProfile(name, hostname string, domains []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := cloneState(&m.st)
	ps := profileState{ID: newID(name, st), N: freeN(st), Name: strings.TrimSpace(name), Hostname: hostname, Domains: domains}
	st.Profiles = append(st.Profiles, ps)
	if err := validate(st); err != nil {
		return err
	}
	if err := m.startProfile(ps); err != nil {
		m.stopProfile(ps)
		return err
	}
	if err := m.apply(st); err != nil {
		m.stopProfile(ps)
		return err
	}
	return nil
}

func (m *manager) updateProfile(id, name, hostname string, domains []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := cloneState(&m.st)
	i := slices.IndexFunc(st.Profiles, func(ps profileState) bool { return ps.ID == id })
	if i < 0 {
		return fmt.Errorf("no profile %q", id)
	}
	ps := &st.Profiles[i]
	ps.Name, ps.Hostname, ps.Domains = strings.TrimSpace(name), hostname, domains
	if err := m.apply(st); err != nil {
		return err
	}
	p := m.profiles[id]
	p.mu.Lock()
	p.name = ps.Name
	p.mu.Unlock()
	return nil
}

func (m *manager) deleteProfile(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := cloneState(&m.st)
	i := slices.IndexFunc(st.Profiles, func(ps profileState) bool { return ps.ID == id })
	if i < 0 {
		return fmt.Errorf("no profile %q", id)
	}
	ps := st.Profiles[i]
	st.Profiles = slices.Delete(st.Profiles, i, i+1)
	if err := m.apply(st); err != nil {
		return err
	}
	m.stopProfile(ps)
	m.loginMu.Lock()
	delete(m.loginURLs, id)
	m.loginMu.Unlock()
	// Keep the saved profile and node key for an undo: move them aside, not delete.
	trash := filepath.Join(dataDir, ".trash", id+"-"+time.Now().Format("20060102-150405"))
	log.Printf("[%s] deleted; its data moved to %s", id, trash)
	if err := os.MkdirAll(filepath.Dir(trash), 0700); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(dataDir, id), trash); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func cloneState(st *state) *state {
	c := *st
	c.Profiles = slices.Clone(st.Profiles)
	return &c
}

// newID makes a free id from a profile name.
func newID(name string, st *state) string {
	base := strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(base) > 24 {
		base = strings.Trim(base[:24], "-")
	}
	if base == "" {
		base = "profile"
	}
	used := func(id string) bool {
		return slices.ContainsFunc(st.Profiles, func(ps profileState) bool { return ps.ID == id })
	}
	id := base
	for i := 2; used(id); i++ {
		id = base + "-" + strconv.Itoa(i)
	}
	return id
}

func freeN(st *state) int {
	for n := 1; ; n++ {
		if !slices.ContainsFunc(st.Profiles, func(ps profileState) bool { return ps.N == n }) {
			return n
		}
	}
}

// setupRouting sends sockets with this mark to table mark. The table's fallback
// route is unreachable, so while the tunnel is down they fail instead of leaving
// direct; the hook adds the tunnel as the preferred default on route-up.
func setupRouting(mark int) error {
	removeRouting(mark)
	m := strconv.Itoa(mark)
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

func removeRouting(mark int) {
	m := strconv.Itoa(mark)
	for exec.Command("ip", "rule", "del", "fwmark", m).Run() == nil {
	}
	exec.Command("ip", "route", "flush", "table", m).Run()
}

// serveDNS forwards DNS queries to the servers the VPN pushed (dnsFile, written by
// the up hook), through the tunnel. The VPC resolver drops some lookups over the
// tunnel, so each query is resent every second, across the pushed servers, up to 5
// times. No cache: sing-box caches. Returns when pc is closed.
func serveDNS(p *profile, pc net.PacketConn, dnsFile string, mark int) {
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
		if errors.Is(err, net.ErrClosed) {
			return
		}
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

func writeSingBoxConfig(st *state) error {
	b, err := json.MarshalIndent(singBoxConfig(st), "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return err
	}
	tmp := singBoxPath + ".new"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if out, err := exec.Command("sing-box", "check", "-c", tmp).CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box check: %v: %s", err, out)
	}
	return os.Rename(tmp, singBoxPath)
}

var (
	ansiRe  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	loginRe = regexp.MustCompile(`endpoint/tailscale\[ts-([a-z0-9-]+)\]: Waiting for authentication: (https://\S+)`)
)

// startSingBox runs sing-box, copies its log to ours and keeps the tailnet login
// URLs it logs for the dashboard.
func (m *manager) startSingBox() error {
	cmd := exec.Command("sing-box", "run", "-c", singBoxPath)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	m.singBox = cmd
	go func() {
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			line := ansiRe.ReplaceAllString(scanner.Text(), "")
			if s := loginRe.FindStringSubmatch(line); s != nil {
				m.loginMu.Lock()
				m.loginURLs[s[1]] = s[2]
				m.loginMu.Unlock()
			}
			fmt.Println(line)
		}
		io.Copy(io.Discard, out)
		log.Fatalf("sing-box exited: %v", cmd.Wait())
	}()
	return nil
}

// loginURL returns the URL to log the profile's tailnet node in, or "" when it is
// logged in: the node's state has a login profile only after login.
func (m *manager) loginURL(id string) string {
	b, _ := os.ReadFile(filepath.Join(dataDir, id, "tailscale", "tailscaled.state"))
	if bytes.Contains(b, []byte(`"profile-`)) {
		return ""
	}
	m.loginMu.Lock()
	defer m.loginMu.Unlock()
	return m.loginURLs[id]
}

type obj = map[string]any

var blockedCIDRs = []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "::/128", "::1/128", "fe80::/10"}

func singBoxConfig(st *state) obj {
	servers := []any{obj{"type": "local", "tag": "local"}}
	outbounds := []any{obj{"type": "direct", "tag": "direct"}}
	endpoints, inbounds, rules := []any{}, []any{}, []any{}
	for _, ps := range st.Profiles {
		n, id := ps.N, ps.ID
		servers = append(servers, obj{"type": "udp", "tag": "dns-" + id, "server": "127.0.0.1", "server_port": dnsPort(n)})
		endpoints = append(endpoints, obj{
			"type": "tailscale", "tag": "ts-" + id, "hostname": ps.Hostname,
			"state_directory": filepath.Join(dataDir, id, "tailscale"),
		})
		inbounds = append(inbounds, obj{"type": "http", "tag": "proxy-" + id, "listen": "127.0.0.1", "listen_port": proxyPort(n)})
		outbounds = append(outbounds, obj{
			"type": "direct", "tag": "vpn-" + id, "routing_mark": vpnMark(n),
			// the tunnel carries IPv4 only
			"domain_resolver": obj{"server": "dns-" + id, "strategy": "ipv4_only"},
		})
		rules = append(rules,
			// tailnet node: 80 = proxy, 8080 = dashboard, nothing else
			obj{"inbound": "ts-" + id, "port": 80, "outbound": "direct", "override_address": "127.0.0.1", "override_port": proxyPort(n)},
			obj{"inbound": "ts-" + id, "port": tailnetUIPort, "outbound": "direct", "override_address": "127.0.0.1", "override_port": 35001},
			obj{"inbound": "ts-" + id, "action": "reject"},
			// The proxy must not reach this container's loopback (the other profiles'
			// proxies, the dashboard and DNS forwarders) or link-local addresses; the
			// direct path must not reach private networks (the NAS LAN, Docker
			// networks). VPN domains may resolve to private VPC addresses.
			obj{"inbound": "proxy-" + id, "ip_cidr": blockedCIDRs, "action": "reject"},
			obj{"inbound": "proxy-" + id, "domain_suffix": ps.Domains, "outbound": "vpn-" + id},
			obj{"inbound": "proxy-" + id, "action": "resolve"},
			obj{"inbound": "proxy-" + id, "ip_cidr": blockedCIDRs, "action": "reject"},
			obj{"inbound": "proxy-" + id, "ip_is_private": true, "action": "reject"},
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
