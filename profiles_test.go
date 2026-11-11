package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeConfig(t *testing.T, s string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigDefaultsDomains(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, `{"domains": [".aws"], "profiles": [
		{"name": "corp", "hostname": "corp-proxy"},
		{"name": "prod", "hostname": "prod-proxy", "domains": [".example.com"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	st := seedState(cfg)
	if got := st.Profiles[0]; got.ID != "corp" || got.N != 1 || !reflect.DeepEqual(got.Domains, []string{".aws"}) {
		t.Errorf("corp = %+v, want id corp, n 1, the top-level domains", got)
	}
	if got := st.Profiles[1]; got.N != 2 || !reflect.DeepEqual(got.Domains, []string{".example.com"}) {
		t.Errorf("prod = %+v, want n 2, its own domains", got)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	for name, s := range map[string]string{
		"no domains":         `{"profiles": [{"name": "corp", "hostname": "corp-proxy"}]}`,
		"duplicate name":     `{"domains": [".aws"], "profiles": [{"name": "a", "hostname": "x"}, {"name": "a", "hostname": "y"}]}`,
		"duplicate hostname": `{"domains": [".aws"], "profiles": [{"name": "a", "hostname": "x"}, {"name": "b", "hostname": "x"}]}`,
		"bad name":           `{"domains": [".aws"], "profiles": [{"name": "../a", "hostname": "x"}]}`,
		"bad domain":         `{"domains": ["a b"], "profiles": [{"name": "a", "hostname": "x"}]}`,
		"unknown field":      `{"domains": [".aws"], "profiles": [{"name": "a", "hostname": "x", "port": 1}]}`,
	} {
		if _, err := loadConfig(writeConfig(t, s)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := loadConfig(writeConfig(t, `{"domains": [".aws"], "profiles": []}`)); err != nil {
		t.Errorf("no profiles: %v, want ok (added in the dashboard)", err)
	}
}

func TestNewIDAndFreeN(t *testing.T) {
	st := &state{Profiles: []profileState{{ID: "corp", N: 1}, {ID: "corp-2", N: 3}}}
	for name, want := range map[string]string{"Corp": "corp-3", "Prod EU!": "prod-eu", "!!!": "profile"} {
		if got := newID(name, st); got != want {
			t.Errorf("newID(%q) = %q, want %q", name, got, want)
		}
	}
	if got := freeN(st); got != 2 {
		t.Errorf("freeN = %d, want the lowest free number 2", got)
	}
}

func TestSplitDomains(t *testing.T) {
	got := splitDomains(".A.com, .b.com\r\n.c.com  .d.com\n")
	if want := []string{".a.com", ".b.com", ".c.com", ".d.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("splitDomains = %v, want %v", got, want)
	}
}

func TestGuard(t *testing.T) {
	m := &manager{st: state{Tailnet: "example.ts.net", Profiles: []profileState{{ID: "corp", Hostname: "corp-proxy"}}}}
	h := m.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, c := range []struct {
		method, host, path, origin string
		want                       int
	}{
		{"GET", "localhost:35001", "/", "", 200},
		{"GET", "corp-proxy.example.ts.net:8080", "/", "", 200},
		{"GET", "rebound.evil.example:35001", "/", "", 403},
		{"POST", "localhost:35001", "/add", "", 403},
		{"POST", "localhost:35001", "/add", "http://evil.example", 403},
		{"POST", "localhost:35001", "/add", "http://localhost:35001", 200},
		{"POST", "127.0.0.1:35001", "/", "https://idp.example", 200}, // SAML result
	} {
		r := httptest.NewRequest(c.method, "http://"+c.host+c.path, nil)
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s %s%s origin %q: %d, want %d", c.method, c.host, c.path, c.origin, w.Code, c.want)
		}
	}
}
