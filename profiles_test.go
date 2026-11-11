package main

import (
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
	if got := cfg.Profiles[0].Domains; !reflect.DeepEqual(got, []string{".aws"}) {
		t.Errorf("corp domains = %v, want the top-level list", got)
	}
	if got := cfg.Profiles[1].Domains; !reflect.DeepEqual(got, []string{".example.com"}) {
		t.Errorf("prod domains = %v, want its own list", got)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	for name, s := range map[string]string{
		"no profiles":        `{"profiles": []}`,
		"no domains":         `{"profiles": [{"name": "corp", "hostname": "corp-proxy"}]}`,
		"duplicate name":     `{"domains": [".aws"], "profiles": [{"name": "a", "hostname": "x"}, {"name": "a", "hostname": "y"}]}`,
		"duplicate hostname": `{"domains": [".aws"], "profiles": [{"name": "a", "hostname": "x"}, {"name": "b", "hostname": "x"}]}`,
		"bad name":           `{"domains": [".aws"], "profiles": [{"name": "../a", "hostname": "x"}]}`,
		"unknown field":      `{"domains": [".aws"], "profiles": [{"name": "a", "hostname": "x", "port": 1}]}`,
	} {
		if _, err := loadConfig(writeConfig(t, s)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
