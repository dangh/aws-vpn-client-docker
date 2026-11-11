package main

import (
	"bytes"
	"embed"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// handler serves the dashboard (every profile) on the SAML callback port; each
// profile's tailnet node forwards its port 8080 here. A POST to / is the SAML
// result, for the profile that began auth last.
func (m *manager) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { m.handleDashboard(w, nil) })
	mux.HandleFunc("POST /{$}", m.handleCallback)
	mux.HandleFunc("GET /events", m.handleVersion)
	mux.HandleFunc("POST /add", func(w http.ResponseWriter, r *http.Request) {
		f := postedForm(r, "add")
		m.saved(w, r, f, m.addProfile(f.Name, f.Hostname, splitDomains(f.Domains)))
	})
	mux.HandleFunc("GET /p/{id}/events", m.withProfile(func(p *profile, w http.ResponseWriter, r *http.Request) { p.handleEvents(w, r) }))
	mux.HandleFunc("GET /p/{id}/login", m.withProfile(func(p *profile, w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		u := ""
		if a := m.signingIn(); a != nil && a.p == p {
			u = a.url // empty while the attempt is still starting
		}
		m.mu.Unlock()
		if u == "" {
			p.mu.Lock()
			u = p.pendingAuthURL // an auto-reconnect
			p.mu.Unlock()
		}
		if u == "" {
			u = "/"
		}
		http.Redirect(w, r, u, http.StatusFound)
	}))
	mux.HandleFunc("POST /p/{id}/upload", m.withProfile(m.connect((*profile).handleUpload)))
	mux.HandleFunc("POST /p/{id}/reconnect", m.withProfile(m.connect((*profile).handleReconnect)))
	mux.HandleFunc("POST /p/{id}/disconnect", m.withProfile(func(p *profile, w http.ResponseWriter, r *http.Request) {
		p.disconnect()
		m.endSignIn(p)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}))
	mux.HandleFunc("POST /p/{id}/edit", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		f := postedForm(r, "edit-"+id)
		m.saved(w, r, f, m.updateProfile(id, f.Name, f.Hostname, splitDomains(f.Domains)))
	})
	mux.HandleFunc("POST /p/{id}/delete", func(w http.ResponseWriter, r *http.Request) {
		if err := m.deleteProfile(r.PathValue("id")); err != nil {
			m.fail(w, "Could not delete the profile", err.Error(), "")
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	return m.guard(mux)
}

// guard serves only requests to this dashboard's own names (no DNS rebinding), and
// refuses a POST that another site's page sent: it must carry its own Origin. The
// SAML result is the exception, which the identity provider's page posts to /.
func (m *manager) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.ownHost(r.Host) {
			http.Error(w, "unknown host name", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path != "/" {
			u, err := url.Parse(r.Header.Get("Origin"))
			if err != nil || u.Host != r.Host {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (m *manager) ownHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.ContainsFunc(m.st.Profiles, func(ps profileState) bool {
		return host == ps.Hostname || (m.st.Tailnet != "" && host == ps.Hostname+"."+m.st.Tailnet)
	})
}

func (m *manager) withProfile(h func(*profile, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		p := m.profiles[r.PathValue("id")]
		m.mu.Unlock()
		if p == nil {
			http.NotFound(w, r)
			return
		}
		h(p, w, r)
	}
}

// catchWriter passes a response through, except an error, which it keeps.
type catchWriter struct {
	http.ResponseWriter
	code int
	body bytes.Buffer
}

func (c *catchWriter) WriteHeader(code int) {
	c.code = code
	if code < 400 {
		c.ResponseWriter.WriteHeader(code)
	}
}

func (c *catchWriter) Write(b []byte) (int, error) {
	if c.code == 0 {
		c.WriteHeader(http.StatusOK)
	}
	if c.code >= 400 {
		return c.body.Write(b)
	}
	return c.ResponseWriter.Write(b)
}

// formView is what a profile form shows: the profile, or what was posted when it was
// not saved.
type formView struct {
	Dialog, Name, Hostname, Domains, Error string
}

func postedForm(r *http.Request, dialog string) formView {
	return formView{Dialog: dialog, Name: r.FormValue("name"), Hostname: strings.TrimSpace(r.FormValue("hostname")), Domains: r.FormValue("domains")}
}

// saved answers a profile form: back to the dashboard, or, when it was not saved, the
// dashboard with that form open again, its input kept and the reason shown.
func (m *manager) saved(w http.ResponseWriter, r *http.Request, f formView, err error) {
	if err != nil {
		// The form names the profile already: drop validate's `profile "x": ` prefix.
		msg := profilePrefix.ReplaceAllString(err.Error(), "")
		f.Error = strings.ToUpper(msg[:1]) + msg[1:] + "."
		m.handleDashboard(w, &f)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

var profilePrefix = regexp.MustCompile(`^profile "[^"]*": `)

func (m *manager) fail(w http.ResponseWriter, title, msg, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Del("X-Content-Type-Options")
	w.WriteHeader(http.StatusBadRequest)
	pages.ExecuteTemplate(w, "error.html", map[string]string{"Title": title, "Message": msg, "Detail": detail})
}

// splitDomains reads a domain list typed one per line, or separated by commas or spaces.
func splitDomains(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
}

type profileView struct {
	ID, Name, Hostname, Host, Status, StatusText, LoginURL string
	Domains                                                []string
	HasProfile, Running, SigningIn                         bool
	BlockedBy                                              string // another profile's sign-in is under way
	Form                                                   formView
}

func (m *manager) handleDashboard(w http.ResponseWriter, posted *formView) {
	m.mu.Lock()
	a := m.signingIn()
	var views []profileView
	connected := 0
	for _, ps := range m.st.Profiles {
		p := m.profiles[ps.ID]
		host := ps.Hostname
		if m.st.Tailnet != "" {
			host += "." + m.st.Tailnet
		}
		v := profileView{ID: ps.ID, Name: ps.Name, Hostname: ps.Hostname, Host: host,
			Domains: ps.Domains, LoginURL: m.loginURL(ps.ID), HasProfile: p.hasProfile(),
			Form: formView{Dialog: "edit-" + ps.ID, Name: ps.Name, Hostname: ps.Hostname, Domains: strings.Join(ps.Domains, "\n")}}
		p.mu.Lock()
		v.Status = p.connStatus
		v.SigningIn = p.pendingAuthURL != "" || (a != nil && a.p == p)
		v.Running = p.activeCmd != nil || v.Status == "connected" || v.Status == "connecting"
		p.mu.Unlock()
		if a != nil && a.p != p {
			v.BlockedBy = a.p.name
		}
		if posted != nil && posted.Dialog == v.Form.Dialog {
			v.Form = *posted
		}
		v.StatusText = statusMessages[v.Status]
		if v.Status == "connected" {
			connected++
		}
		views = append(views, v)
	}
	add := formView{Dialog: "add", Domains: strings.Join(m.st.Domains, "\n")}
	if posted != nil && posted.Dialog == "add" {
		add = *posted
	}
	open := ""
	if posted != nil {
		open = posted.Dialog
	}
	data := struct {
		Profiles           []profileView
		Connected, Version int
		Tailnet, SSH, Open string
		Add                formView
	}{views, connected, m.version, m.st.Tailnet, m.st.SSH, open, add}
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if posted != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	pages.ExecuteTemplate(w, "dashboard.html", data)
}

//go:embed ui/*.html
var uiFiles embed.FS

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"icon": func(name string) template.HTML {
		return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` + icons[name] + `</svg>`)
	},
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	},
}).ParseFS(uiFiles, "ui/*.html"))

// Lucide icons (lucide-static 0.468.0, ISC license): the inner SVG markup.
var icons = map[string]string{
	"check":          `<path d="M20 6 9 17l-5-5"/>`,
	"chevron-down":   `<path d="m6 9 6 6 6-6"/>`,
	"refresh-cw":     `<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>`,
	"terminal":       `<polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/>`,
	"wifi-off":       `<path d="M12 20h.01"/><path d="M8.5 16.429a5 5 0 0 1 7 0"/><path d="M5 12.859a10 10 0 0 1 5.17-2.69"/><path d="M19 12.859a10 10 0 0 0-2.007-1.523"/><path d="M2 8.82a15 15 0 0 1 4.177-2.643"/><path d="M22 8.82a15 15 0 0 0-11.288-3.764"/><path d="m2 2 20 20"/>`,
	"copy":           `<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>`,
	"ellipsis":       `<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>`,
	"info":           `<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>`,
	"loader-circle":  `<path d="M21 12a9 9 0 1 1-6.219-8.56"/>`,
	"log-in":         `<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" x2="3" y1="12" y2="12"/>`,
	"pencil":         `<path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/><path d="m15 5 4 4"/>`,
	"plug-zap":       `<path d="M6.3 20.3a2.4 2.4 0 0 0 3.4 0L12 18l-6-6-2.3 2.3a2.4 2.4 0 0 0 0 3.4Z"/><path d="m2 22 3-3"/><path d="M7.5 13.5 10 11"/><path d="M10.5 16.5 13 14"/><path d="m18 3-4 4h6l-4 4"/>`,
	"plus":           `<path d="M5 12h14"/><path d="M12 5v14"/>`,
	"power":          `<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/>`,
	"shield-check":   `<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>`,
	"trash-2":        `<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/>`,
	"triangle-alert": `<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>`,
	"upload":         `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" x2="12" y1="3" y2="15"/>`,
	"x":              `<path d="M18 6 6 18"/><path d="m6 6 12 12"/>`,
}
