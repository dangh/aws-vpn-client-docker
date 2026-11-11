package main

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

// handler serves the dashboard (every profile) on the SAML callback port; each
// profile's tailnet node forwards its port 8080 here. A POST to / is the SAML
// result, for the profile that began auth last.
func (m *manager) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", m.handleDashboard)
	mux.HandleFunc("POST /{$}", func(w http.ResponseWriter, r *http.Request) {
		p := m.active.Load()
		if p == nil {
			http.Error(w, "no active auth target; start a connection from the dashboard first", http.StatusServiceUnavailable)
			return
		}
		p.handleSAML(w, r)
	})
	mux.HandleFunc("POST /add", func(w http.ResponseWriter, r *http.Request) {
		m.done(w, r, m.addProfile(r.FormValue("name"), r.FormValue("hostname"), splitDomains(r.FormValue("domains"))))
	})
	mux.HandleFunc("GET /p/{id}/events", m.withProfile(func(p *profile, w http.ResponseWriter, r *http.Request) { p.handleEvents(w, r) }))
	mux.HandleFunc("GET /p/{id}/login", m.withProfile(func(p *profile, w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		u := p.pendingAuthURL
		p.mu.Unlock()
		if u == "" {
			u = "/"
		}
		http.Redirect(w, r, u, http.StatusFound)
	}))
	mux.HandleFunc("POST /p/{id}/upload", m.withProfile(func(p *profile, w http.ResponseWriter, r *http.Request) { p.handleUpload(w, r) }))
	mux.HandleFunc("POST /p/{id}/reconnect", m.withProfile(func(p *profile, w http.ResponseWriter, r *http.Request) { p.handleReconnect(w, r) }))
	mux.HandleFunc("POST /p/{id}/disconnect", m.withProfile(func(p *profile, w http.ResponseWriter, r *http.Request) {
		p.disconnect()
		m.done(w, r, nil)
	}))
	mux.HandleFunc("POST /p/{id}/edit", func(w http.ResponseWriter, r *http.Request) {
		m.done(w, r, m.updateProfile(r.PathValue("id"), r.FormValue("name"), r.FormValue("hostname"), splitDomains(r.FormValue("domains"))))
	})
	mux.HandleFunc("POST /p/{id}/delete", func(w http.ResponseWriter, r *http.Request) {
		m.done(w, r, m.deleteProfile(r.PathValue("id")))
	})
	return sameOrigin(mux)
}

// sameOrigin refuses a POST that another site's page sent (the browser says so in
// Origin), except the SAML result, which the identity provider's page posts to /.
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path != "/" {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					http.Error(w, "cross-site request refused", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
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

func (m *manager) done(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		errorTmpl.Execute(w, err.Error())
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// splitDomains reads a domain list typed one per line, or separated by commas or spaces.
func splitDomains(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
}

type profileView struct {
	ID, Name, Hostname, Host, Domains   string
	Status, StatusText, Emoji, LoginURL string
	PendingAuth, HasProfile, Running    bool
}

func (m *manager) handleDashboard(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	var views []profileView
	for _, ps := range m.st.Profiles {
		p := m.profiles[ps.ID]
		host := ps.Hostname
		if m.st.Tailnet != "" {
			host += "." + m.st.Tailnet
		}
		v := profileView{ID: ps.ID, Name: ps.Name, Hostname: ps.Hostname, Host: host,
			Domains: strings.Join(ps.Domains, "\n"), LoginURL: m.loginURL(ps.ID), HasProfile: p.hasProfile()}
		p.mu.Lock()
		v.Status, v.PendingAuth, v.Running = p.connStatus, p.pendingAuthURL != "", p.activeCmd != nil
		p.mu.Unlock()
		v.StatusText, v.Emoji = statusMessages[v.Status], statusEmojis[v.Status]
		views = append(views, v)
	}
	defaults := strings.Join(m.st.Domains, "\n")
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardTmpl.Execute(w, struct {
		Profiles []profileView
		Domains  string
	}{views, defaults})
}

var errorTmpl = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<meta charset="utf-8"><title>AWS VPN</title>
<body style="font-family: sans-serif; margin: 60px auto; padding: 0 16px; max-width: 640px">
<p style="color: #c5221f"><b>Not changed:</b> {{.}}</p><p><a href="/">Back to the dashboard</a></p>`))

var dashboardTmpl = template.Must(template.New("dashboard").Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AWS VPN</title>
  <style>
    body { font-family: sans-serif; margin: 40px auto; padding: 0 16px; max-width: 720px; color: #222; }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; }
    .head { display: flex; align-items: center; gap: 12px; }
    .head h2 { margin: 0; flex: 1; font-size: 1.3em; }
    .emoji { font-size: 2em; }
    .status { padding: 4px 12px; border-radius: 4px; font-weight: bold; }
    .idle, .disconnected { background: #f1f3f4; color: #666; }
    .connecting { background: #fef9e7; color: #b45309; }
    .connected  { background: #e6f4ea; color: #2d6a2d; }
    .error      { background: #f3e8ff; color: #6b21a8; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 12px 0; }
    .actions form { margin: 0; }
    button, .button { padding: 6px 14px; font-size: 0.95em; cursor: pointer; }
    .danger { color: #c5221f; }
    .warn { background: #fef9e7; padding: 8px 12px; border-radius: 4px; }
    label { display: block; margin: 8px 0 4px; font-weight: bold; }
    input[type=text], textarea { width: 100%; box-sizing: border-box; padding: 6px; font: inherit; }
    textarea { font-family: monospace; }
    code { background: #f1f3f4; padding: 1px 4px; border-radius: 3px; }
    .note { color: #666; font-size: 0.9em; }
    summary { cursor: pointer; margin-top: 8px; }
  </style>
</head>
<body>
  <h1>AWS VPN</h1>
  {{range .Profiles}}
  <section class="card">
    <div class="head">
      <span class="emoji" data-emoji="{{.ID}}">{{.Emoji}}</span>
      <h2>{{.Name}}</h2>
      <span class="status {{.Status}}" data-status="{{.ID}}">{{.StatusText}}</span>
    </div>
    <p>Proxy <code>http://{{.Host}}</code> · dashboard <a href="http://{{.Host}}:8080/">{{.Host}}:8080</a></p>
    {{if .LoginURL}}<p class="warn">The tailnet node <b>{{.Hostname}}</b> is not logged in yet: <a href="{{.LoginURL}}" target="_blank" rel="noopener">log it in to Tailscale</a>, then reload this page.</p>{{end}}
    {{if .PendingAuth}}<p class="warn">SAML login started: <a href="/p/{{.ID}}/login">continue it</a>.</p>{{end}}
    <div class="actions">
      <form method="POST" action="/p/{{.ID}}/upload" enctype="multipart/form-data">
        <label class="button" style="display: inline; font-weight: normal">Connect with a .ovpn file
          <input type="file" name="ovpn" accept=".ovpn" onchange="this.form.submit()" hidden></label>
      </form>
      {{if .HasProfile}}<form method="POST" action="/p/{{.ID}}/reconnect"><button>Reconnect with saved profile</button></form>{{end}}
      {{if .Running}}<form method="POST" action="/p/{{.ID}}/disconnect"><button>Disconnect</button></form>{{end}}
    </div>
    <details>
      <summary>Edit</summary>
      <form method="POST" action="/p/{{.ID}}/edit">
        <label>Name</label><input type="text" name="name" value="{{.Name}}" maxlength="40" required>
        <label>Tailnet hostname</label><input type="text" name="hostname" value="{{.Hostname}}" required pattern="[a-z0-9]([a-z0-9\-]*[a-z0-9])?">
        <label>Domains through this VPN (one per line; <code>.example.com</code> = every subdomain)</label>
        <textarea name="domains" rows="6" required>{{.Domains}}</textarea>
        <p class="note">Changing the hostname or domains restarts the proxies and tailnet nodes of all profiles for a few seconds; VPN sessions stay up.</p>
        <button>Save</button>
      </form>
      <form method="POST" action="/p/{{.ID}}/delete" onsubmit="return confirm('Delete profile ' + {{.Name}} + '? Its VPN disconnects and its tailnet node goes offline (remove it in the Tailscale admin console). Its data moves to /data/.trash.')">
        <p><button class="danger">Delete profile</button></p>
      </form>
    </details>
  </section>
  {{else}}
  <p>No profiles yet.</p>
  {{end}}
  <details class="card"{{if not .Profiles}} open{{end}}>
    <summary><b>Add a profile</b></summary>
    <form method="POST" action="/add">
      <label>Name</label><input type="text" name="name" maxlength="40" required>
      <label>Tailnet hostname</label><input type="text" name="hostname" required pattern="[a-z0-9]([a-z0-9\-]*[a-z0-9])?">
      <label>Domains through this VPN (one per line; <code>.example.com</code> = every subdomain)</label>
      <textarea name="domains" rows="6" required>{{.Domains}}</textarea>
      <p class="note">The new tailnet node shows a Tailscale login link here after you add it.</p>
      <button>Add</button>
    </form>
  </details>
  <p class="note">Log in one profile at a time. AWS sends the SAML result to <code>http://127.0.0.1:35001</code>: keep <code>ssh -N -L 35001:localhost:35001</code> to the host open.</p>
  <script>
    const emojis = { idle: '🔓', connecting: '⏳', connected: '🔐', disconnected: '🔓', error: '⛓️‍💥' };
    document.querySelectorAll('[data-status]').forEach(el => {
      const id = el.dataset.status, emoji = document.querySelector('[data-emoji="' + id + '"]');
      const set = (status, message) => { el.className = 'status ' + status; el.textContent = message; emoji.textContent = emojis[status] || ''; };
      const es = new EventSource('/p/' + id + '/events');
      es.onmessage = ({ data }) => { const { status, message } = JSON.parse(data); set(status, message); };
      es.onerror = () => set('error', "Container's down");
    });
  </script>
</body>
</html>`))
