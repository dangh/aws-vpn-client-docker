package main

import (
	"html/template"
	"net"
	"net/http"
	"net/url"
	"slices"
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
	ID, Name, Hostname, Host, Status, StatusText, LoginURL string
	Domains                                                []string
	PendingAuth, HasProfile, Running                       bool
}

func (v profileView) DomainsText() string { return strings.Join(v.Domains, "\n") }

func (m *manager) handleDashboard(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	var views []profileView
	connected := 0
	for _, ps := range m.st.Profiles {
		p := m.profiles[ps.ID]
		host := ps.Hostname
		if m.st.Tailnet != "" {
			host += "." + m.st.Tailnet
		}
		v := profileView{ID: ps.ID, Name: ps.Name, Hostname: ps.Hostname, Host: host,
			Domains: ps.Domains, LoginURL: m.loginURL(ps.ID), HasProfile: p.hasProfile()}
		p.mu.Lock()
		v.Status, v.PendingAuth = p.connStatus, p.pendingAuthURL != ""
		v.Running = p.activeCmd != nil || v.Status == "connected" || v.Status == "connecting"
		p.mu.Unlock()
		v.StatusText = statusMessages[v.Status]
		if v.Status == "connected" {
			connected++
		}
		views = append(views, v)
	}
	data := struct {
		Profiles         []profileView
		Connected        int
		Tailnet, Domains string
	}{views, connected, m.st.Tailnet, strings.Join(m.st.Domains, "\n")}
	m.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardTmpl.Execute(w, data)
}

// Shared look of the dashboard and the error page.
const pageStyle = `
  :root {
    --bg: #f6f7f9; --card: #fff; --text: #1c1e21; --muted: #65676b; --line: #e3e5e8;
    --accent: #2563eb; --accent-text: #fff; --soft: #eef2ff;
    --ok: #16a34a; --ok-bg: #e8f6ed; --warn: #b45309; --warn-bg: #fef6e7;
    --bad: #dc2626; --bad-bg: #fdecec; --idle: #8a8d91; --idle-bg: #f0f1f3;
    --info: #1d4ed8; --info-bg: #eaf1fe;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #111315; --card: #1b1e21; --text: #e6e7e9; --muted: #9a9ea4; --line: #2c3035;
      --accent: #4f8bff; --accent-text: #fff; --soft: #1e2a44;
      --ok: #34d399; --ok-bg: #12291f; --warn: #fbbf24; --warn-bg: #2d2412;
      --bad: #f87171; --bad-bg: #2f1717; --idle: #8a8f96; --idle-bg: #23272b;
      --info: #93b4ff; --info-bg: #1a2540;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 760px; margin: 0 auto; padding: 32px 16px 48px; }
  a { color: var(--accent); }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
  .btn { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--line);
    background: var(--card); color: var(--text); border-radius: 8px; padding: 7px 14px;
    font: inherit; font-weight: 600; cursor: pointer; text-decoration: none; }
  .btn:hover { border-color: var(--muted); }
  .btn.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-text); }
  .btn.primary:hover { filter: brightness(1.08); }
  .btn.danger { color: var(--bad); }
  .btn.danger.solid { background: var(--bad); border-color: var(--bad); color: #fff; }
  .btn.ghost { border-color: transparent; background: transparent; color: var(--muted); }
  .btn.ghost:hover { color: var(--text); }
  .banner { border-radius: 8px; padding: 10px 14px; margin: 12px 0 0; }
  .banner.warn { background: var(--warn-bg); color: var(--warn); }
  .banner.info { background: var(--info-bg); color: var(--info); }
  .banner.bad { background: var(--bad-bg); color: var(--bad); }
  .banner a { color: inherit; font-weight: 700; }
`

var errorTmpl = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AWS VPN</title><style>` + pageStyle + `</style></head>
<body><main><h1>AWS VPN</h1>
<p class="banner bad"><b>Not saved.</b> {{.}}</p>
<p><a class="btn" href="/">Back to the dashboard</a></p></main></body></html>`))

var dashboardTmpl = template.Must(template.New("dashboard").Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AWS VPN</title>
  <style>` + pageStyle + `
    header { display: flex; align-items: center; gap: 16px; margin-bottom: 24px; }
    header h1 { margin: 0; font-size: 1.6em; }
    header .sub { color: var(--muted); }
    header .grow { flex: 1; }
    .card { background: var(--card); border: 1px solid var(--line); border-radius: 12px;
      border-left-width: 4px; padding: 18px 20px; margin-bottom: 16px; }
    .card.connected { border-left-color: var(--ok); }
    .top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .top h2 { margin: 0; font-size: 1.15em; }
    .top .grow { flex: 1; }
    .pill { display: inline-flex; align-items: center; gap: 6px; border-radius: 999px;
      padding: 2px 10px; font-size: 0.85em; font-weight: 700; }
    .pill::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
    .pill.connected { background: var(--ok-bg); color: var(--ok); }
    .pill.connecting { background: var(--warn-bg); color: var(--warn); }
    .pill.connecting::before { animation: pulse 1s infinite; }
    .pill.idle, .pill.disconnected { background: var(--idle-bg); color: var(--idle); }
    .pill.error { background: var(--bad-bg); color: var(--bad); }
    @keyframes pulse { 50% { opacity: 0.3; } }
    dl { display: grid; grid-template-columns: 90px 1fr; gap: 6px 12px; margin: 14px 0 0; }
    dt { color: var(--muted); }
    dd { margin: 0; min-width: 0; }
    .copy { display: inline-flex; align-items: center; gap: 8px; max-width: 100%; }
    .copy code { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .copy button { border: none; background: none; color: var(--accent); cursor: pointer; font: inherit; font-size: 0.85em; padding: 0; }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; }
    .chip { background: var(--soft); border-radius: 6px; padding: 1px 8px; font-family: ui-monospace, Menlo, monospace; font-size: 0.82em; }
    .actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 16px; }
    .actions form { margin: 0; }
    .actions .grow { flex: 1; }
    .panel { border-top: 1px solid var(--line); margin-top: 16px; padding-top: 16px; }
    .panel[hidden] { display: none; }
    label { display: block; font-weight: 600; margin: 12px 0 4px; }
    label:first-child { margin-top: 0; }
    .hint { color: var(--muted); font-size: 0.85em; font-weight: normal; }
    input[type=text], textarea { width: 100%; border: 1px solid var(--line); border-radius: 8px;
      padding: 8px 10px; font: inherit; background: var(--bg); color: var(--text); }
    textarea { font-family: ui-monospace, Menlo, monospace; font-size: 0.9em; resize: vertical; }
    input:focus, textarea:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
    .suffix { display: flex; align-items: center; gap: 6px; }
    .suffix input { flex: 1; }
    .suffix span { color: var(--muted); font-family: ui-monospace, Menlo, monospace; font-size: 0.9em; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; align-items: center; }
    .danger-zone { display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
      margin-top: 18px; padding-top: 14px; border-top: 1px dashed var(--line); }
    .danger-zone p { margin: 0; flex: 1; color: var(--muted); font-size: 0.85em; min-width: 200px; }
    .empty { text-align: center; color: var(--muted); padding: 32px 20px; }
    footer { color: var(--muted); font-size: 0.85em; margin-top: 28px; }
    @media (max-width: 520px) { dl { grid-template-columns: 1fr; gap: 0 0; } dt { margin-top: 6px; } }
  </style>
</head>
<body>
<main>
  <header>
    <div class="grow">
      <h1>AWS VPN</h1>
      <div class="sub">{{len .Profiles}} profile{{if ne (len .Profiles) 1}}s{{end}} · {{.Connected}} connected</div>
    </div>
    <button class="btn primary" type="button" onclick="toggle('add')">+ Add profile</button>
  </header>

  <section class="card panel-card" id="add" {{if .Profiles}}hidden{{end}}>
    <h2 style="margin: 0 0 12px; font-size: 1.15em">New profile</h2>
    <form method="POST" action="/add">
      <label>Name</label>
      <input type="text" name="name" maxlength="40" required placeholder="e.g. Corp">
      <label>Tailnet hostname <span class="hint">· the proxy's address on the tailnet</span></label>
      <div class="suffix"><input type="text" name="hostname" required pattern="[a-z0-9]([a-z0-9\-]*[a-z0-9])?" placeholder="corp-proxy">{{if .Tailnet}}<span>.{{.Tailnet}}</span>{{end}}</div>
      <label>Domains through this VPN <span class="hint">· one per line; <code>.example.com</code> = every subdomain</span></label>
      <textarea name="domains" rows="5" required>{{.Domains}}</textarea>
      <div class="row">
        <button class="btn primary">Add profile</button>
        {{if .Profiles}}<button class="btn ghost" type="button" onclick="toggle('add')">Cancel</button>{{end}}
        <span class="hint">The new node shows a Tailscale login link here.</span>
      </div>
    </form>
  </section>

  {{range .Profiles}}
  <section class="card {{.Status}}" data-profile="{{.ID}}" data-status="{{.Status}}">
    <div class="top">
      <h2>{{.Name}}</h2>
      <span class="pill {{.Status}}" data-pill>{{.StatusText}}</span>
      <span class="grow"></span>
      <button class="btn ghost" type="button" onclick="toggle('edit-{{.ID}}')">Edit</button>
    </div>

    {{if .LoginURL}}<p class="banner warn">Tailnet node <b>{{.Hostname}}</b> is not logged in. <a href="{{.LoginURL}}" target="_blank" rel="noopener">Log it in to Tailscale →</a> then reload this page.</p>{{end}}
    {{if .PendingAuth}}<p class="banner info">SAML login started. <a href="/p/{{.ID}}/login">Continue the login →</a></p>{{end}}

    <dl>
      <dt>Proxy</dt>
      <dd class="copy"><code>http://{{.Host}}</code><button type="button" data-copy="http://{{.Host}}">Copy</button></dd>
      <dt>Domains</dt>
      <dd class="chips">{{range .Domains}}<span class="chip">{{.}}</span>{{end}}</dd>
    </dl>

    <div class="actions">
      {{if .Running}}
        <form method="POST" action="/p/{{.ID}}/disconnect"><button class="btn danger">Disconnect</button></form>
      {{else if .HasProfile}}
        <form method="POST" action="/p/{{.ID}}/reconnect"><button class="btn primary">Connect</button></form>
        <form method="POST" action="/p/{{.ID}}/upload" enctype="multipart/form-data">
          <label class="btn ghost" style="margin: 0">Use another .ovpn<input type="file" name="ovpn" accept=".ovpn" hidden onchange="this.form.submit()"></label>
        </form>
      {{else}}
        <form method="POST" action="/p/{{.ID}}/upload" enctype="multipart/form-data">
          <label class="btn primary" style="margin: 0">Upload .ovpn to connect<input type="file" name="ovpn" accept=".ovpn" hidden onchange="this.form.submit()"></label>
        </form>
      {{end}}
    </div>

    <div class="panel" id="edit-{{.ID}}" hidden>
      <form method="POST" action="/p/{{.ID}}/edit">
        <label>Name</label>
        <input type="text" name="name" value="{{.Name}}" maxlength="40" required>
        <label>Tailnet hostname</label>
        <div class="suffix"><input type="text" name="hostname" value="{{.Hostname}}" required pattern="[a-z0-9]([a-z0-9\-]*[a-z0-9])?">{{if $.Tailnet}}<span>.{{$.Tailnet}}</span>{{end}}</div>
        <label>Domains through this VPN <span class="hint">· one per line; <code>.example.com</code> = every subdomain</span></label>
        <textarea name="domains" rows="5" required>{{.DomainsText}}</textarea>
        <div class="row">
          <button class="btn primary">Save</button>
          <button class="btn ghost" type="button" onclick="toggle('edit-{{.ID}}')">Cancel</button>
          <span class="hint">A new hostname or domains restart every proxy for a few seconds; VPN sessions stay up.</span>
        </div>
      </form>
      <form class="danger-zone" method="POST" action="/p/{{.ID}}/delete" onsubmit="return confirm('Delete ' + {{.Name}} + '? Its VPN disconnects. Its data moves to /data/.trash.')">
        <p>Delete this profile. Its tailnet node stays in the Tailscale admin console, offline, until you remove it there.</p>
        <button class="btn danger">Delete profile</button>
      </form>
    </div>
  </section>
  {{else}}
  <section class="card empty">No profiles yet. Add one above.</section>
  {{end}}

  <footer>Log in one profile at a time. AWS sends the SAML result to <code>http://127.0.0.1:35001</code> on your computer: keep <code>ssh -N -L 35001:localhost:35001</code> to the VPN host open while you log in.</footer>
</main>
<script>
  function toggle(id) {
    const el = document.getElementById(id);
    el.hidden = !el.hidden;
    if (!el.hidden) el.querySelector('input, textarea')?.focus();
  }
  document.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => {
    const t = document.createElement('textarea');
    t.value = b.dataset.copy; document.body.appendChild(t); t.select();
    document.execCommand('copy'); t.remove();
    b.textContent = 'Copied'; setTimeout(() => b.textContent = 'Copy', 1500);
  }));
  // Live status. The buttons depend on the status: reload when it changes.
  document.querySelectorAll('[data-profile]').forEach(card => {
    const pill = card.querySelector('[data-pill]');
    const es = new EventSource('/p/' + card.dataset.profile + '/events');
    es.onmessage = ({ data }) => {
      const { status, message } = JSON.parse(data);
      pill.className = 'pill ' + status; pill.textContent = message;
      if (status !== card.dataset.status) setTimeout(() => location.reload(), 400);
    };
    es.onerror = () => { pill.className = 'pill error'; pill.textContent = 'Not reachable'; };
  });
</script>
</body>
</html>`))
