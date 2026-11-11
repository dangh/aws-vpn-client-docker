package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The AWS SAML result of every profile comes back on the one callback port, so the
// dashboard runs one sign-in at a time. An attempt is reserved before its auth work
// starts, gets its identity provider URL when the handler redirects there, and ends
// on the SAML result, a cancel, a failure or the timeout. Only the attempt under way
// takes a callback, once: a late or repeated callback is refused.

// signIn is one sign-in attempt; m.signIn holds the one under way.
type signIn struct {
	p   *profile
	url string // the identity provider page; empty while the attempt starts
	at  time.Time
}

// An unfinished sign-in ends after this time. A variable for tests.
var signInTimeout = 5 * time.Minute

// signingIn returns the sign-in under way, or nil. m.mu held.
func (m *manager) signingIn() *signIn {
	if a := m.signIn; a != nil && time.Since(a.at) <= signInTimeout {
		return a
	}
	return nil
}

// changed tells every open dashboard to refresh. m.mu held.
func (m *manager) changed() {
	m.version++
	for ch := range m.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// end ends attempt a if it is still the one under way. m.mu held.
func (m *manager) end(a *signIn) {
	if a != nil && m.signIn == a {
		m.signIn = nil
		m.changed()
	}
}

func (m *manager) endSignIn(p *profile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signIn != nil && m.signIn.p == p {
		m.end(m.signIn)
	}
}

// connect wraps a handler that begins an AWS sign-in (upload or reconnect).
func (m *manager) connect(h func(*profile, http.ResponseWriter, *http.Request)) func(*profile, http.ResponseWriter, *http.Request) {
	return func(p *profile, w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		if a := m.signingIn(); a != nil {
			m.mu.Unlock()
			m.fail(w, "Could not connect", fmt.Sprintf("The AWS sign-in for %s is still open. Finish it, or cancel it on its card, then try again.", a.p.name), "")
			return
		}
		a := &signIn{p: p, at: time.Now()}
		m.signIn = a
		m.changed()
		m.mu.Unlock()

		cw := &catchWriter{ResponseWriter: w}
		h(p, cw, r)

		m.mu.Lock()
		if cw.code == http.StatusFound && m.signIn == a {
			a.url, a.at = w.Header().Get("Location"), time.Now()
			m.changed()
			time.AfterFunc(signInTimeout, func() {
				m.mu.Lock()
				m.end(a)
				m.mu.Unlock()
			})
		} else {
			m.end(a)
		}
		m.mu.Unlock()
		if cw.code >= 400 {
			msg, detail := connectError(cw.body.String())
			m.fail(w, "Could not connect", msg, detail)
		}
	}
}

// handleCallback takes the SAML result the identity provider posts to /, for the
// sign-in under way.
func (m *manager) handleCallback(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	a := m.signingIn()
	m.end(a)
	m.mu.Unlock()
	if a == nil {
		m.fail(w, "Sign-in not accepted", "No AWS sign-in is open: it was canceled, it timed out, or it already finished. Connect again from the dashboard.", "")
		return
	}
	a.p.handleSAML(w, r)
}

// handleVersion streams the dashboard version: an open page refreshes when it changes.
func (m *manager) handleVersion(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := make(chan struct{}, 1)
	m.mu.Lock()
	if m.subs == nil {
		m.subs = map[chan struct{}]struct{}{}
	}
	m.subs[ch] = struct{}{}
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.subs, ch)
		m.mu.Unlock()
	}()
	for {
		m.mu.Lock()
		v := m.version
		m.mu.Unlock()
		fmt.Fprintf(w, "data: %d\n\n", v)
		flusher.Flush()
		select {
		case <-ch:
		case <-r.Context().Done():
			return
		}
	}
}

// connectError turns the error of a sign-in start into a next step, with the
// original text as detail.
func connectError(raw string) (msg, detail string) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.Contains(raw, "no such host"), strings.Contains(raw, "DNS lookup"):
		return "The VPN server name in the .ovpn file could not be resolved. Check the file, and the DNS of the VPN host.", raw
	case strings.Contains(raw, "auth URL not found"):
		return "The VPN server did not start an AWS sign-in. Check that the .ovpn file is an AWS Client VPN file with SAML sign-in.", raw
	}
	return "The VPN did not start the AWS sign-in.", raw
}
