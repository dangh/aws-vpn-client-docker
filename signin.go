package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The AWS SAML result of every profile comes back on the one callback port, so the
// dashboard runs one sign-in at a time. An attempt is reserved before its auth work
// starts, gets the ID of its SAML request when the handler redirects to the identity
// provider, and ends on its own SAML result, a cancel, a failure or the timeout.
// A callback is taken only when its response answers that request (InResponseTo);
// any other callback is refused and leaves the attempt as it is. The attempt stays
// reserved until its callback has handed the VPN session over, so no new attempt can
// replace that session meanwhile. This only routes callbacks: the VPN server still
// checks the SAML response itself.

// signIn is one sign-in attempt; m.signIn holds the one under way.
type signIn struct {
	p         *profile
	url       string // the identity provider page; empty while the attempt starts
	requestID string // ID of the SAML AuthnRequest in url
	claimed   bool   // its callback arrived and is handing the session over
	at        time.Time
}

// An unfinished sign-in ends after this time. A variable for tests.
var signInTimeout = 5 * time.Minute

// handleSAML hands a SAML result to its profile. A variable for tests.
var handleSAML = (*profile).handleSAML

// signingIn returns the sign-in under way, or nil. m.mu held.
func (m *manager) signingIn() *signIn {
	if a := m.signIn; a != nil && (a.claimed || time.Since(a.at) <= signInTimeout) {
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

// endSignIn cancels the sign-in of p, unless its callback is handing over.
func (m *manager) endSignIn(p *profile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a := m.signIn; a != nil && a.p == p && !a.claimed {
		m.end(a)
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

		hw := &holdWriter{header: w.Header()}
		h(p, hw, r)
		loc := w.Header().Get("Location")
		id, idErr := requestID(loc)

		m.mu.Lock()
		ok := hw.code == http.StatusFound && idErr == nil && m.signIn == a
		if ok {
			a.url, a.requestID, a.at = loc, id, time.Now()
			m.changed()
			time.AfterFunc(signInTimeout, func() {
				m.mu.Lock()
				if !a.claimed {
					m.end(a)
				}
				m.mu.Unlock()
			})
		} else {
			m.end(a)
		}
		m.mu.Unlock()

		switch {
		case ok:
			w.WriteHeader(http.StatusFound) // to the identity provider
		case hw.code >= 400:
			msg, detail := connectError(hw.body.String())
			m.fail(w, "Could not connect", msg, detail)
		case idErr != nil:
			log.Printf("%s: sign-in URL: %v", p.name, idErr)
			m.fail(w, "Could not connect", "The VPN server's sign-in request could not be read, so its result could not be matched to this profile.", idErr.Error())
		default:
			m.fail(w, "Could not connect", "The sign-in was canceled while it started.", "")
		}
	}
}

// handleCallback takes the SAML result the identity provider posts to /. Only the
// result of the sign-in under way is taken, once.
func (m *manager) handleCallback(w http.ResponseWriter, r *http.Request) {
	inResponseTo, err := responseTo(r.PostFormValue("SAMLResponse"))
	m.mu.Lock()
	a := m.signingIn()
	match := err == nil && a != nil && !a.claimed && a.requestID != "" && inResponseTo == a.requestID
	if match {
		a.claimed = true
	}
	m.mu.Unlock()
	if !match {
		if err != nil {
			log.Printf("SAML callback refused: %v", err)
		}
		m.fail(w, "Sign-in not accepted", "This sign-in result does not belong to an open sign-in: it was canceled, it timed out, it already finished, or it was not a valid result. Connect again from the dashboard.", "")
		return
	}
	handleSAML(a.p, w, r)
	m.mu.Lock()
	m.end(a)
	m.mu.Unlock()
}

// requestID reads the ID of the SAML AuthnRequest in an identity provider URL
// (HTTP-Redirect binding: base64 of raw DEFLATE).
func requestID(loc string) (string, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("no SAMLRequest in the sign-in URL")
	}
	x, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 1<<20))
	if err != nil {
		return "", fmt.Errorf("SAMLRequest: %v", err)
	}
	return rootAttr(x, "AuthnRequest", "ID")
}

// responseTo reads InResponseTo of a SAML Response posted by the identity provider
// (HTTP-POST binding: base64).
func responseTo(samlResponse string) (string, error) {
	x, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil || len(x) == 0 {
		return "", fmt.Errorf("SAMLResponse missing or not base64")
	}
	return rootAttr(x, "Response", "InResponseTo")
}

const samlProtocol = "urn:oasis:names:tc:SAML:2.0:protocol"

// rootAttr returns the unqualified attribute attr of the root element, which must be
// elem in the SAML protocol namespace. It reads the whole document: a truncated or
// badly nested document, a second root or text outside the root is an error. This
// checks structure for routing only; the VPN server checks the SAML trust.
func rootAttr(x []byte, elem, attr string) (string, error) {
	d := xml.NewDecoder(bytes.NewReader(x))
	val, depth, roots := "", 0, 0
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("%s: %v", elem, err)
		}
		switch t := t.(type) {
		case xml.StartElement:
			if depth == 0 {
				if roots++; roots > 1 {
					return "", fmt.Errorf("%s: more than one root element", elem)
				}
				if t.Name.Space != samlProtocol || t.Name.Local != elem {
					return "", fmt.Errorf("root is {%s}%s, want {%s}%s", t.Name.Space, t.Name.Local, samlProtocol, elem)
				}
				for _, a := range t.Attr {
					if a.Name.Space == "" && a.Name.Local == attr {
						val = a.Value
					}
				}
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return "", fmt.Errorf("%s: text outside the root element", elem)
			}
		}
	}
	switch {
	case roots == 0 || depth != 0:
		return "", fmt.Errorf("%s: incomplete document", elem)
	case val == "":
		return "", fmt.Errorf("%s has no %s", elem, attr)
	}
	return val, nil
}

// holdWriter keeps a handler's response: connect decides what to send.
type holdWriter struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (h *holdWriter) Header() http.Header { return h.header }

func (h *holdWriter) WriteHeader(code int) {
	if h.code == 0 {
		h.code = code
	}
}

func (h *holdWriter) Write(b []byte) (int, error) {
	h.WriteHeader(http.StatusOK)
	return h.body.Write(b)
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
