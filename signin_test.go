package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// idpURL is an identity provider URL whose SAMLRequest has the given ID, like the
// one AWS Client VPN sends (HTTP-Redirect binding).
func idpURL(id string) string {
	return idpURLFor(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="` + id + `" Version="2.0"/>`)
}

func idpURLFor(authnRequest string) string {
	var b bytes.Buffer
	fw, _ := flate.NewWriter(&b, flate.DefaultCompression)
	fw.Write([]byte(authnRequest))
	fw.Close()
	return "https://idp.example/saml?SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(b.Bytes()))
}

// samlResponse is a SAMLResponse form value that answers request id.
func samlResponse(id string) string {
	return base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r-` + id + `" InResponseTo="` + id + `"/>`))
}

// fakeAuth is a connect handler that waits for its result: the request ID to
// redirect with, or "" for an error.
type fakeAuth struct {
	started chan string
	result  chan string
}

func newFakeAuth() *fakeAuth {
	return &fakeAuth{started: make(chan string, 8), result: make(chan string, 8)}
}

func (f *fakeAuth) handle(p *profile, w http.ResponseWriter, r *http.Request) {
	f.started <- p.name
	if id := <-f.result; id != "" {
		http.Redirect(w, r, idpURL(id), http.StatusFound)
	} else {
		http.Error(w, "dial tcp: lookup vpn.example: no such host", http.StatusBadRequest)
	}
}

type harness struct {
	t      *testing.T
	m      *manager
	f      *fakeAuth
	h      func(*profile, http.ResponseWriter, *http.Request)
	saml   []string // profiles whose handleSAML ran
	holdIn chan struct{}
	hold   chan struct{}
}

func newHarness(t *testing.T) *harness {
	x := &harness{t: t, m: &manager{}, f: newFakeAuth()}
	x.h = x.m.connect(x.f.handle)
	old := handleSAML
	handleSAML = func(p *profile, w http.ResponseWriter, r *http.Request) {
		x.saml = append(x.saml, p.name)
		if x.hold != nil {
			x.holdIn <- struct{}{}
			<-x.hold
		}
		w.WriteHeader(http.StatusFound)
	}
	t.Cleanup(func() { handleSAML = old })
	return x
}

func (x *harness) start(p *profile, id string) int {
	x.f.result <- id
	w := httptest.NewRecorder()
	x.h(p, w, httptest.NewRequest("POST", "/p/x/reconnect", nil))
	<-x.f.started
	return w.Code
}

func (x *harness) callback(body string) int {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	x.m.handleCallback(w, r)
	return w.Code
}

func form(id string) string { return "SAMLResponse=" + url.QueryEscape(samlResponse(id)) }

// formXML posts an arbitrary SAMLResponse document.
func formXML(doc string) string {
	return "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(doc)))
}

const ns = `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`

// open checks that p's attempt with request id is still the one under way.
func (x *harness) open(p *profile, id string) {
	x.t.Helper()
	if a := x.m.signIn; a == nil || a.p != p || a.requestID != id || a.claimed {
		x.t.Errorf("attempt %s of %s is not open: %+v", id, p.name, a)
	}
}

func TestSignInReservedBeforeAuthStarts(t *testing.T) {
	corp, prod := &profile{name: "corp"}, &profile{name: "prod"}
	x := newHarness(t)
	first := make(chan *httptest.ResponseRecorder)
	go func() {
		w := httptest.NewRecorder()
		x.h(corp, w, httptest.NewRequest("POST", "/p/corp/reconnect", nil))
		first <- w
	}()
	<-x.f.started // corp's auth work is under way and has not redirected yet

	for _, p := range []*profile{prod, corp} {
		w := httptest.NewRecorder()
		x.h(p, w, httptest.NewRequest("POST", "/p/x/reconnect", nil))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "still open") {
			t.Errorf("%s while corp starts: %d, want 400 still open", p.name, w.Code)
		}
	}
	if len(x.f.started) != 0 {
		t.Fatalf("a competing handler ran")
	}
	x.f.result <- "" // corp fails: its reservation is released
	if w := <-first; w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "could not be resolved") {
		t.Errorf("failed start: %d %q", w.Code, w.Body.String())
	}
	if x.m.signIn != nil {
		t.Fatalf("failed attempt still reserved")
	}
	if c := x.start(prod, "B"); c != http.StatusFound {
		t.Errorf("after the failure: %d", c)
	}
	x.open(prod, "B")
}

func TestOldCallbackLeavesNewAttempt(t *testing.T) {
	corp, prod := &profile{name: "corp"}, &profile{name: "prod"}
	for name, endA := range map[string]func(x *harness){
		"canceled":  func(x *harness) { x.m.endSignIn(corp) },
		"timed out": func(x *harness) { x.m.signIn.at = time.Now().Add(-signInTimeout - time.Second) },
		"completed": func(x *harness) {
			if c := x.callback(form("A")); c != http.StatusFound {
				t.Fatalf("A's own callback: %d", c)
			}
		},
	} {
		x := newHarness(t)
		x.start(corp, "A")
		endA(x)
		x.saml = nil
		if c := x.start(prod, "B"); c != http.StatusFound {
			t.Fatalf("%s: start B: %d", name, c)
		}
		if c := x.callback(form("A")); c != http.StatusBadRequest || len(x.saml) != 0 {
			t.Errorf("A %s, B open, A's callback: %d, handleSAML for %v; want 400 and none", name, c, x.saml)
		}
		x.open(prod, "B")
	}
}

func TestBadCallbackLeavesAttempt(t *testing.T) {
	prod := &profile{name: "prod"}
	for name, body := range map[string]string{
		"empty":       "",
		"no response": "RelayState=x",
		"not base64":  "SAMLResponse=%%%",
		"not XML":     "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("hello"))),
		"not a Response": "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString(
			[]byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="B"/>`))),
		"no InResponseTo": "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(`<Response ID="r"/>`))),
		"other request":   form("Z"),
		// Matching ID, broken document:
		"truncated":        formXML(`<samlp:Response ` + ns + ` InResponseTo="B">`),
		"mismatched close": formXML(`<samlp:Response ` + ns + ` InResponseTo="B"><a></b></samlp:Response>`),
		"two roots":        formXML(`<samlp:Response ` + ns + ` InResponseTo="B"/><samlp:Response ` + ns + ` InResponseTo="B"/>`),
		"no namespace":     formXML(`<Response InResponseTo="B"/>`),
		"other namespace":  formXML(`<x:Response xmlns:x="urn:example" InResponseTo="B"/>`),
		"text after root":  formXML(`<samlp:Response ` + ns + ` InResponseTo="B"/>junk`),
		"prefixed attr":    formXML(`<samlp:Response ` + ns + ` xmlns:x="urn:example" x:InResponseTo="B"/>`),
	} {
		x := newHarness(t) // each case on its own open attempt B
		x.start(prod, "B")
		if c := x.callback(body); c != http.StatusBadRequest || len(x.saml) != 0 {
			t.Errorf("%s: %d, handleSAML %v; want 400 and none", name, c, x.saml)
		}
		x.open(prod, "B")
		if c := x.callback(form("B")); c != http.StatusFound || len(x.saml) != 1 {
			t.Errorf("%s: B's own callback after it: %d, handleSAML %v; want 302 once", name, c, x.saml)
		}
	}
}

func TestCallbackKeepsAttemptUntilHandedOver(t *testing.T) {
	prod := &profile{name: "prod"}
	x := newHarness(t)
	x.start(prod, "B")
	x.holdIn, x.hold = make(chan struct{}), make(chan struct{})
	done := make(chan int)
	go func() { done <- x.callback(form("B")) }()
	<-x.holdIn // B's callback is handing the session over

	x.f.result <- "C" // what a wrongly allowed start would get
	w := httptest.NewRecorder()
	x.h(prod, w, httptest.NewRequest("POST", "/p/prod/reconnect", nil))
	if w.Code != http.StatusBadRequest || len(x.f.started) != 0 {
		t.Fatalf("new start for prod during B's hand-over: %d, want 400 and no auth work", w.Code)
	}
	<-x.f.result
	x.m.endSignIn(prod) // a cancel during the hand-over does not drop it
	if c := x.callback(form("B")); c != http.StatusBadRequest {
		t.Errorf("duplicate B during the hand-over: %d, want 400", c)
	}
	close(x.hold)
	if c := <-done; c != http.StatusFound {
		t.Errorf("B's callback: %d", c)
	}
	if x.m.signIn != nil {
		t.Errorf("B still reserved after its hand-over")
	}
}

func TestCallbackTakenOnce(t *testing.T) {
	prod := &profile{name: "prod"}
	x := newHarness(t)
	x.start(prod, "B")
	if c := x.callback(form("B")); c != http.StatusFound {
		t.Fatalf("B: %d", c)
	}
	if c := x.callback(form("B")); c != http.StatusBadRequest {
		t.Errorf("duplicate B, nothing open: %d, want 400", c)
	}
	x.start(prod, "C")
	if c := x.callback(form("B")); c != http.StatusBadRequest || len(x.saml) != 1 {
		t.Errorf("duplicate B, C open: %d, handleSAML %v", c, x.saml)
	}
	x.open(prod, "C")
	if c := x.callback(""); c != http.StatusBadRequest {
		t.Errorf("no callback body: %d", c)
	}
}

func TestStartWithBadSAMLRequestFails(t *testing.T) {
	for name, loc := range map[string]string{
		"no SAMLRequest": "https://idp.example/no-request",
		"truncated":      idpURLFor(`<samlp:AuthnRequest ` + ns + ` ID="A">`),
		"no namespace":   idpURLFor(`<AuthnRequest ID="A"/>`),
		"two roots":      idpURLFor(`<samlp:AuthnRequest ` + ns + ` ID="A"/><samlp:AuthnRequest ` + ns + ` ID="A"/>`),
		"no ID":          idpURLFor(`<samlp:AuthnRequest ` + ns + `/>`),
	} {
		m := &manager{}
		h := m.connect(func(p *profile, w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, loc, http.StatusFound)
		})
		w := httptest.NewRecorder()
		h(&profile{name: "corp"}, w, httptest.NewRequest("POST", "/p/corp/reconnect", nil))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "could not be read") || m.signIn != nil {
			t.Errorf("%s: got %d, sign-in %+v; want 400 and released", name, w.Code, m.signIn)
		}
	}
}

func TestSignInChangesReachOpenDashboards(t *testing.T) {
	old := signInTimeout
	signInTimeout = 50 * time.Millisecond
	defer func() { signInTimeout = old }()
	x := newHarness(t)
	ch := make(chan struct{}, 1)
	x.m.subs = map[chan struct{}]struct{}{ch: {}}
	x.start(&profile{name: "corp"}, "A")
	<-ch // start
	x.m.mu.Lock()
	v := x.m.version
	x.m.mu.Unlock()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("no change event when the sign-in timed out")
	}
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	if x.m.signIn != nil || x.m.version <= v {
		t.Errorf("after the timeout: sign-in %+v, version %d (was %d)", x.m.signIn, x.m.version, v)
	}
}
