package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeAuth is a connect handler that waits for a result: a redirect to the
// identity provider, or an error.
type fakeAuth struct {
	started chan string
	result  chan int
}

func newFakeAuth() *fakeAuth {
	return &fakeAuth{started: make(chan string, 4), result: make(chan int, 4)}
}

func (f *fakeAuth) handle(p *profile, w http.ResponseWriter, r *http.Request) {
	f.started <- p.name
	if code := <-f.result; code == http.StatusFound {
		http.Redirect(w, r, "https://idp.example/"+p.name, code)
	} else {
		http.Error(w, "dial tcp: lookup vpn.example: no such host", code)
	}
}

func post(h func(*profile, http.ResponseWriter, *http.Request), p *profile) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(p, w, httptest.NewRequest("POST", "/p/x/reconnect", nil))
	return w
}

func TestSignInReservedBeforeAuthStarts(t *testing.T) {
	corp, prod := &profile{name: "corp"}, &profile{name: "prod"}
	m := &manager{}
	f := newFakeAuth()
	h := m.connect(f.handle)

	first := make(chan *httptest.ResponseRecorder)
	go func() { first <- post(h, corp) }()
	<-f.started // corp's auth work is under way and has not redirected yet

	for _, p := range []*profile{prod, corp} {
		if w := post(h, p); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "still open") {
			t.Errorf("%s while corp starts: %d, want 400 still open", p.name, w.Code)
		}
	}
	if len(f.started) != 0 {
		t.Fatalf("a competing handler ran")
	}

	f.result <- http.StatusBadRequest // corp fails: its reservation is released
	if w := <-first; w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "could not be resolved") {
		t.Errorf("failed start: %d %q", w.Code, w.Body.String())
	}
	if m.signIn != nil {
		t.Fatalf("failed attempt still reserved")
	}

	f.result <- http.StatusFound
	if w := post(h, prod); w.Code != http.StatusFound || m.signIn == nil || m.signIn.p != prod || m.signIn.url != "https://idp.example/prod" {
		t.Errorf("after the failure: %d %+v", w.Code, m.signIn)
	}
}

func TestCallbackOnlyForTheOpenSignIn(t *testing.T) {
	corp := &profile{name: "corp", publicURL: "/"}
	m := &manager{}
	f := newFakeAuth()
	h := m.connect(f.handle)
	callback := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader("SAMLResponse=x"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		m.handleCallback(w, r)
		return w.Code
	}
	start := func() {
		f.result <- http.StatusFound
		post(h, corp)
		<-f.started
	}

	if c := callback(); c != http.StatusBadRequest {
		t.Errorf("callback with no sign-in: %d, want 400", c)
	}
	start()
	if c := callback(); c != http.StatusFound {
		t.Errorf("callback for the open sign-in: %d, want 302", c)
	}
	if c := callback(); c != http.StatusBadRequest {
		t.Errorf("repeated callback: %d, want 400", c)
	}

	start()
	m.endSignIn(corp) // Cancel sign-in
	if c := callback(); c != http.StatusBadRequest {
		t.Errorf("late callback after cancel: %d, want 400", c)
	}

	start()
	m.signIn.at = time.Now().Add(-signInTimeout - time.Second)
	if c := callback(); c != http.StatusBadRequest {
		t.Errorf("late callback after the timeout: %d, want 400", c)
	}
}

func TestSignInChangesReachOpenDashboards(t *testing.T) {
	old := signInTimeout
	signInTimeout = 50 * time.Millisecond
	defer func() { signInTimeout = old }()
	corp := &profile{name: "corp"}
	m := &manager{subs: map[chan struct{}]struct{}{}}
	ch := make(chan struct{}, 1)
	m.subs[ch] = struct{}{}
	f := newFakeAuth()
	h := m.connect(f.handle)
	f.result <- http.StatusFound
	post(h, corp)
	<-f.started
	<-ch // start
	m.mu.Lock()
	v := m.version
	m.mu.Unlock()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("no change event when the sign-in timed out")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signIn != nil || m.version <= v {
		t.Errorf("after the timeout: sign-in %+v, version %d (was %d)", m.signIn, m.version, v)
	}
}
