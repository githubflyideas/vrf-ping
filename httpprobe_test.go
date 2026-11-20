package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func httpTarget(t *testing.T, srv *httptest.Server, opts map[string]any) TargetCfg {
	t.Helper()
	host, ps, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(ps)
	tg := TargetCfg{Name: "web", Type: typeHTTP, Host: host, Port: port, Options: opts}
	if err := validateTarget(&tg, 0, map[string]bool{}, map[string]bool{}); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return tg
}

func httpRoundOf(t *testing.T, tg TargetCfg) Round {
	t.Helper()
	r, err := httpRoundTarget(context.Background(), tg, 3, time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHTTPMeasuresAndCountsLoss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad":
			w.WriteHeader(500)
		case "/moved":
			http.Redirect(w, r, "/ok", http.StatusMovedPermanently)
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()

	if r := httpRoundOf(t, httpTarget(t, srv, map[string]any{"scheme": "http", "path": "/ok"})); r.R != 3 || len(r.MS) != 3 {
		t.Fatalf("healthy: %+v", r)
	}
	// A 500 is "the server answered but is broken": every probe is lost, and it is
	// loss, not a probe error.
	if r := httpRoundOf(t, httpTarget(t, srv, map[string]any{"scheme": "http", "path": "/bad"})); r.R != 0 || r.S != 3 || r.Error != "" {
		t.Fatalf("500 must be loss: %+v", r)
	}
	if r := httpRoundOf(t, httpTarget(t, srv, map[string]any{"scheme": "http", "path": "/bad", "expect_status": 500})); r.R != 3 {
		t.Fatalf("expect_status 500: %+v", r)
	}
	if r := httpRoundOf(t, httpTarget(t, srv, map[string]any{"scheme": "http", "path": "/moved", "expect_status": 301})); r.R != 3 {
		t.Fatalf("301 as the answer: %+v", r)
	}
	if r := httpRoundOf(t, httpTarget(t, srv, map[string]any{"scheme": "http", "path": "/moved", "follow_redirects": true})); r.R != 3 {
		t.Fatalf("followed: %+v", r)
	}
}

func TestHTTPCertificatesAreVerified(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if r := httpRoundOf(t, httpTarget(t, srv, nil)); r.R != 0 {
		t.Fatalf("an untrusted certificate was accepted: %+v", r)
	}
}

// What cannot be measured at all is a probe error (the round carries Error), and
// what the network simply did not answer is loss: the same split the tcp probe makes.
func TestHTTPUnresolvableNameIsAProbeErrorNotLoss(t *testing.T) {
	tg := TargetCfg{Name: "gone", Type: typeHTTP, Host: "no-such-host.invalid", Port: 80, Options: map[string]any{"scheme": "http"}}
	if err := validateTarget(&tg, 0, map[string]bool{}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	r, err := httpRoundTarget(context.Background(), tg, 2, time.Millisecond, time.Second)
	if err == nil || r.Error == "" || r.S != 0 {
		t.Fatalf("want a probe error, got r=%+v err=%v", r, err)
	}
}

func TestHTTPInputIsJudgedStrictly(t *testing.T) {
	for name, tg := range map[string]TargetCfg{
		"hostile host":    {Name: "n", Type: typeHTTP, Host: "good.example/@evil.example", Port: 443},
		"no port":         {Name: "n", Type: typeHTTP, Host: "example.org"},
		"path no slash":   {Name: "n", Type: typeHTTP, Host: "example.org", Port: 443, Options: map[string]any{"path": "nope"}},
		"bad scheme":      {Name: "n", Type: typeHTTP, Host: "example.org", Port: 443, Options: map[string]any{"scheme": "ftp"}},
		"bad host_header": {Name: "n", Type: typeHTTP, Host: "example.org", Port: 443, Options: map[string]any{"host_header": "a b"}},
		"path with space": {Name: "n", Type: typeHTTP, Host: "example.org", Port: 443, Options: map[string]any{"path": "/a b"}},
		"path with #":     {Name: "n", Type: typeHTTP, Host: "example.org", Port: 443, Options: map[string]any{"path": "/a#b"}},
		"unknown option":  {Name: "n", Type: typeHTTP, Host: "example.org", Port: 443, Options: map[string]any{"verify": false}},
		"icmp with opts":  {Name: "n", Type: "icmp", Host: "example.org", Options: map[string]any{"path": "/"}},
	} {
		tg := tg
		if err := validateTarget(&tg, 0, map[string]bool{}, map[string]bool{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHTTPURLIsBuiltSafely(t *testing.T) {
	tg := TargetCfg{Name: "n", Type: typeHTTP, Host: "example.org", Port: 8443, Options: map[string]any{"path": "/p?a=b"}}
	if err := validateTarget(&tg, 0, map[string]bool{}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if got := httpURL(tg); got != "https://example.org:8443/p?a=b" {
		t.Fatalf("url = %q", got)
	}
}

func TestHTTPStopsWithTheTarget(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	tg := httpTarget(t, slow, map[string]any{"scheme": "http"})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	t0 := time.Now()
	if _, err := httpRoundTarget(ctx, tg, 3, time.Millisecond, time.Minute); err == nil || time.Since(t0) > 3*time.Second {
		t.Fatalf("not stopped: %v after %v", err, time.Since(t0))
	}
}

// http.list lines: host:port, then key=value words. The words an http line does not
// know are refused by name (ping and tcp lines keep ignoring unknown words).
func TestHTTPListLines(t *testing.T) {
	tg, err := parseListLine("example.org:8443 path=/health expect_status=200 follow_redirects=true vrf=blue Health check", typeHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateTarget(&tg, 0, map[string]bool{}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if tg.Name != "Health check" || tg.Port != 8443 || tg.VRF != "blue" ||
		tg.OptString("path") != "/health" || tg.OptInt("expect_status") != 200 || !tg.OptBool("follow_redirects") ||
		tg.OptString("scheme") != "https" {
		t.Fatalf("%+v", tg)
	}
	for name, line := range map[string]string{
		"typo in a key":      "example.org:443 pth=/x",
		"int given as text":  "example.org:443 expect_status=ok",
		"bool given as text": "example.org:443 follow_redirects=maybe",
		"missing port":       "example.org",
	} {
		bad, err := parseListLine(line, typeHTTP)
		if err == nil {
			err = validateTarget(&bad, 0, map[string]bool{}, map[string]bool{})
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A tcp line with an unknown word is still fine: that is how it always was.
	if _, err := parseListLine("example.org:22 colour=blue", "tcp"); err != nil {
		t.Errorf("tcp line with an unknown word: %v", err)
	}
}

// The option declarations are constants in this file. They are checked here, by the
// tests, so that a mistake in them cannot ship, and not at start-up, where nothing a
// user does can reach them and nothing of ours should be able to stop the program.
func TestHTTPSpecsAreValid(t *testing.T) {
	if err := validateSpecs(httpSpecs); err != nil {
		t.Fatal(err)
	}
}
