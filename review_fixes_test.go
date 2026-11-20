package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Findings from an outside review of the released version: the 429 on login was
// hand-written without the "code" field every other error has, the login endpoint
// did not enforce the content-type rule, an oversize body was a 400 although the
// docs promise 413, and a mistyped address was accepted and then drawn as 100% loss.

func rawLogin(h http.Handler, body io.Reader, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "http://vp.local/api/login", body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestLoginRequiresJSONAndDoesNotSpendTheThrottle(t *testing.T) {
	h, _, _ := apiHarness(t)
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
		for i := 0; i < 10; i++ { // refusals carry no credentials: they must never lock the address
			w := rawLogin(h, strings.NewReader(`{"user":"admin","pass":"pw"}`), ct)
			if w.Code != 415 || !strings.Contains(w.Body.String(), `"unsupported_media_type"`) {
				t.Fatalf("content type %q: %d %s", ct, w.Code, w.Body)
			}
		}
	}
	if w := apiCall(h, "POST", "/api/login", `{"user":"admin","pass":"pw"}`, "", ""); w.Code != 200 {
		t.Fatalf("JSON login after the refusals: %d %s", w.Code, w.Body)
	}
}

func TestLoginTooManyAttemptsHasACode(t *testing.T) {
	h, _, _ := apiHarness(t)
	var last *httptest.ResponseRecorder
	for i := 0; i < 12 && (last == nil || last.Code != 429); i++ {
		last = apiCall(h, "POST", "/api/login", `{"user":"admin","pass":"wrong"}`, "", "")
	}
	if last.Code != 429 {
		t.Fatalf("never throttled: %d", last.Code)
	}
	if !strings.Contains(last.Body.String(), `"rate_limited"`) || last.Header().Get("Retry-After") == "" {
		t.Fatalf("429: %s (Retry-After %q)", last.Body, last.Header().Get("Retry-After"))
	}
	checkAPIResponse(t, "429", last)
}

func TestOversizeBodyIs413(t *testing.T) {
	h, session, _ := apiHarness(t)
	big := `{"name":"A","vrf":"` + strings.Repeat("a", 20<<10) + `","source_address":""}`
	for _, c := range []struct{ method, path, session string }{
		{"PUT", "/api/routing-options", session},
		{"POST", "/api/login", ""},
	} {
		req := httptest.NewRequest(c.method, "http://vp.local"+c.path, strings.NewReader(big))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://vp.local") // a write must be same-origin
		if c.session != "" {
			req.Header.Set("Cookie", sessionCookie+"="+c.session)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 413 || !strings.Contains(w.Body.String(), `"too_large"`) {
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
		checkAPIResponse(t, c.path, w)
	}
}

func TestMistypedAddressesAreRefused(t *testing.T) {
	for name, line := range map[string]string{
		"port above 65535": "10.0.0.1:99999 web",
		"port zero":        "10.0.0.1:0 web",
		"octets above 255": "999.999.999.999:443 web",
		"too few octets":   "10.0.0:443 web",
		"all digits":       "123:443 web",
		"too many octets":  "1.2.3.4.5:443 web",
	} {
		for _, typ := range []string{"tcp", typeHTTP} {
			tg, err := parseListLine(line, typ)
			if err == nil {
				err = validateTarget(&tg, 0, map[string]bool{}, map[string]bool{})
			}
			if err == nil {
				t.Errorf("%s (%s): accepted", name, typ)
			}
		}
	}
	// ping.list takes a bare address.
	tg, _ := parseListLine("999.999.999.999 router", "icmp")
	if err := validateTarget(&tg, 0, map[string]bool{}, map[string]bool{}); err == nil {
		t.Error("ping target 999.999.999.999 accepted")
	}
	for _, ok := range []string{"10.0.0.1:443 web", "example.org:443 web", "[2001:db8::1]:443 web", "1e100.net:443 web"} {
		tg, err := parseListLine(ok, "tcp")
		if err == nil {
			err = validateTarget(&tg, 0, map[string]bool{}, map[string]bool{})
		}
		if err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}
