package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testStatsToken = "zabbix-test-token-0123456789"

func TestBuildStatsVRF(t *testing.T) {
	targets := []TargetCfg{
		{Name: "steady", Type: "tcp", Host: "10.9.8.7", Port: 443, VRF: "blue", dir: "steady"},
		{Name: "broken vrf", Type: "icmp", Host: "192.0.2.99", VRF: "nope", dir: "broken_vrf"},
	}
	s, _ := newTestStore(t, "steady", "broken vrf")
	now := time.Now().Unix()
	for i := 3; i >= 0; i-- {
		s.Append("steady", Round{T: now - int64(i)*60, S: 10, R: 9, MS: []float64{10, 20, 30, 40, 50, 60, 70, 80, 90}, B: i == 0})
		s.Append("broken vrf", Round{T: now - int64(i)*60, Error: "bind to VRF nope: no such device"})
	}
	rep := buildStats(s, targets, time.Now())
	if rep.WindowSec != 300 || len(rep.Targets) != 2 {
		t.Fatalf("report: %+v", rep)
	}
	st, br := rep.Targets[0], rep.Targets[1]
	if st.Rounds != 4 || st.P50 == nil || *st.P50 != 50 || *st.LossPct != 10 || st.Bursts != 1 || *st.Up != 1 || st.ProbeErrors != 0 {
		t.Errorf("steady: %+v", st)
	}
	// A round that could not probe is not "0% loss".
	if br.Rounds != 0 || br.LossPct != nil || br.P50 != nil || br.Up != nil || br.ProbeErrors != 4 {
		t.Errorf("broken vrf must report probe errors, not numbers: %+v", br)
	}
	if st.ID != targetID("steady") || st.ID == br.ID || st.ID <= 0 || st.ID >= 1<<48 {
		t.Errorf("ids: %d %d", st.ID, br.ID)
	}
}

func TestStatsOffByDefault(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	if res := get(t, srv, "/api/stats", nil); res.StatusCode != http.StatusNotFound {
		t.Fatalf("stats without --zabbix: %d, want 404", res.StatusCode)
	}
}

func TestStatsEndpoint(t *testing.T) {
	cfg := defaultConfig()
	cfg.ZabbixToken = testStatsToken
	cfg.Targets = []TargetCfg{{Name: "A", Type: "icmp", Host: "127.0.0.1", VRF: "blue", SourceAddress: "127.0.0.2", dir: "A"}}
	s, _ := newTestStore(t, "A")
	s.Append("A", Round{T: time.Now().Unix() - 60, S: 20, R: 20, MS: samples(20, 5)})
	h := newMux(cfg, s, map[string]string{"admin": "pw"})
	do := func(method, auth, remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/stats", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		if remote != "" {
			req.RemoteAddr = remote
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	for _, auth := range []string{"", "Bearer wrong-token-0123456789", testStatsToken} {
		if w := do("GET", auth, ""); w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), `"A"`) {
			t.Errorf("auth %q: %d %s", auth, w.Code, w.Body)
		}
	}
	w := do("GET", "Bearer "+testStatsToken, "198.51.100.1:1")
	if w.Code != 200 {
		t.Fatalf("good token: %d %s", w.Code, w.Body)
	}
	for _, leak := range []string{"127.0.0.1", "127.0.0.2", "blue", `"host"`, `"vrf"`, `"source`, `"version"`} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("stats response exposes %s: %s", leak, w.Body)
		}
	}
	var rep statsReport
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil || len(rep.Targets) != 1 || rep.Targets[0].Name != "A" || rep.Targets[0].P50 == nil {
		t.Fatalf("decode: %v %s", err, w.Body)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("security headers missing on /api/stats")
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if w := do(m, "Bearer "+testStatsToken, ""); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d, want 405", m, w.Code)
		}
	}
	for i := 0; i <= loginFreeFails; i++ {
		do("GET", "Bearer nope-nope-nope-nope", "203.0.113.9:1")
	}
	if w := do("GET", "Bearer "+testStatsToken, "203.0.113.9:1"); w.Code != http.StatusTooManyRequests {
		t.Errorf("right token from a locked address: %d, want 429", w.Code)
	}
}

func TestResolveZabbixToken(t *testing.T) {
	f := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(f, []byte(testStatsToken+"\n"), 0600)
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	withTok := env(map[string]string{"VRFPING_ZABBIX_TOKEN": testStatsToken})
	if tok, ign, err := resolveZabbixToken(false, "", env(nil)); err != nil || tok != "" || ign {
		t.Errorf("default must be off: %q %v %v", tok, ign, err)
	}
	if tok, ign, err := resolveZabbixToken(false, f, withTok); err != nil || tok != "" || !ign {
		t.Errorf("token without --zabbix: %q %v %v", tok, ign, err)
	}
	if _, _, err := resolveZabbixToken(true, "", env(nil)); err == nil || !strings.Contains(err.Error(), "--zabbix needs a token") {
		t.Errorf("--zabbix without token: %v", err)
	}
	if tok, _, err := resolveZabbixToken(true, "", withTok); err != nil || tok != testStatsToken {
		t.Errorf("env: %q %v", tok, err)
	}
	if tok, _, err := resolveZabbixToken(true, f, env(nil)); err != nil || tok != testStatsToken {
		t.Errorf("file flag: %q %v", tok, err)
	}
	if _, _, err := resolveZabbixToken(true, "", env(map[string]string{"VRFPING_ZABBIX_TOKEN": "short"})); err == nil {
		t.Error("a short token was accepted")
	}
}
