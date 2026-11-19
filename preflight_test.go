package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func noEnv(string) string { return "" }

// A refused start names every problem at once.
func TestPrepareReportsEveryProblem(t *testing.T) {
	_, problems := prepare([]string{"unknown=value"}, true, "", "invalid", false, noEnv)
	if len(problems) != 3 {
		t.Fatalf("want 3 problems, got %v", problems)
	}
	s, problems := prepare([]string{"user=a", "passwd=b"}, false, "", "127.0.0.1:8517", false, noEnv)
	if len(problems) != 0 || len(s.users) != 1 || s.cfg.Listen != "127.0.0.1:8517" {
		t.Fatalf("good setup: %+v %v", s, problems)
	}
}

func TestSecuritySummaryMarksWhatIsExposed(t *testing.T) {
	open, _ := prepare(nil, false, "", "0.0.0.0:8517", false, noEnv)
	text := strings.Join(securitySummary(open), "\n")
	if !strings.Contains(text, "! listen") || !strings.Contains(text, "! login     OFF") {
		t.Errorf("open instance:\n%s", text)
	}
	local, _ := prepare(nil, false, "", "0.0.0.0:8517", true, noEnv)
	if text := strings.Join(securitySummary(local), "\n"); strings.Contains(text, "!") {
		t.Errorf("localhost-only instance flagged:\n%s", text)
	}
	pw, _ := prepare([]string{"user=a", "passwd=b"}, false, "", "127.0.0.1:8517", false, noEnv)
	if text := strings.Join(securitySummary(pw), "\n"); !strings.Contains(text, "visible in ps") {
		t.Errorf("command-line password not flagged:\n%s", text)
	}
}

// --check writes nothing: no demo list, no data directory. A bad list line is a
// warning (it would be skipped at start); a port in use is a failure.
func TestCheckReportsWithoutChangingAnything(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(old)

	free := func() string {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		return ln.Addr().String()
	}
	s, _ := prepare(nil, false, "", free(), false, noEnv)
	var out bytes.Buffer
	if code := runCheck(&out, s, nil); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("--check wrote %v", entries)
	}

	os.MkdirAll("targets", 0o755)
	os.WriteFile("targets/ping.list", []byte("10.0.0.1 good\n999.999.999.999 bad\n"), 0o644)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	s, _ = prepare(nil, false, "", ln.Addr().String(), false, noEnv)
	out.Reset()
	if code := runCheck(&out, s, nil); code != 1 {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	for _, want := range []string{"warn  target", "1 would be probed", "FAIL  port", "would NOT start (1 problem(s)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

func TestGenTokenIsStrongPrivateAndNeverPrinted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zabbix.token")
	var out bytes.Buffer
	if err := genToken(&out, path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	token := strings.TrimSpace(string(b))
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(token) {
		t.Fatalf("token %q", token)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if strings.Contains(out.String(), token) {
		t.Fatal("the token was printed")
	}
	if got, _, err := resolveZabbixToken(true, path, noEnv); err != nil || got != token {
		t.Fatalf("not accepted: %v", err)
	}
	if err := genToken(&out, path); err == nil {
		t.Fatal("overwrote an existing token")
	}
}
