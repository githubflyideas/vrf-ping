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
	old := runningAsRoot
	runningAsRoot = func() bool { return false }
	defer func() { runningAsRoot = old }()
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
	text = strings.Join(securitySummary(pw), "\n")
	for _, want := range []string{"visible in ps", "1 password(s) shorter than 8"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	runningAsRoot = func() bool { return true }
	open2, _ := prepare(nil, false, "", "0.0.0.0:8517", false, noEnv)
	text = strings.Join(securitySummary(open2), "\n")
	for _, want := range []string{"! account", "! transport"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
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

// The password can come from the environment or a file, so it never has to be on
// the command line where every account can read it.
func TestLoginFromEnvironmentOrFile(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	users, cli, err := resolveAuth(nil, env(map[string]string{"VRFPING_USER": "admin", "VRFPING_PASSWD": "long-enough-pw"}))
	if err != nil || cli || users["admin"] != "long-enough-pw" {
		t.Fatalf("environment: %v %v %v", users, cli, err)
	}
	file := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(file, []byte("from-file-pw\n"), 0o600)
	users, cli, err = resolveAuth([]string{"user=admin", "passwd-file=" + file}, noEnv)
	if err != nil || cli || users["admin"] != "from-file-pw" {
		t.Fatalf("file: %v %v %v", users, cli, err)
	}
	users, cli, _ = resolveAuth([]string{"user=admin", "passwd=on-the-line"}, noEnv)
	if !cli || users["admin"] != "on-the-line" {
		t.Fatal("a command-line password is not reported as such")
	}
	if _, _, err := resolveAuth(nil, env(map[string]string{"VRFPING_USER": "a", "VRFPING_PASSWD": "x", "VRFPING_PASSWD_FILE": file})); err == nil {
		t.Fatal("both VRFPING_PASSWD and VRFPING_PASSWD_FILE accepted")
	}
	if _, _, err := resolveAuth([]string{"user=a", "passwd=x", "passwd-file=" + file}, noEnv); err == nil {
		t.Fatal("both passwd= and passwd-file= accepted")
	}
}
