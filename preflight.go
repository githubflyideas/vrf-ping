package main

// Start-up made easy to get right, without loosening anything (the same three tools
// as fogping and pingping):
//
//   - prepare returns ALL the problems with the flags and credentials at once, so a
//     refused start names everything to fix, not the first thing.
//   - --check runs the same preparation plus the checks that need the machine
//     (working directory, target lists, port) and reports, without starting: run it
//     before restarting a service, and a mistake never takes monitoring down.
//   - --gen-token writes a strong random token to a file only its owner can read, so
//     the safe way to configure Zabbix is also the easy one.
//
// And at every start a security summary says what is exposed. Every refusal stays a
// refusal (ISO/IEC 27001:2022 A.8.9, A.8.15, A.8.24; ISO/IEC 25010:2023 user error
// protection).

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// setup is everything the command line and the environment decided.
type setup struct {
	cfg          *Config
	users        map[string]string
	localOnly    bool
	cliPasswd    bool // a password was given on the command line (visible in ps)
	tokenIgnored bool
}

// prepare reads the auth arguments, the Zabbix token and the listen address, and
// returns every problem instead of stopping at the first.
func prepare(args []string, zabbix bool, tokenFile, listen string, localOnly bool, getenv func(string) string) (setup, []error) {
	var problems []error
	s := setup{cfg: defaultConfig(), localOnly: localOnly}
	users, cliPasswd, err := resolveAuth(args, getenv)
	if err != nil {
		problems = append(problems, fmt.Errorf("bad auth args: %v", err))
	}
	s.users, s.cliPasswd = users, cliPasswd
	token, ignored, err := resolveZabbixToken(zabbix, tokenFile, getenv)
	if err != nil {
		problems = append(problems, err)
	}
	s.cfg.ZabbixToken, s.tokenIgnored = token, ignored
	if addr, err := listenAddr(listen, localOnly); err != nil {
		problems = append(problems, fmt.Errorf("bad --listen: %v", err))
	} else {
		s.cfg.Listen = addr
	}
	return s, problems
}

// loopbackOnly says whether a listen address accepts connections from this machine
// only: a loopback IP (127.x, ::1) or the name localhost.
func loopbackOnly(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// securitySummary describes what this instance exposes. Lines that deserve a second
// look start with "!".
func securitySummary(s setup) []string {
	var out []string
	line := func(risky bool, name, text string) {
		mark := " "
		if risky {
			mark = "!"
		}
		out = append(out, fmt.Sprintf("%s %-9s %s", mark, name, text))
	}
	local := loopbackOnly(s.cfg.Listen)
	if local {
		line(false, "listen", s.cfg.Listen+" (this machine only)")
	} else {
		line(true, "listen", s.cfg.Listen+" (every interface: reachable from the network)")
	}
	if !local {
		line(true, "transport", "plain HTTP: logins and pages cross the network unencrypted; put an HTTPS reverse proxy in front")
	}
	switch {
	case len(s.users) > 0:
		// Every issue with the login is named, not just the first.
		var issues []string
		if weak := weakPasswords(s.users); weak > 0 {
			issues = append(issues, fmt.Sprintf("%d password(s) shorter than %d characters", weak, minPasswordLen))
		}
		if s.cliPasswd {
			issues = append(issues, "the password is on the command line, visible in ps")
		}
		text := fmt.Sprintf("on, %d user(s)", len(s.users))
		if len(issues) > 0 {
			text += "; " + strings.Join(issues, "; ")
		}
		line(len(issues) > 0, "login", text)
	case local:
		line(false, "login", "off (only this machine can connect; put a reverse proxy with login in front)")
	default:
		line(true, "login", "OFF: anyone who can reach the port can see the charts")
	}
	line(false, "editing", "routing options only, and only with a login")
	if runningAsRoot() {
		line(true, "account", "running as root: a flaw anywhere is a flaw with full control of this machine; use an ordinary account (a VRF needs only CAP_NET_RAW)")
	}
	if s.cfg.ZabbixToken != "" {
		line(false, "zabbix", "on: GET /api/stats with a read-only token")
	} else {
		line(false, "zabbix", "off")
	}
	return out
}

type machineCheck struct {
	name, detail string
	err          error
	warnOnly     bool // reported, but vrf-ping would still start (a skipped list line)
}

// runCheck is --check: it reports on the configuration and the machine and exits
// without starting anything. 0 means vrf-ping would start; 1 means it would not.
func runCheck(w io.Writer, s setup, problems []error) int {
	fmt.Fprintln(w, "vrf-ping --check: nothing is started; this only reports.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "configuration")
	if len(problems) == 0 {
		fmt.Fprintln(w, "  ok    flags, login and tokens")
	}
	for _, p := range problems {
		fmt.Fprintf(w, "  FAIL  %v\n", p)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "this machine")
	failed := len(problems)
	for _, c := range checkMachine(s) {
		status, detail := "ok  ", c.detail
		switch {
		case c.err != nil && c.warnOnly:
			status, detail = "warn", c.err.Error()
		case c.err != nil:
			status, detail = "FAIL", c.err.Error()
			failed++
		}
		fmt.Fprintf(w, "  %s  %-9s %s\n", status, c.name, detail)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "security summary")
	for _, l := range securitySummary(s) {
		fmt.Fprintln(w, "  "+l)
	}
	fmt.Fprintln(w)
	if failed > 0 {
		fmt.Fprintf(w, "result: vrf-ping would NOT start (%d problem(s) above)\n", failed)
		return 1
	}
	fmt.Fprintln(w, "result: vrf-ping would start")
	return 0
}

// checkMachine looks at what the start-up needs from this machine without changing
// anything: no demo list is written, no data directory created.
func checkMachine(s setup) []machineCheck {
	var out []machineCheck
	if err := checkWritable("."); err != nil {
		out = append(out, machineCheck{name: "workdir", err: fmt.Errorf("cannot write to the working directory: %v", err)})
	} else {
		out = append(out, machineCheck{name: "workdir", detail: "writable"})
	}
	out = append(out, checkTargets(s.cfg.TargetsDir)...)
	if ln, err := net.Listen("tcp", s.cfg.Listen); err != nil {
		out = append(out, machineCheck{name: "port", err: fmt.Errorf("cannot listen on %s: %v", s.cfg.Listen, err)})
	} else {
		ln.Close()
		out = append(out, machineCheck{name: "port", detail: s.cfg.Listen + " is free"})
	}
	return out
}

// checkTargets reads the lists the way the start-up does: a bad line is skipped
// (a warning), a broken routing-options.json or no target at all stops the start.
func checkTargets(dir string) []machineCheck {
	if _, err := os.Stat(filepath.Join(dir, "ping.list")); errors.Is(err, os.ErrNotExist) {
		return []machineCheck{{name: "targets", detail: "none yet; " + dir + "/ping.list with a demo target will be created"}}
	}
	ts, problems := loadTargetListsLenient(dir)
	if err := loadRoutingOptions(dir, ts); err != nil {
		return []machineCheck{{name: "targets", err: err}}
	}
	ts, bad := validateTargetsLenient(ts)
	problems = append(problems, bad...)
	var out []machineCheck
	for _, p := range problems {
		out = append(out, machineCheck{name: "target", warnOnly: true, err: fmt.Errorf("would be skipped: %s", p)})
	}
	if len(ts) == 0 && len(problems) == 0 {
		return append(out, machineCheck{name: "targets",
			err: fmt.Errorf("no targets: add one line to %s/ping.list, tcp.list or http.list", dir)})
	}
	return append(out, machineCheck{name: "targets", detail: fmt.Sprintf("%d would be probed", len(ts))})
}

// genToken writes a new random token to path, readable by its owner only. It never
// overwrites a file (an existing token may be in use) and never prints the token:
// it would end up in the terminal's scrollback and in logs.
func genToken(w io.Writer, path string) error {
	b := make([]byte, 32) // 256 bits from the operating system's CSPRNG
	if _, err := rand.Read(b); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; not overwriting it (it may be in use). Remove it first, or choose another path", path)
		}
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(b) + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote a new 64-character token to %s (readable by you only).\n", path)
	fmt.Fprintf(w, "start vrf-ping with it:\n  ./vrf-ping --zabbix --zabbix-token-file %s\n", path)
	fmt.Fprintf(w, "and give the same token to the Zabbix template ({$FOGPING.TOKEN}).\n")
	return nil
}

// minPasswordLen is the shortest password not flagged as weak: pingping's rule.
const minPasswordLen = 8

// weakPasswords counts the passwords shorter than minPasswordLen. A short one is
// warned about, not refused: refusing would stop a running setup at its next start.
func weakPasswords(users map[string]string) int {
	n := 0
	for _, pw := range users {
		if len([]rune(pw)) < minPasswordLen {
			n++
		}
	}
	return n
}

// runningAsRoot is a variable so tests can pretend.
var runningAsRoot = func() bool { return os.Geteuid() == 0 }
