package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Read-only statistics for Zabbix. Same contract and same template as fogping:
// https://github.com/githubflyideas/fogping/tree/main/zabbix
//
// Off unless vrf-ping runs with --zabbix (and a token), and off means absent: no
// route, nothing in the UI. vrf-ping without it is exactly vrf-ping. With a
// token, GET /api/stats returns the latest summary of every target —
// percentiles, loss, bursts — and nothing else: no hosts, no ports, no VRF or
// source address, no version, no raw samples. It never writes.

// statsWindow is how far back the summary looks.
const statsWindow = 5 * time.Minute

// statsTarget is the contract with the Zabbix template, shared with fogping and
// pingping. Fields may be added; none may be renamed or change meaning.
type statsTarget struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Rounds      int      `json:"rounds"`
	P50         *float64 `json:"p50,omitempty"` // ms
	P90         *float64 `json:"p90,omitempty"`
	P99         *float64 `json:"p99,omitempty"`
	LossPct     *float64 `json:"loss_pct,omitempty"`
	Bursts      int      `json:"bursts"`
	Up          *int     `json:"up,omitempty"`
	ProbeErrors int      `json:"probe_errors"` // rounds that could not probe at all (e.g. VRF bind failed)
}

type statsReport struct {
	WindowSec int           `json:"window_sec"`
	Targets   []statsTarget `json:"targets"`
}

// targetID gives a list-file target a stable number for Zabbix item keys.
// vrf-ping identifies targets by name, so the id is derived from it: the same
// name always gets the same id, and a rename starts a new item — as a changed
// routing context already starts a new history in vrf-ping itself. 48 bits
// stay exact in JSON numbers.
func targetID(name string) int64 {
	h := sha256.Sum256([]byte(name))
	return int64(binary.BigEndian.Uint64(h[:8]) >> 16)
}

// resolveZabbixToken reads the token from --zabbix-token-file or from
// VRFPING_ZABBIX_TOKEN / VRFPING_ZABBIX_TOKEN_FILE.
//
// Without --zabbix (enabled=false) the token is ignored and the integration is
// off; ignored reports that one was supplied anyway, so the caller can say so.
// With --zabbix a token is required: an open stats endpoint is never an option.
func resolveZabbixToken(enabled bool, file string, getenv func(string) string) (token string, ignored bool, err error) {
	envTok, envFile := getenv("VRFPING_ZABBIX_TOKEN"), getenv("VRFPING_ZABBIX_TOKEN_FILE")
	if !enabled {
		return "", file != "" || envTok != "" || envFile != "", nil
	}
	if file == "" {
		switch {
		case envTok != "" && envFile != "":
			return "", false, errStr("set VRFPING_ZABBIX_TOKEN or VRFPING_ZABBIX_TOKEN_FILE, not both")
		case envTok != "":
			token = envTok
		default:
			file = envFile
		}
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", false, errStr("zabbix token file: " + err.Error())
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		return "", false, errStr("--zabbix needs a token: set VRFPING_ZABBIX_TOKEN=... or VRFPING_ZABBIX_TOKEN_FILE=PATH (or --zabbix-token-file PATH)")
	}
	if len(token) < 16 {
		return "", false, errStr("zabbix token must be at least 16 characters")
	}
	return token, false, nil
}

type errStr string

func (e errStr) Error() string { return string(e) }

func statsErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// registerStats adds GET /api/stats when --zabbix gave a token, and nothing
// otherwise.
func registerStats(mux *http.ServeMux, token string, cfg *Config, store *Store) {
	if token == "" {
		return
	}
	throttle := newLoginThrottle() // wrong tokens are guesses too
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET")
			statsErr(w, http.StatusMethodNotAllowed, "read-only")
			return
		}
		key := loginClientKey(r)
		if wait, ok := throttle.begin(key); !ok {
			w.Header().Set("Retry-After", retryAfter(wait))
			statsErr(w, http.StatusTooManyRequests, "too many failed attempts")
			return
		}
		got, isBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !isBearer || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			if lock := throttle.fail(key); lock > 0 {
				log.Printf("stats: bad token from %s; address locked for %v", r.RemoteAddr, lock)
			}
			statsErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		throttle.success(key)
		writeJSON(w, buildStats(store, cfg.TargetList(), time.Now()))
	})
}

func buildStats(store *Store, targets []TargetCfg, now time.Time) statsReport {
	out := statsReport{WindowSec: int(statsWindow / time.Second), Targets: []statsTarget{}}
	since := now.Add(-statsWindow).Unix()
	for _, t := range targets {
		// A round that could not probe at all (S == 0, Error set) is not loss:
		// counting it would report a broken VRF binding as 0% loss. Count it
		// apart and leave it out of the numbers.
		var measured []Round
		errs := 0
		for _, r := range store.Recent(t.Name, since) {
			if r.S == 0 {
				errs++
				continue
			}
			measured = append(measured, r)
		}
		st := calcStats(measured)
		item := statsTarget{ID: targetID(t.Name), Name: t.Name, Rounds: st.Rounds, Bursts: st.Bursts, ProbeErrors: errs}
		if st.Rounds > 0 {
			loss := st.LossPct
			item.LossPct = &loss
			up := 0
			if measured[len(measured)-1].R > 0 {
				up = 1
			}
			item.Up = &up
			if st.LossPct < 100 {
				p50, p90, p99 := st.P50, st.P90, st.P99
				item.P50, item.P90, item.P99 = &p50, &p90, &p99
			}
		}
		out.Targets = append(out.Targets, item)
	}
	return out
}
