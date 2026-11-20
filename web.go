package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

//go:embed static
var staticFS embed.FS

// sessionCookie is vrf-ping's own name. It used to be "pingping_session", which a
// pingping console on the same host (cookies ignore the port) would overwrite,
// signing the operator out of one whenever they signed in to the other.
const sessionCookie = "vrfping_session"

// loginFailDelay is paid by every wrong password before the answer goes out.
// Tests shorten it.
var loginFailDelay = time.Second

// sessionTTL is an absolute lifetime: a login is good for two hours from the moment
// it was issued, whether or not the page keeps refreshing.
const sessionTTL = 7200 * time.Second

// maxInflight caps concurrent data requests (/api/targets, /api/series). A long
// series read holds the CPU and the disk; five at a time keeps a small host
// responsive no matter how many tabs or clients are open.
const (
	maxInflight = 5
	queueWait   = 30 * time.Second // then 503: a queue this long means the host is saturated
)

// sessions: in-memory, so a restart logs everyone out — acceptable and simple
// for a single-binary tool. Auth exists only when users are passed on the CLI.
type sessions struct {
	mu  sync.Mutex
	m   map[string]time.Time
	now func() time.Time // tests move the clock
}

func newSessions() *sessions { return &sessions{m: map[string]time.Time{}, now: time.Now} }

func (s *sessions) issue() string {
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	now := s.now()
	for t, exp := range s.m { // tokens nobody presents again would otherwise pile up
		if now.After(exp) {
			delete(s.m, t)
		}
	}
	s.m[tok] = now.Add(sessionTTL)
	s.mu.Unlock()
	return tok
}

func (s *sessions) revoke(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

func (s *sessions) valid(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if !ok || s.now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return true
}

// limiter admits at most n handlers at once. Excess requests wait for a slot until
// the client gives up (the UI aborts superseded series queries) or `wait` passes.
func limiter(n int, wait time.Duration) func(http.HandlerFunc) http.HandlerFunc {
	slots := make(chan struct{}, n)
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			t := time.NewTimer(wait)
			defer t.Stop()
			select {
			case slots <- struct{}{}:
			case <-r.Context().Done():
				return
			case <-t.C:
				w.Header().Set("Retry-After", "5")
				jsonErr(w, http.StatusServiceUnavailable, "busy: too many requests in flight, try again shortly")
				return
			}
			defer func() { <-slots }()
			h(w, r)
		}
	}
}

func serveWeb(cfg *Config, store *Store, users map[string]string) error {
	return http.ListenAndServe(cfg.Listen, newMux(cfg, store, users))
}

// webApp holds what the HTTP handlers share. newMux only wires routes; each
// area registers its own, so no single function grows past a screenful.
type webApp struct {
	cfg      *Config
	store    *Store
	users    map[string]string
	sess     *sessions
	throttle *loginThrottle
	limit    func(http.HandlerFunc) http.HandlerFunc
}

func newMux(cfg *Config, store *Store, users map[string]string) http.Handler {
	return securityHeaders(apiRules(buildMux(cfg, store, users)))
}

// buildMux is newMux without the outer wrappers, so tests can ask the router
// which pattern serves a request.
func buildMux(cfg *Config, store *Store, users map[string]string) *http.ServeMux {
	a := &webApp{cfg: cfg, store: store, users: users, sess: newSessions(),
		throttle: newLoginThrottle(), limit: limiter(maxInflight, queueWait)}
	mux := http.NewServeMux()
	a.registerPages(mux)
	a.registerAuth(mux)
	a.registerData(mux)
	registerStats(mux, cfg.ZabbixToken, cfg, store)
	return mux
}

func (a *webApp) authed(r *http.Request) bool {
	if len(a.users) == 0 {
		return true
	}
	c, err := r.Cookie(sessionCookie)
	return err == nil && a.sess.valid(c.Value)
}

func (a *webApp) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) { // before the limiter: unauthenticated requests never hold a slot
			jsonErr(w, http.StatusUnauthorized, "sign in first")
			return
		}
		a.limit(func(w http.ResponseWriter, r *http.Request) {
			t0 := time.Now()
			h(w, r)
			if d := time.Since(t0); d > time.Second {
				log.Printf("slow request: %s %s took %v", r.URL.Path, r.URL.RawQuery, d)
			}
		})(w, r)
	}
}

// page serves one embedded HTML file with a CSP that allows its own inline
// scripts by hash.
func page(name string) http.HandlerFunc {
	b, _ := staticFS.ReadFile("static/" + name)
	csp := pageCSP(b)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", csp)
		w.Write(b)
	}
}

func (a *webApp) registerPages(mux *http.ServeMux) {
	index := page("index.html")
	// Pages are bound to GET like every endpoint, so the router itself can tell a
	// wrong method (405) from a wrong path (404); a catch-all "/" would answer
	// every request it does not recognise with 404, API calls included.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		index(w, r)
	})
	mux.HandleFunc("GET /login", page("login.html"))
	mux.Handle("GET /static/", http.FileServer(http.FS(staticFS)))
}

func (a *webApp) registerAuth(mux *http.ServeMux) {
	// login: constant-time compare, 1s delay on failure, and a per-address lockout
	// after repeated failures (see loginthrottle.go).
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			a.sess.revoke(c.Value) // otherwise the token stays valid until it expires
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
		writeJSON(w, map[string]bool{"ok": true})
	})
}

func (a *webApp) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Before the throttle: this refuses a request that carries no credentials at
	// all, so it must not take the address's one login slot (begin) or count as
	// a guess.
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		jsonErr(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	key := loginClientKey(r)
	if wait, ok := a.throttle.begin(key); !ok {
		w.Header().Set("Retry-After", retryAfter(wait))
		jsonErr(w, http.StatusTooManyRequests, "too many failed logins, try again later")
		return
	}
	var body struct{ User, Pass string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			a.throttle.fail(key) // release the slot taken by begin; junk of this size is abuse, so it counts
			jsonErr(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return
		}
		// Anything else unreadable falls through as an empty login and fails
		// like a wrong password, so the throttle counts it.
	}
	if !a.checkPassword(body.User, body.Pass) {
		a.loginFailed(w, r, key)
		return
	}
	a.throttle.success(key)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: a.sess.issue(),
		Path: "/", HttpOnly: true, MaxAge: int(sessionTTL.Seconds()), SameSite: http.SameSiteLaxMode})
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *webApp) checkPassword(user, pass string) bool {
	want, ok := a.users[user]
	return len(a.users) != 0 && ok &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(want)) == 1
}

func (a *webApp) loginFailed(w http.ResponseWriter, r *http.Request, key string) {
	time.Sleep(loginFailDelay)
	if lock := a.throttle.fail(key); lock > 0 {
		log.Printf("web login failed from %s; address locked for %v", r.RemoteAddr, lock)
	} else {
		log.Printf("web login failed from %s", r.RemoteAddr)
	}
	jsonErr(w, http.StatusUnauthorized, "wrong username or password")
}

func (a *webApp) registerData(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"version": version})
	})
	// health: whether the target lists are applied in full. Same gate as the data:
	// the messages quote list lines, which name the hosts this machine watches.
	mux.HandleFunc("GET /api/health", a.guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, a.cfg.Health.report())
	}))
	mux.HandleFunc("GET /api/routing-options", a.guard(a.getRoutingOptions))
	mux.HandleFunc("PUT /api/routing-options", a.guard(a.putRoutingOptions))
	mux.HandleFunc("GET /api/targets", a.guard(a.handleTargets))
	mux.HandleFunc("GET /api/series", a.guard(a.handleSeries))
}

// getRoutingOptions answers one target's routing as running and as saved for
// the next reload.
func (a *webApp) getRoutingOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	name := r.URL.Query().Get("target")
	for _, target := range a.cfg.TargetList() {
		if target.Name == name {
			a.writeRoutingTarget(w, target)
			return
		}
	}
	jsonErr(w, http.StatusNotFound, "target not found")
}

func (a *webApp) writeRoutingTarget(w http.ResponseWriter, target TargetCfg) {
	routingOptionsMu.Lock()
	options, err := readRoutingOptions(a.cfg.TargetsDir)
	routingOptionsMu.Unlock()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "cannot read routing options")
		return
	}
	saved := target
	if option, ok := options[target.Name]; ok {
		saved.VRF, saved.SourceAddress = option.VRF, option.SourceAddress
	}
	pending := saved.VRF != target.VRF || saved.SourceAddress != target.SourceAddress
	writeJSON(w, map[string]any{"editable": len(a.users) > 0, "target": target, "saved_target": saved, "pending_reload": pending})
}

// routingBody is what PUT /api/routing-options accepts.
type routingBody struct {
	Name          string  `json:"name"`
	VRF           *string `json:"vrf"`
	SourceAddress *string `json:"source_address"`
}

// putRoutingOptions saves one target's routing for the next reload.
func (a *webApp) putRoutingOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if len(a.users) == 0 {
		jsonErr(w, http.StatusForbidden, "Routing is read-only: configure login users to edit.")
		return
	}
	if !routingRequestAllowed(w, r) {
		return
	}
	body, ok := decodeRoutingBody(w, r)
	if !ok {
		return
	}
	routingOptionsMu.Lock()
	defer routingOptionsMu.Unlock()
	a.saveRoutingOption(w, body)
}

// routingRequestAllowed requires an explicit browser same-origin signal and a
// JSON body. Do not trust forwarded headers supplied by clients; the browser
// Origin must match this host.
func routingRequestAllowed(w http.ResponseWriter, r *http.Request) bool {
	if !strictSameOrigin(r) {
		jsonErr(w, http.StatusForbidden, "same-origin request required")
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		jsonErr(w, http.StatusForbidden, "same-origin request required")
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		jsonErr(w, http.StatusUnsupportedMediaType, "application/json required")
		return false
	}
	return true
}

// strictSameOrigin: the Origin header must be exactly this request's scheme
// and host, with nothing else in it.
func strictSameOrigin(r *http.Request) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return err == nil && origin.Scheme == scheme && origin.Host == r.Host && origin.User == nil &&
		origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
}

func decodeRoutingBody(w http.ResponseWriter, r *http.Request) (routingBody, bool) {
	var body routingBody
	if err := decodeRoutingJSON(http.MaxBytesReader(w, r.Body, 8192), &body); err != nil || body.Name == "" || body.VRF == nil || body.SourceAddress == nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			jsonErr(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return body, false
		}
		jsonErr(w, http.StatusBadRequest, "expected name, vrf and source_address JSON fields")
		return body, false
	}
	return body, true
}

// saveRoutingOption validates and stores one change. The caller holds
// routingOptionsMu.
func (a *webApp) saveRoutingOption(w http.ResponseWriter, body routingBody) {
	targets := a.cfg.TargetList()
	found := targetIndex(targets, body.Name)
	if found < 0 {
		jsonErr(w, http.StatusNotFound, "target not found")
		return
	}
	options, err := readRoutingOptions(a.cfg.TargetsDir)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "cannot read routing options")
		return
	}
	// The running snapshot can lag earlier saves. Validate the complete
	// pending overlay, not just the requested change on that stale snapshot.
	applyRoutingOptions(targets, options)
	targets[found].VRF = *body.VRF
	targets[found].SourceAddress = *body.SourceAddress
	candidate := &Config{Targets: targets, Probe: a.cfg.Probe}
	if err := validateTargets(candidate); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	options[body.Name] = routingOption{VRF: *body.VRF, SourceAddress: *body.SourceAddress}
	if err := writeRoutingOptions(a.cfg.TargetsDir, options); err != nil {
		jsonErr(w, http.StatusInternalServerError, "cannot persist routing options")
		return
	}
	// The existing reload loop owns probe replacement, not this handler.
	writeJSON(w, map[string]any{"saved": true, "pending_reload": true, "target": targets[found]})
}

func targetIndex(targets []TargetCfg, name string) int {
	for i := range targets {
		if targets[i].Name == name {
			return i
		}
	}
	return -1
}

func applyRoutingOptions(targets []TargetCfg, options map[string]routingOption) {
	for i := range targets {
		if option, ok := options[targets[i].Name]; ok {
			targets[i].VRF = option.VRF
			targets[i].SourceAddress = option.SourceAddress
		}
	}
}

// targetItem is one row of GET /api/targets.
type targetItem struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	IntervalSec   int    `json:"interval_sec"`
	Pace          string `json:"pace"`
	Down          bool   `json:"down"`
	VRF           string `json:"vrf"`
	SourceAddress string `json:"source_address"`
	Error         string `json:"error,omitempty"`
	Last1h        Stats  `json:"last_1h"`
	Last24h       Stats  `json:"last_24h"`
}

func (a *webApp) handleTargets(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	byName := map[string]TargetCfg{}
	for _, t := range a.cfg.TargetList() {
		byName[t.Name] = t
	}
	var out []targetItem
	for _, name := range a.store.Names() {
		out = append(out, a.targetItem(name, byName[name], now))
	}
	writeJSON(w, out)
}

func (a *webApp) targetItem(name string, t TargetCfg, now time.Time) targetItem {
	iv, _ := probeParams(t, a.cfg.Probe)
	pace := t.Pace
	if pace == "" {
		pace = "normal"
	}
	rec := a.store.Recent(name, now.Add(-time.Hour).Unix())
	down := len(rec) > 0 && rec[len(rec)-1].S > 0 && rec[len(rec)-1].R == 0 && rec[len(rec)-1].Error == ""
	probeError := ""
	if len(rec) > 0 {
		probeError = rec[len(rec)-1].Error
	}
	return targetItem{
		Name: name, Type: t.Type, Host: targetAddr(t),
		VRF: t.VRF, SourceAddress: t.SourceAddress, Error: probeError,
		IntervalSec: int(iv.Seconds()), Pace: pace, Down: down,
		Last1h:  calcStats(rec),
		Last24h: calcStats(a.store.Recent(name, now.Add(-24*time.Hour).Unix())),
	}
}

// handleSeries returns raw rounds for smoke. Supports either minutes=N (recent
// window) or from/to unix (arbitrary range). No thinning: every sample is
// returned as stored.
func (a *webApp) handleSeries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := q.Get("target")
	from, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	to, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	if from == 0 || to == 0 {
		minutes, _ := strconv.Atoi(q.Get("minutes"))
		if minutes <= 0 || minutes > 432000 { // up to 300 days
			minutes = 360
		}
		to = time.Now().Unix()
		from = to - int64(minutes)*60
	}
	writeJSON(w, a.store.ReadRange(r.Context(), name, from, to))
}

func targetAddr(t TargetCfg) string {
	if t.Type == "tcp" {
		return t.Host + ":" + strconv.Itoa(t.Port)
	}
	return t.Host
}
