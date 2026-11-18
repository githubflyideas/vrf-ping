# HTTP API

vrf-ping's web UI and the Zabbix template talk to vrf-ping through this API. The
same rules hold in fogping and pingping, so a client written for one reads the
others the same way. Targets themselves are not edited through the API: they
come from `targets/*.list` (see the README).

## Rules

These are enforced by tests (`api_test.go`): code that breaks one does not pass CI.

1. **Version.** This is API version 1. Every `/api/` response carries the header
   `API-Version: 1`. Within version 1, changes are only additive: new endpoints,
   new optional request fields, new response fields. Removing or renaming a field,
   or changing what it means, needs a new prefix `/api/v2/`, and `/api/` keeps
   answering as before.
2. **Methods.** Every endpoint names its methods. Reads are `GET`, creates
   `POST`, replacements `PUT`, deletions `DELETE`, actions `POST`. Any other
   method gets `405` with an `Allow` header.
3. **JSON in, JSON out.** A request with a body sends
   `Content-Type: application/json` (anything else gets `415`). Every response,
   errors included, is `application/json; charset=utf-8`.
4. **One error shape.** Every error is
   `{"error": "<message for a person>", "code": "<code for a program>"}`.
   Programs branch on `code` (or the status); people read `error`. The codes:

   | Status | `code` |
   |---|---|
   | 400 | `bad_request` |
   | 401 | `unauthorized` |
   | 403 | `forbidden` |
   | 404 | `not_found` |
   | 405 | `method_not_allowed` |
   | 409 | `conflict` |
   | 413 | `too_large` |
   | 415 | `unsupported_media_type` |
   | 429 | `rate_limited` (with `Retry-After`) |
   | 500 | `internal` |
   | 503 | `unavailable` |

   An unknown path under `/api/` is a `404` in the same shape.
5. **Names.** JSON keys are `snake_case`, in requests and responses. Times are
   Unix seconds; a duration or size says its unit in its name (`interval_sec`,
   `window_sec`); a percentage ends in `_pct`. The one exception is the compact
   sample format of `/api/series` (below), which predates these rules and is
   kept for compatibility.
6. **Authentication.** The web UI signs in with `POST /api/login` and then sends
   the `vrfping_session` cookie. Machine clients use a bearer token
   (`Authorization: Bearer …`) where an endpoint says so. A missing or bad
   credential is `401`. The one write, `PUT /api/routing-options`, needs a login
   to be configured and a same-origin browser request (`403` otherwise).
7. **Documented.** Every endpoint is listed below. A test compares this table with
   the routes the code registers, both ways.

## Endpoints

| Method | Path | Auth | What it does |
|---|---|---|---|
| POST | /api/login | none | Sign in. Body `{"user": "…", "pass": "…"}`; sets the session cookie. Repeated failures from one address get `429`. |
| POST | /api/logout | none | Sign out: the session ends on the server too. Safe to call without one. |
| GET | /api/version | none | `{"version"}`. |
| GET | /api/health | session | Whether the target lists are applied in full: lines skipped at startup and the latest refused reload. |
| GET | /api/routing-options | session | `?target=NAME`: the target's active and saved VRF and source address, and whether a reload is pending. |
| PUT | /api/routing-options | session, login configured, same-origin | Save a target's VRF and source address. Body `{"name", "vrf", "source_address"}`; applied by the next reload. |
| GET | /api/targets | session | Every target with its last-hour and last-day summary, routing and latest probe error. |
| GET | /api/series | session | Rounds for one target: `?target=NAME` and either `?minutes=N` or `?from=&to=` (Unix seconds). |
| GET | /api/stats | bearer token | Per-target summary of the last 5 minutes, for Zabbix. Exists only with `--zabbix`. |

"session" means: a signed-in session when vrf-ping was started with a login,
anyone otherwise. Data requests (`/api/targets`, `/api/series`) are limited to a
few at a time; beyond that they wait, and after 30 seconds get `503`.

## `/api/series` format

```json
[{"t": 1700000000, "s": 20, "r": 19, "ms": [12.1, 12.4], "b": true, "z": 3.8},
 {"t": 1700000060, "s": 0, "r": 0, "ms": null, "error": "bind to VRF blue: no such device"}]
```

One entry per round, oldest first: `t` time (Unix seconds), `s` packets sent,
`r` received, `ms` every reply's round-trip time in milliseconds, `b` true when
the round was flagged as a loss burst, `z` the robust z-score behind that flag,
`error` set when the round could not probe at all (then `s` and `r` are 0; it is
not packet loss). Rounds older than the full-sample window are downsampled in
place and keep the same shape.
