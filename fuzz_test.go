package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Fuzz tests for everything that reads input vrf-ping does not control: a line of a
// target list and a target's options. Each checks more than "does not panic":
// whatever is ACCEPTED must satisfy the rules the rest of the code relies on.
//
// `go test` runs the seeds only. To search for new inputs:
//   go test -run '^$' -fuzz FuzzListLineToTarget -fuzztime 30s

func seedVectors(f *testing.F, file, field string) {
	b, err := os.ReadFile("docs/conformance/" + file)
	if err != nil {
		f.Fatal(err)
	}
	var doc struct {
		Vectors []map[string]json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		f.Fatal(err)
	}
	for _, v := range doc.Vectors {
		if raw, ok := v[field]; ok {
			f.Add([]byte(raw))
		}
	}
}

// fuzzSpecs has one option of every kind, so one corpus exercises all of them.
var fuzzSpecs = []optionSpec{
	{Key: "name", Label: "Name", Kind: optString, Required: true, MaxLen: 16},
	{Key: "mode", Label: "Mode", Kind: optChoice, Choices: []string{"a", "b"}, Default: "a"},
	{Key: "count", Label: "Count", Kind: optInt, Min: 1, Max: 9},
	{Key: "flag", Label: "Flag", Kind: optBool},
}

func FuzzNormalizeOptions(f *testing.F) {
	seedVectors(f, "options.json", "input")
	f.Add([]byte(`{"name":"x","count":1e300}`))
	f.Add([]byte(`{"name":"x","count":-0.0}`))
	f.Add([]byte(`{"name":["x"],"mode":{"a":1}}`))
	f.Add([]byte(`{"name":"\u202e\u0000"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var in map[string]any
		if json.Unmarshal(raw, &in) != nil {
			return // not an object: the API layer refuses it before this
		}
		tg := TargetCfg{Options: in}
		if err := normalizeOptions("fuzz", fuzzSpecs, &tg); err != nil {
			if errCode(err) == "" {
				t.Fatalf("an error with no code: %v", err)
			}
			return
		}
		allowed := map[string]bool{"name": true, "mode": true, "count": true, "flag": true}
		for k, v := range tg.Options {
			if !allowed[k] {
				t.Fatalf("an undeclared key %q survived", k)
			}
			switch k {
			case "name", "mode":
				if _, ok := v.(string); !ok {
					t.Fatalf("%s is %T", k, v)
				}
			case "count":
				if n, ok := v.(int); !ok || n < 1 || n > 9 {
					t.Fatalf("count is %#v", v)
				}
			case "flag":
				if _, ok := v.(bool); !ok {
					t.Fatalf("flag is %T", v)
				}
			}
		}
		if _, ok := tg.Options["name"]; !ok {
			t.Fatal("a required option is missing from an accepted target")
		}
		// Normalising is idempotent: what comes out is what a stored target looks like,
		// and it must be accepted again as it is.
		again := TargetCfg{Options: tg.Options}
		if err := normalizeOptions("fuzz", fuzzSpecs, &again); err != nil {
			t.Fatalf("the output is refused when fed back: %v", err)
		}
		if encodeOptions(again.Options) != encodeOptions(tg.Options) {
			t.Fatalf("not idempotent: %s then %s", encodeOptions(tg.Options), encodeOptions(again.Options))
		}
		if len(encodeOptions(tg.Options)) > maxOptionBytes {
			t.Fatal("accepted options over the size limit")
		}
	})
}

// A list line, as it travels from the file to a probed target: parse it, validate it,
// and check what comes out. An accepted target must be one the probe can run.
func FuzzListLineToTarget(f *testing.F) {
	for _, s := range []struct{ line, typ string }{
		{"10.0.0.1 router", "icmp"},
		{"10.0.0.5:443 gw vrf=blue source=10.0.0.2 pace=fast", "tcp"},
		{"example.org:443 site path=/health expect_status=200 follow_redirects=true", typeHTTP},
		{"example.org:443 site scheme=http method=HEAD host_header=x.example", typeHTTP},
		{"999.999.999.999:99999 bad", "tcp"},
		{"example.org:443 typo pth=/x", typeHTTP},
		{"[2001:db8::1]:443 v6", typeHTTP},
		{"host:0 x", "tcp"},
	} {
		f.Add(s.line, s.typ)
	}
	f.Fuzz(func(t *testing.T, line, typ string) {
		switch typ {
		case "icmp", "tcp", typeHTTP:
		default:
			typ = "icmp"
		}
		tg, err := parseListLine(line, typ)
		if err != nil {
			return
		}
		if err := validateTarget(&tg, 0, map[string]bool{}, map[string]bool{}); err != nil {
			return
		}
		if tg.Name == "" || tg.Host == "" || strings.ContainsAny(tg.Host, " \t\r\n") {
			t.Fatalf("accepted name %q host %q from %q", tg.Name, tg.Host, line)
		}
		if numericButNotIP(tg.Host) {
			t.Fatalf("accepted the mistyped address %q", tg.Host)
		}
		switch tg.Type {
		case "icmp":
			if len(tg.Options) != 0 {
				t.Fatalf("a ping target with options: %v", tg.Options)
			}
		case "tcp", typeHTTP:
			if tg.Port < 1 || tg.Port > 65535 {
				t.Fatalf("accepted port %d from %q", tg.Port, line)
			}
		default:
			t.Fatalf("accepted type %q", tg.Type)
		}
		if tg.Type == typeHTTP {
			// Every option of an accepted http target is a declared one with a valid value,
			// and normalising what came out changes nothing.
			again := tg
			again.Options = map[string]any{}
			for k, v := range tg.Options {
				again.Options[k] = v
			}
			if err := normalizeOptions(typeHTTP, httpSpecs, &again); err != nil {
				t.Fatalf("the output is refused when fed back: %v (%v)", err, tg.Options)
			}
			if encodeOptions(again.Options) != encodeOptions(tg.Options) {
				t.Fatalf("not idempotent: %s then %s", encodeOptions(tg.Options), encodeOptions(again.Options))
			}
			if err := validateHTTP(&tg); err != nil {
				t.Fatalf("an accepted http target fails its own check: %v", err)
			}
		}
	})
}
