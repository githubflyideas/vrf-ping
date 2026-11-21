package main

import (
	"reflect"
	"testing"
)

// The family speaks both spellings: vrf-ping's flags (--check,
// --gen-token=F) and the subcommand forms (check, gen-token F).
// aliasArgs translates only the first argument.
func TestAliasArgs(t *testing.T) {
	cases := []struct {
		in, want []string
	}{
		{nil, nil},
		{[]string{}, []string{}},
		{[]string{"check"}, []string{"--check"}},
		{[]string{"check", "user=admin", "passwd=x"}, []string{"--check", "user=admin", "passwd=x"}},
		{[]string{"gen-token", "tok.txt"}, []string{"--gen-token=tok.txt"}},
		{[]string{"gen-token", "tok.txt", "--zabbix"}, []string{"--gen-token=tok.txt", "--zabbix"}},
		{[]string{"gen-token"}, []string{"--gen-token"}},
		{[]string{"--check"}, []string{"--check"}},
		{[]string{"--gen-token=tok.txt"}, []string{"--gen-token=tok.txt"}},
		{[]string{"user=admin", "passwd=x"}, []string{"user=admin", "passwd=x"}},
		{[]string{"checkup"}, []string{"checkup"}},
		{[]string{"--localhost", "check"}, []string{"--localhost", "check"}},
	}
	for _, c := range cases {
		if got := aliasArgs(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("aliasArgs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
