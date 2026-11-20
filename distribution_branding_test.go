package main

import (
	"os"
	"strings"
	"testing"
)

func TestDistributionUsesVRFPingName(t *testing.T) {
	cases := []struct {
		file string
		want []string
	}{
		{".goreleaser.yaml", []string{"project_name: vrf-ping", "binary: vrf-ping", "./vrf-ping"}},
		{"package.json", []string{`"name": "vrf-ping-browser-tests"`}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			b, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(b), want) {
					t.Errorf("%s must contain %q", tc.file, want)
				}
			}
		})
	}
}

// Release archives must not carry the CI runner's uid/gid (1001): extracted as
// root, the files would belong to whichever local account has that uid.
func TestReleaseArchiveOwnedByRoot(t *testing.T) {
	b, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, block := range []string{"builds_info:", "- src: LICENSE"} {
		i := strings.Index(s, block)
		if i < 0 {
			t.Fatalf(".goreleaser.yaml has no %s block", block)
		}
		rest := s[i:]
		if !strings.Contains(rest, "owner: root") || !strings.Contains(rest, "group: root") {
			t.Errorf(".goreleaser.yaml %s must set owner and group root", block)
		}
	}
}

// goreleaser must publish to the repository's real name, and the only name that
// is always right is the one in the checkout's git remote. The old name only
// redirects, and the upload API answers a redirect with 307 instead of storing the
// asset, so a name written into the config fails every release after a rename
// (v3.3.2, v3.3.9). Keep it out of the release block.
func TestReleaseTakesTheRepositoryNameFromGit(t *testing.T) {
	b, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// The release: block is every line after "release:" up to the next top-level key.
	inRelease := false
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if line != "" && line[0] != ' ' && line[0] != '\t' && line[0] != '#' {
			inRelease = trimmed == "release:"
			continue
		}
		if inRelease && strings.HasPrefix(trimmed, "github:") {
			t.Errorf(".goreleaser.yaml release.github must be absent so GoReleaser reads the name from git: %q", trimmed)
		}
	}
}
