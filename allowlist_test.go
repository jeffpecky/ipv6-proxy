package main

// Tests for the target allowlist ported from the HE gateway. These guard the
// one thing that keeps a public proxy from being an open relay, so they cover
// the fail-closed paths, not just the happy path.
//
// Run: go test ./...

import "testing"

func withAllow(entries []string, token string, fn func()) {
	oldEntries, oldToken := allowEntries, allowToken
	allowEntries, allowToken = parseAllowList(entries), token
	defer func() { allowEntries, allowToken = oldEntries, oldToken }()
	fn()
}

func TestParseAllowListSplitsAndTrims(t *testing.T) {
	got := parseAllowList([]string{" https://a.test/ , https://b.test ", ""})
	want := []string{"https://a.test", "https://b.test"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestExactOriginAllowedWithoutToken(t *testing.T) {
	withAllow([]string{"https://opencode.ai"}, "", func() {
		if !allowTarget("opencode.ai", 443, "") {
			t.Fatal("exact origin must be allowed")
		}
	})
}

func TestUnlistedTargetBlocked(t *testing.T) {
	withAllow([]string{"https://opencode.ai"}, "", func() {
		if allowTarget("example.com", 443, "") {
			t.Fatal("unlisted target must be blocked")
		}
	})
}

func TestWildcardNeedsToken(t *testing.T) {
	withAllow([]string{"*.example.com"}, "", func() {
		if allowTarget("api.example.com", 443, "") {
			t.Fatal("wildcard without a token must fail closed")
		}
	})
	withAllow([]string{"*.example.com"}, "secret", func() {
		if allowTarget("api.example.com", 443, "") {
			t.Fatal("wildcard without the token must be blocked")
		}
		if !allowTarget("api.example.com", 443, "secret") {
			t.Fatal("wildcard with the token must be allowed")
		}
		if allowTarget("api.example.com", 443, "wrong") {
			t.Fatal("wildcard with a wrong token must be blocked")
		}
	})
}

func TestWildcardMatchesApexAndSubdomains(t *testing.T) {
	withAllow([]string{"*.example.com"}, "t", func() {
		for _, h := range []string{"example.com", "a.example.com", "a.b.example.com"} {
			if !allowTarget(h, 443, "t") {
				t.Fatalf("%s should match the wildcard", h)
			}
		}
		if allowTarget("notexample.com", 443, "t") {
			t.Fatal("suffix must not match a lookalike domain")
		}
	})
}

func TestEmptyAllowlistIsOpen(t *testing.T) {
	// Documented behaviour, and the startup log says "OPEN" in those words.
	withAllow(nil, "", func() {
		if !allowTarget("anything.test", 443, "") {
			t.Fatal("an empty allowlist means open")
		}
	})
}

func TestNonHTTPPortFailsClosed(t *testing.T) {
	withAllow([]string{"https://opencode.ai"}, "", func() {
		// An exact origin is 443; a CONNECT to 22 is a different origin and
		// must not inherit the *.ai permission.
		if allowTarget("opencode.ai", 22, "") {
			t.Fatal("a non-HTTP port must not match an https origin")
		}
	})
}

func TestTargetOriginForms(t *testing.T) {
	cases := []struct {
		host string
		port uint16
		want string
	}{
		{"opencode.ai", 443, "https://opencode.ai"},
		{"opencode.ai", 80, "http://opencode.ai"},
		{"opencode.ai", 8443, "https://opencode.ai:8443"},
		{"2001:db8::1", 443, "https://[2001:db8::1]"},
	}
	for _, c := range cases {
		if got := targetOrigin(c.host, c.port); got != c.want {
			t.Errorf("targetOrigin(%q,%d) = %q want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestRegexEntryMatchesOrigin(t *testing.T) {
	withAllow([]string{`re:^https://.*\.opencode\.ai$`}, "t", func() {
		if !allowTarget("api.opencode.ai", 443, "t") {
			t.Fatal("regex entry should match")
		}
		if allowTarget("evil.test", 443, "t") {
			t.Fatal("regex entry must not match an unrelated host")
		}
	})
}
