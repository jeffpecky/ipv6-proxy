package main

// Tests for multi-prefix pool accounting. New addresses are spread over all
// configured prefixes so a drained bucket can actually be escaped.

import (
	"net"
	"testing"
	"time"
)

func setPrefixes(t *testing.T, cidrs ...string) {
	t.Helper()
	pools := []*net.IPNet{}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("bad cidr %q: %v", c, err)
		}
		pools = append(pools, n)
	}
	old := prefixPools
	prefixPools = pools
	t.Cleanup(func() { prefixPools = old })
}

func resetPool(ips ...string) {
	poolLock.Lock()
	ipv6Pool = []net.IP{}
	ipv6PoolIndex = map[string]int{}
	for _, s := range ips {
		ip := net.ParseIP(s)
		ipv6PoolIndex[ip.String()] = len(ipv6Pool)
		ipv6Pool = append(ipv6Pool, ip)
	}
	poolLock.Unlock()
}

func TestPrefixOfDistinguishesBlocks(t *testing.T) {
	setPrefixes(t, "2001:470:5:559::/64", "2001:470:4:559::/64")

	if got := prefixOf(net.ParseIP("2001:470:5:559:1::1")); got != "2001:470:5:559::/64" {
		t.Errorf("pool prefix = %q", got)
	}
	if got := prefixOf(net.ParseIP("2001:470:4:559:1::1")); got != "2001:470:4:559::/64" {
		t.Errorf("link prefix = %q", got)
	}
	if got := prefixOf(net.ParseIP("2001:470:6:559::1")); got != "" {
		t.Errorf("unconfigured prefix must map to empty, got %q", got)
	}
	if got := prefixOf(nil); got != "" {
		t.Errorf("nil must map to empty, got %q", got)
	}
}

func TestGenIPStaysInsideAConfiguredPrefix(t *testing.T) {
	setPrefixes(t, "2001:470:5:559::/64", "2001:470:4:559::/64")
	for i := 0; i < 200; i++ {
		ip := genIP()
		if ip == nil {
			t.Fatal("genIP returned nil with prefixes configured")
		}
		if prefixOf(ip) == "" {
			t.Fatalf("generated %s outside every configured prefix", ip)
		}
	}
}

func TestGenIPSpreadsAcrossConfiguredPrefixes(t *testing.T) {
	prefixes := []string{
		"2001:470:dab9::/64",
		"2001:470:dab9:1::/64",
		"2001:470:dab9:2::/64",
		"2001:470:dab9:3::/64",
	}
	setPrefixes(t, prefixes...)
	oldPrefix := config.IPv6Prefix
	config.IPv6Prefix = prefixes[0]
	t.Cleanup(func() { config.IPv6Prefix = oldPrefix })
	resetPool()
	seen := map[string]int{}
	for i := 0; i < 12; i++ {
		ip := genIP()
		seen[prefixOf(ip)]++
		// Emulate the pool growing, the way addOnePoolIP would.
		poolLock.Lock()
		ipv6PoolIndex[ip.String()] = len(ipv6Pool)
		ipv6Pool = append(ipv6Pool, ip)
		poolLock.Unlock()
	}
	if len(seen) != len(prefixes) {
		t.Fatalf("pool must spread over every configured /64, got %v", seen)
	}
	for _, p := range prefixes {
		if seen[p] != 3 {
			t.Errorf("prefix %s got %d of 12, want 3", p, seen[p])
		}
	}
}

func TestSinglePrefixIsUnchanged(t *testing.T) {
	setPrefixes(t, "2001:470:5:559::/64")
	for i := 0; i < 50; i++ {
		if got := prefixOf(genIP()); got != "2001:470:5:559::/64" {
			t.Fatalf("single-prefix install must stay in that prefix, got %q", got)
		}
	}
}

func TestRetirePrefixRemovesOnlyThatBlock(t *testing.T) {
	setPrefixes(t, "2001:470:5:559::/64", "2001:470:4:559::/64")
	resetPool(
		"2001:470:5:559:1::1",
		"2001:470:5:559:2::2",
		"2001:470:4:559:1::1",
	)

	n := retirePrefix("2001:470:5:559::/64")
	if n != 2 {
		t.Fatalf("expected 2 addresses retired, got %d", n)
	}
	if len(ipv6Pool) != 1 {
		t.Fatalf("expected 1 address left, got %d", len(ipv6Pool))
	}
	if got := prefixOf(ipv6Pool[0]); got != "2001:470:4:559::/64" {
		t.Fatalf("the healthy block must survive, left %q", got)
	}
}

func TestRetirePrefixUnknownIsNoop(t *testing.T) {
	setPrefixes(t, "2001:470:5:559::/64")
	resetPool("2001:470:5:559:1::1")
	if n := retirePrefix("2001:470:9:9::/64"); n != 0 {
		t.Fatalf("unknown prefix must retire nothing, got %d", n)
	}
	if n := retirePrefix(""); n != 0 {
		t.Fatalf("empty prefix must retire nothing, got %d", n)
	}
	if len(ipv6Pool) != 1 {
		t.Fatal("pool must be untouched")
	}
}

func TestEffectivePrefixesFallsBackToSingle(t *testing.T) {
	oldCfg := config
	t.Cleanup(func() { config = oldCfg })

	config.IPv6Prefix = "2001:470:5:559::/64"
	config.IPv6Prefixes = nil
	if got := effectivePrefixes(); len(got) != 1 || got[0] != "2001:470:5:559::/64" {
		t.Fatalf("legacy single prefix must still work, got %v", got)
	}

	config.IPv6Prefixes = []string{"2001:470:5:559::/64", "2001:470:4:559::/64", "  "}
	if got := effectivePrefixes(); len(got) != 2 {
		t.Fatalf("list must win and blank entries drop, got %v", got)
	}

	config.IPv6Prefixes = []string{"not-a-cidr", "2001:470:4:559::/64"}
	if got := effectivePrefixes(); len(got) != 1 || got[0] != "2001:470:4:559::/64" {
		t.Fatalf("invalid entries must be dropped, got %v", got)
	}
}

func TestGenIPFallsBackWhenPrimaryCooling(t *testing.T) {
	setPrefixes(t, "2001:470:dab9::/64", "2001:470:dab9:1::/64")
	oldPrefix := config.IPv6Prefix
	config.IPv6Prefix = "2001:470:dab9::/64"
	t.Cleanup(func() {
		config.IPv6Prefix = oldPrefix
		cooldownLock.Lock()
		delete(prefixCooldown, "2001:470:dab9::/64")
		cooldownLock.Unlock()
	})
	cooldownLock.Lock()
	prefixCooldown["2001:470:dab9::/64"] = time.Now().Add(time.Hour)
	cooldownLock.Unlock()
	resetPool()
	if got := prefixOf(genIP()); got != "2001:470:dab9:1::/64" {
		t.Fatalf("cooling primary must fall back to another /64, got %q", got)
	}
}

func TestPickPrefixRecyclesWhenAllCooling(t *testing.T) {
	prefixes := []string{
		"2001:470:dab9::/64",
		"2001:470:dab9:1::/64",
	}
	setPrefixes(t, prefixes...)
	oldPrefix := config.IPv6Prefix
	config.IPv6Prefix = prefixes[0]
	t.Cleanup(func() {
		config.IPv6Prefix = oldPrefix
		cooldownLock.Lock()
		for _, p := range prefixes {
			delete(prefixCooldown, p)
		}
		cooldownLock.Unlock()
	})
	resetPool()
	cooldownLock.Lock()
	prefixCooldown[prefixes[0]] = time.Now().Add(time.Hour)
	prefixCooldown[prefixes[1]] = time.Now().Add(2 * time.Hour)
	cooldownLock.Unlock()
	if got := pickPrefix().String(); got != prefixes[1] {
		t.Fatalf("all-cooling fallback must recycle the longest-cooled prefix, got %s", got)
	}
	cooldownLock.RLock()
	_, still := prefixCooldown[prefixes[1]]
	cooldownLock.RUnlock()
	if still {
		t.Fatal("recycled prefix must have its cooldown cleared")
	}
}
