package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"io"
	"io/fs"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	Port            string       `json:"port"`
	WebPort         string       `json:"web_port"`
	WebUsername     string       `json:"web_username"`
	WebPassword     string       `json:"web_password"`
	Username        string       `json:"username"`
	Password        string       `json:"password"`
	IPv6Prefix      string       `json:"ipv6_prefix"`
	IPv6Prefixes    []string     `json:"ipv6_prefixes"`
	NextHopAddr     string       `json:"nexthop_addr"`
	Interface       string       `json:"interface"`
	InitialPool     int          `json:"initial_pool"`
	TargetPool      int          `json:"target_pool"`
	AutoRotate      bool         `json:"auto_rotate"`
	AutoRotateHours int          `json:"auto_rotate_hours"`
	AutoClean       bool         `json:"auto_clean"`
	AllowedTargets  []string     `json:"allowed_targets"`
	AllowToken      string       `json:"allow_token"`
	SignalToken     string       `json:"signal_token"`
	SignalCooldown  int          `json:"signal_cooldown_minutes"`
	Ports           []PortConfig `json:"ports"`
}
type PortConfig struct {
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
	Created  string `json:"created"`
}
type Stats struct {
	StartTime                                                                                                  time.Time
	TotalConns, ActiveConns, SuccessConns, FailedConns, TimeoutConns, PoolSize, TotalBytesRecv, TotalBytesSent int64
	SignalReports int64
}
type ConnLog struct{ Time, ClientIP, Target, IPv6, Status, Duration string }
type ActiveConn struct {
	ID, ClientIP, Target, IPv6, Duration string
	StartTime                            time.Time
}

var config Config
var stats Stats
var ipv6Pool []net.IP
var ipv6PoolIndex map[string]int
var poolLock sync.RWMutex
var logs []*ConnLog
var logsLock sync.RWMutex
var failLogs []*ConnLog
var failLogsLock sync.RWMutex
var active = map[string]*ActiveConn{}
var activeLock sync.RWMutex
var iface netlink.Link
// Every routable prefix we may bind from. Quota is bucketed per network block,
// not per /128, so multiple prefixes are multiple buckets — the only rotation
// that can actually escape a drained block. One prefix is the old behaviour.
var prefixPools []*net.IPNet
var discardQueue chan net.IP
var rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))
var rngLock sync.Mutex

// A 429 is reported by the client that saw it, not by the proxy: CONNECT only
// carries encrypted bytes. These maps tie a proxy username to one exit address
// and keep drained buckets out of the refill path long enough to matter.
var laneLock sync.RWMutex
var clientLanes = map[string]net.IP{}
var cooldownLock sync.RWMutex
var prefixCooldown = map[string]time.Time{}

//go:embed web
var webFS embed.FS

const appVersion = "7.6"

var configFilePath string

func readLine(prompt, def string) string {
	r := bufio.NewReader(os.Stdin)
	if def == "" {
		fmt.Printf("%s: ", prompt)
	} else {
		fmt.Printf("%s (default %s): ", prompt, def)
	}
	s, _ := r.ReadString('\n')
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}
func readInt(prompt string, def int) int {
	for {
		n, err := strconv.Atoi(readLine(prompt, strconv.Itoa(def)))
		if err == nil && n >= 0 {
			return n
		}
	}
}
func readChoice(max int) int {
	for {
		n, err := strconv.Atoi(readLine(fmt.Sprintf("Choose (1-%d)", max), ""))
		if err == nil && n >= 1 && n <= max {
			return n
		}
	}
}
func saveConfig() error {
	b, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFilePath, b, 0600)
}
func loadConfig() error {
	b, err := os.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &config)
}

func selectInterface() (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var arr []netlink.Link
	for _, l := range links {
		if l.Attrs().Flags&net.FlagUp != 0 && l.Attrs().Flags&net.FlagLoopback == 0 {
			arr = append(arr, l)
		}
	}
	if len(arr) == 0 {
		return nil, errors.New("no usable network interface")
	}
	log.Println("Available interfaces:")
	for i, l := range arr {
		log.Printf("  %d: %s", i+1, l.Attrs().Name)
	}
	return arr[readChoice(len(arr))-1], nil
}
func selectPrefix(link netlink.Link) (string, error) {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return "", err
	}
	set := map[string]bool{}
	for _, a := range addrs {
		if a.IPNet != nil && a.IP.IsGlobalUnicast() {
			ones, bits := a.IPNet.Mask.Size()
			if bits == 128 && ones <= 64 {
				m := a.IP.Mask(net.CIDRMask(ones, 128))
				set[fmt.Sprintf("%s/%d", m.String(), ones)] = true
			}
		}
	}
	if len(set) == 0 {
		return readLine("Enter IPv6 prefix, e.g. 2605:6400:408c::/48", ""), nil
	}
	var arr []string
	for p := range set {
		arr = append(arr, p)
	}
	sort.Strings(arr)
	log.Println("Detected IPv6 prefixes:")
	for i, p := range arr {
		log.Printf("  %d: %s", i+1, p)
	}
	return arr[readChoice(len(arr))-1], nil
}
func firstSetup() error {
	config.WebUsername = readLine("Web username", "admin")
	config.WebPassword = readLine("Web password", "admin123")
	config.Port = readLine("Proxy port", "1080")
	config.WebPort = readLine("Web port", "8080")
	config.Username = readLine("Proxy username", "proxy")
	config.Password = readLine("Proxy password", "proxy")
	l, err := selectInterface()
	if err != nil {
		return err
	}
	config.Interface = l.Attrs().Name
	p, err := selectPrefix(l)
	if err != nil {
		return err
	}
	config.IPv6Prefix = p
	config.NextHopAddr = readLine("Next-hop address, leave empty if none", "")
	config.InitialPool = readInt("Initial IP count", 1)
	config.TargetPool = readInt("Target IP count", 1)
	if config.TargetPool < config.InitialPool {
		config.TargetPool = config.InitialPool
	}
	config.AutoRotate = strings.ToLower(readLine("Enable auto rotation? (y/n)", "n")) == "y"
	if config.AutoRotate {
		config.AutoRotateHours = readInt("Rotation interval (hours)", 6)
	}
	config.AutoClean = strings.ToLower(readLine("Enable automatic cleanup of failed IPs? (y/n)", "y")) == "y"
	return saveConfig()
}
// effectivePrefixes is the configured set of egress prefixes, with the legacy
// single ipv6_prefix honoured as a one-element list so old configs keep
// working untouched.
func effectivePrefixes() []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, _, err := net.ParseCIDR(v); err != nil {
			log.Printf("Ignoring invalid prefix %q: %v", v, err)
			return
		}
		if seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, p := range config.IPv6Prefixes {
		add(p)
	}
	if len(out) == 0 {
		add(config.IPv6Prefix)
	}
	return out
}

// prefixOf reports which configured prefix an address belongs to, or "" if it
// belongs to none of them.
func prefixOf(ip net.IP) string {
	if ip == nil {
		return ""
	}
	for _, p := range prefixPools {
		if p.Contains(ip) {
			return p.String()
		}
	}
	return ""
}

// prefixCounts reports how many pool addresses sit in each prefix.
func prefixCounts() map[string]int {
	counts := map[string]int{}
	poolLock.RLock()
	defer poolLock.RUnlock()
	for _, ip := range ipv6Pool {
		if p := prefixOf(ip); p != "" {
			counts[p]++
		}
	}
	return counts
}

// pickPrefix chooses the least-populated prefix so the pool spreads across
// buckets instead of piling into the first. A single bucket is worthless for
// rotation, because a drained block cannot be escaped from inside itself.
func pickPrefix() *net.IPNet {
	if len(prefixPools) == 0 {
		return nil
	}
	if len(prefixPools) == 1 {
		return prefixPools[0]
	}
	counts := prefixCounts()
	best := -1
	bestN := -1
	now := time.Now()
	cooldownLock.RLock()
	for i, p := range prefixPools {
		if until, cooled := prefixCooldown[p.String()]; cooled && now.Before(until) {
			continue
		}
		n := counts[p.String()]
		if best < 0 || n < bestN {
			best, bestN = i, n
		}
	}
	cooldownLock.RUnlock()
	// A pool still has to refill when every bucket is cooling.
	if best < 0 {
		for i := range prefixPools {
			best = i
			break
		}
	}
	return prefixPools[best]
}

// genIP mints a random /128 inside a chosen prefix.
func genIP() net.IP {
	p := pickPrefix()
	if p == nil {
		return nil
	}
	ip := make(net.IP, 16)
	copy(ip, p.IP.To16())
	ones, _ := p.Mask.Size()
	b := ones / 8
	if b < 16 {
		_, _ = rand.Read(ip[b:])
	}
	if ones%8 != 0 && b < 16 {
		mask := byte(0xff << (8 - ones%8))
		ip[b] = (p.IP[b] & mask) | (ip[b] &^ mask)
	}
	return ip
}
func addIP(ip net.IP) error {
	return netlink.AddrAdd(iface, &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, Flags: syscall.IFA_F_NODAD})
}
func delIP(ip net.IP) {
	_ = netlink.AddrDel(iface, &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}})
}
func cleanupStale() {
	addrs, err := netlink.AddrList(iface, netlink.FAMILY_V6)
	if err != nil {
		log.Printf("Failed to clean up old IPv6 on startup: %v", err)
		return
	}
	var nh net.IP
	if config.NextHopAddr != "" {
		nh = net.ParseIP(config.NextHopAddr)
	}
	n := 0
	for _, a := range addrs {
		if a.IPNet == nil || a.IP == nil {
			continue
		}
		ones, bits := a.IPNet.Mask.Size()
		if bits != 128 || ones != 128 || prefixOf(a.IP) == "" {
			continue
		}
		if nh != nil && a.IP.Equal(nh) {
			continue
		}
		if netlink.AddrDel(iface, &a) == nil {
			n++
		}
	}
	log.Printf("Startup cleanup of old IPv6: %d removed", n)
}
func initPool() error {
	log.Printf("Initializing IP pool: %d", config.InitialPool)
	ipv6Pool = []net.IP{}
	ipv6PoolIndex = map[string]int{}
	if config.InitialPool < 1 {
		atomic.StoreInt64(&stats.PoolSize, 0)
		log.Printf("Initial IP count is 0, waiting for additions from the web panel")
		return nil
	}
	for i := 0; i < config.InitialPool; i++ {
		ip := genIP()
		if addIP(ip) == nil {
			ipv6PoolIndex[ip.String()] = len(ipv6Pool)
			ipv6Pool = append(ipv6Pool, ip)
		}
		if (i+1)%100 == 0 || i+1 == config.InitialPool {
			fmt.Printf("\rProgress: %d/%d", i+1, config.InitialPool)
		}
	}
	fmt.Println()
	atomic.StoreInt64(&stats.PoolSize, int64(len(ipv6Pool)))
	if len(ipv6Pool) == 0 {
		return errors.New("failed to add any IPv6 address")
	}
	return nil
}
func addOnePoolIP() bool {
	ip := genIP()
	if addIP(ip) != nil {
		return false
	}
	poolLock.Lock()
	ipv6PoolIndex[ip.String()] = len(ipv6Pool)
	ipv6Pool = append(ipv6Pool, ip)
	n := len(ipv6Pool)
	poolLock.Unlock()
	atomic.StoreInt64(&stats.PoolSize, int64(n))
	return true
}
func addPoolIPs(count int) int {
	if count < 1 {
		return 0
	}
	ok := 0
	for i := 0; i < count; i++ {
		if addOnePoolIP() {
			ok++
		}
	}
	if ok > 0 {
		config.TargetPool += ok
		config.InitialPool = config.TargetPool
		_ = saveConfig()
	}
	return ok
}
func setPoolTarget(count int) int {
	if count < 1 {
		count = 1
	}
	config.TargetPool = count
	config.InitialPool = count
	poolLock.Lock()
	remove := []net.IP{}
	if len(ipv6Pool) > count {
		remove = append(remove, ipv6Pool[count:]...)
		ipv6Pool = ipv6Pool[:count]
	}
	ipv6PoolIndex = map[string]int{}
	for i, ip := range ipv6Pool {
		ipv6PoolIndex[ip.String()] = i
	}
	n := len(ipv6Pool)
	poolLock.Unlock()
	for _, ip := range remove {
		delIP(ip)
	}
	atomic.StoreInt64(&stats.PoolSize, int64(n))
	_ = saveConfig()
	for i := 0; i < 50 && int(atomic.LoadInt64(&stats.PoolSize)) < config.TargetPool; i++ {
		addOnePoolIP()
	}
	return int(atomic.LoadInt64(&stats.PoolSize))
}
func clearAllIPv6() int {
	config.TargetPool = 0
	config.InitialPool = 0
	_ = saveConfig()
	poolLock.Lock()
	poolIPs := append([]net.IP(nil), ipv6Pool...)
	ipv6Pool = []net.IP{}
	ipv6PoolIndex = map[string]int{}
	poolLock.Unlock()
	deleted := 0
	seen := map[string]bool{}
	for _, ip := range poolIPs {
		delIP(ip)
		seen[ip.String()] = true
		deleted++
	}
	addrs, err := netlink.AddrList(iface, netlink.FAMILY_V6)
	if err == nil {
		var nh net.IP
		if config.NextHopAddr != "" {
			nh = net.ParseIP(config.NextHopAddr)
		}
		for _, a := range addrs {
			if a.IPNet == nil || a.IP == nil {
				continue
			}
			ones, bits := a.IPNet.Mask.Size()
			if bits != 128 || ones != 128 || prefixOf(a.IP) == "" {
				continue
			}
			if nh != nil && a.IP.Equal(nh) {
				continue
			}
			if seen[a.IP.String()] {
				continue
			}
			if netlink.AddrDel(iface, &a) == nil {
				deleted++
			}
		}
	}
	atomic.StoreInt64(&stats.PoolSize, 0)
	return deleted
}
func backgroundFill(ctx context.Context) {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for i := 0; i < 50 && int(atomic.LoadInt64(&stats.PoolSize)) < config.TargetPool; i++ {
				addOnePoolIP()
			}
		}
	}
}
// retirePrefix removes every pool address inside one prefix.
//
// A quota bucket is a network block, not an address: measured on 2026-11-18,
// every /128 in 2001:470:5:559::/64 answered 429 for a model while
// 2001:470:4:559::/64 answered 200 in the same minute. Retiring single
// addresses from the drained block therefore achieves nothing — the refill
// draws from the same block. Retiring the block, with nextPrefixIP filling
// from the other one, is what actually moves traffic.
func retirePrefix(prefix string) int {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return 0
	}
	poolLock.RLock()
	victims := []net.IP{}
	for _, ip := range ipv6Pool {
		if prefixOf(ip) == prefix {
			victims = append(victims, append(net.IP(nil), ip...))
		}
	}
	poolLock.RUnlock()
	n := 0
	for _, ip := range victims {
		if removePoolIP(ip) {
			n++
		}
	}
	return n
}

func rotatePool() {
	want := config.TargetPool
	if want < 1 {
		want = config.InitialPool
	}
	if want < 1 {
		log.Printf("Rotation skipped: target IP count is 0")
		return
	}
	log.Printf("Starting IPv6 pool rotation, generating %d new addresses", want)
	newIPs := []net.IP{}
	newIndex := map[string]int{}
	for i := 0; i < want; i++ {
		ip := genIP()
		if addIP(ip) == nil {
			newIndex[ip.String()] = len(newIPs)
			newIPs = append(newIPs, ip)
		}
	}
	if len(newIPs) == 0 {
		log.Printf("Rotation failed: could not add new addresses")
		return
	}
	poolLock.Lock()
	old := ipv6Pool
	ipv6Pool = newIPs
	ipv6PoolIndex = newIndex
	poolLock.Unlock()
	atomic.StoreInt64(&stats.PoolSize, int64(len(newIPs)))
	log.Printf("Rotation complete: %d new IPs, old IPs will be cleaned up in 30 minutes", len(newIPs))
	go func(ips []net.IP) {
		time.Sleep(30 * time.Minute)
		for _, ip := range ips {
			delIP(ip)
		}
	}(old)
}
func autoRotate(ctx context.Context) {
	if !config.AutoRotate {
		return
	}
	hours := config.AutoRotateHours
	if hours < 1 {
		hours = 6
	}
	t := time.NewTicker(time.Duration(hours) * time.Hour)
	defer t.Stop()
	log.Printf("Auto rotation enabled, rotating every %d hours", hours)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rotatePool()
		}
	}
}
func getIP() net.IP {
	poolLock.RLock()
	defer poolLock.RUnlock()
	if len(ipv6Pool) == 0 {
		return nil
	}
	rngLock.Lock()
	i := rng.Intn(len(ipv6Pool))
	rngLock.Unlock()
	return append(net.IP(nil), ipv6Pool[i]...)
}
func cooledPrefix(prefix string) bool {
	if prefix == "" {
		return false
	}
	cooldownLock.RLock()
	defer cooldownLock.RUnlock()
	until, ok := prefixCooldown[prefix]
	return ok && time.Now().Before(until)
}
func coolPrefix(prefix string) {
	if prefix == "" || len(prefixPools) < 2 {
		return
	}
	minutes := config.SignalCooldown
	if minutes < 1 {
		minutes = 15
	}
	cooldownLock.Lock()
	prefixCooldown[prefix] = time.Now().Add(time.Duration(minutes) * time.Minute)
	cooldownLock.Unlock()
}

// laneIP pins one client to one exit until a 429 signal condemns it. That makes
// the offending address known: a fresh TLS connection from the same client
// cannot silently land on a different address and hide the verdict.
func laneIP(clientID string) net.IP {
	if clientID == "" {
		return getIP()
	}
	laneLock.RLock()
	ip, ok := clientLanes[clientID]
	laneLock.RUnlock()
	if ok {
		poolLock.RLock()
		_, still := ipv6PoolIndex[ip.String()]
		poolLock.RUnlock()
		if still && !cooledPrefix(prefixOf(ip)) {
			return append(net.IP(nil), ip...)
		}
	}
	poolLock.RLock()
	candidates := make([]net.IP, 0, len(ipv6Pool))
	for _, x := range ipv6Pool {
		if p := prefixOf(x); p == "" || !cooledPrefix(p) {
			candidates = append(candidates, x)
		}
	}
	poolLock.RUnlock()
	if len(candidates) == 0 {
		ip = getIP()
	} else {
		rngLock.Lock()
		i := rng.Intn(len(candidates))
		rngLock.Unlock()
		ip = append(net.IP(nil), candidates[i]...)
	}
	if ip != nil {
		laneLock.Lock()
		clientLanes[clientID] = ip
		laneLock.Unlock()
	}
	return ip
}
func removePoolIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	key := ip.String()
	poolLock.Lock()
	idx, ok := ipv6PoolIndex[key]
	if ok {
		last := len(ipv6Pool) - 1
		if idx >= 0 && idx <= last {
			if idx != last {
				ipv6Pool[idx] = ipv6Pool[last]
				ipv6PoolIndex[ipv6Pool[idx].String()] = idx
			}
			ipv6Pool = ipv6Pool[:last]
		}
		delete(ipv6PoolIndex, key)
	}
	n := len(ipv6Pool)
	poolLock.Unlock()
	if ok {
		atomic.StoreInt64(&stats.PoolSize, int64(n))
		delIP(ip)
	}
	return ok
}

type DialTarget struct {
	Network, Address string
	UseIPv6          bool
}

func resolveTargets(ctx context.Context, host string, port uint16) ([]DialTarget, error) {
	ps := strconv.Itoa(int(port))
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return []DialTarget{{"tcp4", net.JoinHostPort(ip.String(), ps), false}}, nil
		}
		return []DialTarget{{"tcp6", net.JoinHostPort(ip.String(), ps), true}}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	v6 := []DialTarget{}
	v4 := []DialTarget{}
	for _, a := range addrs {
		if a.IP == nil {
			continue
		}
		addr := net.JoinHostPort(a.IP.String(), ps)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		if a.IP.To4() == nil {
			v6 = append(v6, DialTarget{"tcp6", addr, true})
		} else {
			v4 = append(v4, DialTarget{"tcp4", addr, false})
		}
	}
	if len(v6) > 0 {
		return v6, nil
	}
	if len(v4) > 0 {
		return v4, nil
	}
	return nil, fmt.Errorf("target %s has no available IP record", host)
}
func addLog(c, t, ip, st string, d time.Duration) {
	x := &ConnLog{time.Now().Format("15:04:05"), c, t, ip, st, fmt.Sprintf("%.2fs", d.Seconds())}
	logsLock.Lock()
	logs = append(logs, x)
	if len(logs) > 10 {
		logs = logs[len(logs)-10:]
	}
	logsLock.Unlock()
	if !strings.Contains(st, "success") {
		failLogsLock.Lock()
		failLogs = append(failLogs, x)
		if len(failLogs) > 10 {
			failLogs = failLogs[len(failLogs)-10:]
		}
		failLogsLock.Unlock()
	}
}
func auth(port, u, p string) bool {
	eu, ep := config.Username, config.Password
	if port != config.Port {
		ok := false
		for _, x := range config.Ports {
			if x.Port == port && x.Enabled {
				eu = x.Username
				ep = x.Password
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return subtle.ConstantTimeCompare([]byte(u), []byte(eu)) == 1 && subtle.ConstantTimeCompare([]byte(p), []byte(ep)) == 1
}
func copyConn(dst, src net.Conn, deadline time.Time, counter *int64, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 65536)
	for {
		src.SetReadDeadline(deadline)
		dst.SetWriteDeadline(deadline)
		n, er := src.Read(buf)
		if n > 0 {
			atomic.AddInt64(counter, int64(n))
			if _, ew := dst.Write(buf[:n]); ew != nil {
				return
			}
		}
		if er != nil {
			return
		}
	}
}
// ---- target allowlist ------------------------------------------------------
// Ported from the HE gateway's install.sh. A proxy on a public port is an open
// relay unless it says what it will connect to, so this is not optional: an
// empty list means OPEN, which the startup log states in those words.
//
//   "*"          any target
//   "*.suffix"   the apex and any subdomain
//   "re:..."     a regexp against the origin
//   otherwise    an exact origin, e.g. https://opencode.ai
//
// An exact-origin hit needs no token. A wildcard or regexp hit always does, and
// fails closed when no token is configured — a wildcard without a token would
// be the same as "*".

const defaultAllowedTargets = "https://opencode.ai,https://api.kilo.ai,https://oai.endpoints.kepler.ai.cloud.ovh.net,https://cloudflare.com"

var allowEntries []string
var allowToken string

func parseAllowList(in []string) []string {
	out := []string{}
	for _, raw := range in {
		for _, e := range strings.Split(raw, ",") {
			e = strings.TrimSpace(e)
			e = strings.TrimSuffix(e, "/")
			if e != "" {
				out = append(out, e)
			}
		}
	}
	return out
}

func initAllow() {
	allowEntries = parseAllowList(config.AllowedTargets)
	allowToken = config.AllowToken
}

// targetOrigin derives the URL origin of a proxy target. CONNECT carries no
// scheme, so 443 is https, 80 is http, and anything else is https with an
// explicit port. A non-HTTP port therefore matches no exact origin and fails
// closed, which is the intent.
func targetOrigin(host string, port uint16) string {
	scheme := "https"
	if port == 80 {
		scheme = "http"
	}
	h := strings.Trim(host, "[]")
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	if port == 443 || port == 80 {
		return scheme + "://" + h
	}
	return scheme + "://" + h + ":" + strconv.Itoa(int(port))
}

func matchTarget(origin, hostname string) (matched, exact bool) {
	for _, entry := range allowEntries {
		switch {
		case entry == "*":
			matched = true
		case strings.HasPrefix(entry, "*."):
			suffix := strings.ToLower(strings.TrimPrefix(entry, "*."))
			if suffix != "" && (hostname == suffix || strings.HasSuffix(hostname, "."+suffix)) {
				matched = true
			}
		case strings.HasPrefix(entry, "re:"):
			re, err := regexp.Compile(entry[3:])
			if err != nil {
				continue
			}
			if re.MatchString(origin) {
				matched = true
			}
		default:
			if u, err := url.Parse(entry); err == nil && u.Scheme != "" {
				if u.Scheme+"://"+u.Host == origin {
					matched = true
					exact = true
				}
			} else if entry == origin || entry == hostname {
				matched = true
				exact = true
			}
		}
	}
	if !matched {
		return false, false
	}
	return true, exact
}

func isAuthorized(exact bool, token string) bool {
	if exact {
		return true
	}
	if allowToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(allowToken)) == 1
}

func allowTarget(host string, port uint16, token string) bool {
	if len(allowEntries) == 0 {
		return true
	}
	origin := targetOrigin(host, port)
	hostname := strings.ToLower(strings.Trim(host, "[]"))
	matched, exact := matchTarget(origin, hostname)
	return matched && isAuthorized(exact, token)
}

// denyTarget answers a blocked CONNECT in the dialect the client spoke.
func denyTarget(client net.Conn, isSocks bool) {
	if isSocks {
		client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
	} else {
		client.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	}
}

func proxy(client net.Conn, host string, port uint16, isSocks bool, clientID string) {
	start := time.Now()
	cip := client.RemoteAddr().String()
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	// Checked here rather than in each caller so SOCKS and CONNECT cannot
	// drift apart: one place decides, both dialects obey.
	if !allowTarget(host, port, "") {
		addLog(cip, target, "none", "blocked: not in allowlist", time.Since(start))
		log.Printf("BLOCKED target not in allowlist: %s", target)
		denyTarget(client, isSocks)
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	id := fmt.Sprintf("%s-%d", cip, time.Now().UnixNano())
	activeLock.Lock()
	active[id] = &ActiveConn{ID: id, ClientIP: cip, Target: target, IPv6: "dialing", StartTime: start}
	activeLock.Unlock()
	defer func() { activeLock.Lock(); delete(active, id); activeLock.Unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	targets, err := resolveTargets(ctx, host, port)
	if err != nil {
		st := "failed: " + err.Error()
		if len(st) > 80 {
			st = st[:80]
		}
		addLog(cip, target, "none", st, time.Since(start))
		if isSocks {
			client.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	maxAttempts := len(targets)
	if maxAttempts < 3 {
		maxAttempts = 3
	}
	if maxAttempts > 6 {
		maxAttempts = 6
	}
	var remote net.Conn
	var lastErr error
	lastIP := "none"
	for attempt := 0; attempt < maxAttempts; attempt++ {
		dt := targets[attempt%len(targets)]
		d := net.Dialer{Timeout: 15 * time.Second}
		logIP := "IPv4"
		var ip net.IP
		if dt.UseIPv6 {
			ip = laneIP(clientID)
			if ip == nil {
				lastErr = errors.New("no available IP")
				break
			}
			d.LocalAddr = &net.TCPAddr{IP: ip}
			logIP = ip.String()
		}
		lastIP = logIP
		activeLock.Lock()
		if ac := active[id]; ac != nil {
			ac.IPv6 = logIP
		}
		activeLock.Unlock()
		remote, err = d.DialContext(ctx, dt.Network, dt.Address)
		if err == nil {
			break
		}
		lastErr = err
		if dt.UseIPv6 && config.AutoClean {
			removePoolIP(ip)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if remote == nil {
		st := "failed: " + lastErr.Error()
		if len(st) > 80 {
			st = st[:80]
		}
		addLog(cip, target, lastIP, st, time.Since(start))
		if isSocks {
			client.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	defer remote.Close()
	atomic.AddInt64(&stats.SuccessConns, 1)
	addLog(cip, target, lastIP, "success", time.Since(start))
	if isSocks {
		client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	} else {
		client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}
	deadline := start.Add(1000 * time.Second)
	var wg sync.WaitGroup
	wg.Add(2)
	go copyConn(remote, client, deadline, &stats.TotalBytesSent, &wg)
	go copyConn(client, remote, deadline, &stats.TotalBytesRecv, &wg)
	wg.Wait()
}
func handleSocks(c net.Conn, first byte, listenPort string) {
	defer c.Close()
	defer atomic.AddInt64(&stats.ActiveConns, -1)
	b := make([]byte, 512)
	b[0] = first
	if _, e := io.ReadFull(c, b[1:2]); e != nil {
		return
	}
	n := int(b[1])
	if _, e := io.ReadFull(c, b[:n]); e != nil {
		return
	}
	has := false
	for i := 0; i < n; i++ {
		if b[i] == 2 {
			has = true
		}
	}
	if !has {
		c.Write([]byte{5, 255})
		return
	}
	c.Write([]byte{5, 2})
	if _, e := io.ReadFull(c, b[:2]); e != nil {
		return
	}
	ulen := int(b[1])
	if _, e := io.ReadFull(c, b[:ulen]); e != nil {
		return
	}
	u := string(b[:ulen])
	if _, e := io.ReadFull(c, b[:1]); e != nil {
		return
	}
	plen := int(b[0])
	if _, e := io.ReadFull(c, b[:plen]); e != nil {
		return
	}
	p := string(b[:plen])
	if !auth(listenPort, u, p) {
		c.Write([]byte{1, 1})
		return
	}
	c.Write([]byte{1, 0})
	if _, e := io.ReadFull(c, b[:4]); e != nil {
		return
	}
	var host string
	var port uint16
	switch b[3] {
	case 1:
		if _, e := io.ReadFull(c, b[:6]); e != nil {
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
		port = binary.BigEndian.Uint16(b[4:6])
	case 3:
		if _, e := io.ReadFull(c, b[:1]); e != nil {
			return
		}
		l := int(b[0])
		if _, e := io.ReadFull(c, b[:l+2]); e != nil {
			return
		}
		host = string(b[:l])
		port = binary.BigEndian.Uint16(b[l : l+2])
	case 4:
		if _, e := io.ReadFull(c, b[:18]); e != nil {
			return
		}
		host = net.IP(b[:16]).String()
		port = binary.BigEndian.Uint16(b[16:18])
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	proxy(c, host, port, true, u)
}
// handleSignal is the out-of-band 429 channel. zen-proxy is the only process
// that can read a 429 inside the CONNECT tunnel, so it POSTs the verdict here
// with a bearer token. No log scraping, no polling, no guessing which client.
func handleSignal(c net.Conn, raw []byte) {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	deny := func(code int) {
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n", code, http.StatusText(code))
	}
	if config.SignalToken == "" {
		deny(404)
		return
	}
	r, err := http.ReadRequest(bufio.NewReader(io.MultiReader(bytes.NewReader(raw), c)))
	if err != nil || r.Method != "POST" || r.URL.Path != "/__signal" {
		deny(400)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if subtle.ConstantTimeCompare([]byte(token), []byte(config.SignalToken)) != 1 {
		c.Write([]byte("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\nConnection: close\r\n\r\n"))
		return
	}
	var report struct {
		ClientID   string  `json:"clientId"`
		Status     int     `json:"status"`
		Model      string  `json:"model"`
		RetryAfter float64 `json:"retryAfter"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&report) != nil {
		deny(400)
		return
	}
	if report.Status != 429 {
		c.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
		return
	}
	clientID := strings.TrimSpace(report.ClientID)
	if clientID == "" || len(clientID) > 64 || strings.ContainsAny(clientID, " \t\r\n:") {
		deny(400)
		return
	}
	atomic.AddInt64(&stats.SignalReports, 1)
	laneLock.RLock()
	victim, known := clientLanes[clientID]
	laneLock.RUnlock()
	rotated := ""
	if known && victim != nil {
		prefix := prefixOf(victim)
		if prefix != "" && len(prefixPools) > 1 {
			// Quota is keyed on the /64 bucket, not the individual /128: every
			// address in a drained block gets 429. Retire the whole block and
			// keep the refiller out of it for a while.
			n := retirePrefix(prefix)
			coolPrefix(prefix)
			rotated = prefix
			log.Printf("429 signal from %s (%s): retired prefix %s (%d IPs)", clientID, report.Model, prefix, n)
		} else {
			removePoolIP(victim)
			rotated = victim.String()
			log.Printf("429 signal from %s (%s): retired IP %s", clientID, report.Model, victim)
		}
		laneLock.Lock()
		delete(clientLanes, clientID)
		laneLock.Unlock()
		laneIP(clientID)
	} else {
		log.Printf("429 signal from %s (%s): no lane to retire", clientID, report.Model)
	}
	fmt.Fprintf(c, "HTTP/1.1 204 No Content\r\nX-Rotated: %s\r\nConnection: close\r\n\r\n", rotated)
}
func handleHTTP(c net.Conn, first byte, listenPort string) {
	defer c.Close()
	defer atomic.AddInt64(&stats.ActiveConns, -1)
	b := make([]byte, 8192)
	b[0] = first
	n, e := c.Read(b[1:])
	if e != nil {
		return
	}
	lines := strings.Split(string(b[:n+1]), "\r\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return
	}
	if parts[0] == "POST" && parts[1] == "/__signal" {
		handleSignal(c, b[:n+1])
		return
	}
	if len(parts) < 3 {
		return
	}
	proxyUser := ""
	ok := false
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "proxy-authorization: basic ") {
			dec, e := base64.StdEncoding.DecodeString(strings.TrimSpace(line[27:]))
			if e == nil {
				kv := strings.SplitN(string(dec), ":", 2)
				if len(kv) == 2 && auth(listenPort, kv[0], kv[1]) {
					ok = true
					proxyUser = kv[0]
				}
			}
		}
	}
	if !ok {
		c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
		return
	}
	if parts[0] != "CONNECT" {
		c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	h, ps, e := net.SplitHostPort(parts[1])
	if e != nil && strings.Count(parts[1], ":") == 1 {
		sp := strings.SplitN(parts[1], ":", 2)
		h = sp[0]
		ps = sp[1]
	}
	pn, e := strconv.Atoi(ps)
	if e != nil || pn < 1 || pn > 65535 {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	proxy(c, h, uint16(pn), false, proxyUser)
}
func handleConn(c net.Conn, port string) {
	atomic.AddInt64(&stats.ActiveConns, 1)
	atomic.AddInt64(&stats.TotalConns, 1)
	one := []byte{0}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, e := c.Read(one)
	c.SetReadDeadline(time.Time{})
	if e != nil || n != 1 {
		c.Close()
		atomic.AddInt64(&stats.ActiveConns, -1)
		return
	}
	if one[0] == 5 {
		handleSocks(c, one[0], port)
	} else {
		handleHTTP(c, one[0], port)
	}
}
func listen(ctx context.Context, port string, wg *sync.WaitGroup) (net.Listener, error) {
	l, e := net.Listen("tcp", ":"+port)
	if e != nil {
		return nil, e
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		go func() { <-ctx.Done(); l.Close() }()
		for {
			c, e := l.Accept()
			if e != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go handleConn(c, port)
		}
	}()
	log.Printf("Proxy port %s is listening, supports HTTP and SOCKS5", port)
	return l, nil
}
func discard(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-discardQueue:
			removePoolIP(ip)
		}
	}
}
func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "index.html not found", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}

// serveAsset serves a single embedded brand asset (favicons etc.) without auth.
func serveAsset(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := webFS.ReadFile("web/assets/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
	}
}
func webAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != config.WebUsername || p != config.WebPassword {
			w.Header().Set("WWW-Authenticate", "Basic")
			w.WriteHeader(401)
			return
		}
		next(w, r)
	}
}
func js(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func startWeb(ctx context.Context) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", webAuth(index))
	assets, _ := fs.Sub(webFS, "web/assets")
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	mux.HandleFunc("/favicon.svg", serveAsset("favicon.svg"))
	mux.HandleFunc("/favicon.ico", serveAsset("favicon.ico"))
	mux.HandleFunc("/api/info", webAuth(func(w http.ResponseWriter, r *http.Request) {
		extra := 0
		for _, p := range config.Ports {
			if p.Enabled && p.Port != "" && p.Port != config.Port {
				extra++
			}
		}
		js(w, map[string]interface{}{"version": appVersion, "prefix": config.IPv6Prefix, "interface": config.Interface, "proxy_port": config.Port, "web_port": config.WebPort, "extra_ports": extra, "auto_rotate": config.AutoRotate, "rotate_hours": config.AutoRotateHours, "auto_clean": config.AutoClean})
	}))
	mux.HandleFunc("/api/stats", webAuth(func(w http.ResponseWriter, r *http.Request) {
		up := time.Since(stats.StartTime)
		js(w, map[string]interface{}{"active": atomic.LoadInt64(&stats.ActiveConns), "total": atomic.LoadInt64(&stats.TotalConns), "success": atomic.LoadInt64(&stats.SuccessConns), "failed": atomic.LoadInt64(&stats.FailedConns), "signals": atomic.LoadInt64(&stats.SignalReports), "pool": atomic.LoadInt64(&stats.PoolSize), "target": config.TargetPool, "buckets": prefixCounts(), "bytes_recv": atomic.LoadInt64(&stats.TotalBytesRecv), "bytes_sent": atomic.LoadInt64(&stats.TotalBytesSent), "auto_rotate": config.AutoRotate, "rotate_interval": config.AutoRotateHours, "uptime": fmt.Sprintf("%dd %dh %dm", int(up.Hours())/24, int(up.Hours())%24, int(up.Minutes())%60)})
	}))
	mux.HandleFunc("/api/rotate", webAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		go rotatePool()
		js(w, map[string]string{"message": "Rotation started"})
	}))
	mux.HandleFunc("/api/add_ips", webAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var q struct {
			Count int `json:"count"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Count < 1 {
			q.Count = 1
		}
		added := addPoolIPs(q.Count)
		js(w, map[string]interface{}{"message": "Add complete", "added": added, "pool": atomic.LoadInt64(&stats.PoolSize), "target": config.TargetPool})
	}))
	mux.HandleFunc("/api/pool", webAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var q struct {
			Count int `json:"count"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Count < 1 {
			http.Error(w, "count must be greater than 0", 400)
			return
		}
		pool := setPoolTarget(q.Count)
		js(w, map[string]interface{}{"message": "Count updated", "pool": pool, "target": config.TargetPool})
	}))
	mux.HandleFunc("/api/clear_ips", webAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		deleted := clearAllIPv6()
		js(w, map[string]interface{}{"message": "All IPv6 addresses deleted", "deleted": deleted, "pool": atomic.LoadInt64(&stats.PoolSize), "target": config.TargetPool})
	}))
	mux.HandleFunc("/api/retire", webAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var q struct {
			Prefix  string `json:"prefix"`
			Address string `json:"address"`
		}
		if e := json.NewDecoder(r.Body).Decode(&q); e != nil {
			http.Error(w, "invalid JSON body", 400)
			return
		}
		if strings.TrimSpace(q.Prefix) != "" {
			n := retirePrefix(q.Prefix)
			if n > 0 {
				log.Printf("Prefix retire: %s drained, %d addresses removed", q.Prefix, n)
			}
			js(w, map[string]interface{}{"prefix": q.Prefix, "removed": n, "pool": atomic.LoadInt64(&stats.PoolSize), "target": config.TargetPool, "buckets": prefixCounts()})
			return
		}
		ip := net.ParseIP(strings.TrimSpace(q.Address))
		ok := removePoolIP(ip)
		if ok {
			log.Printf("Lane retire: %s removed from the pool", q.Address)
		}
		js(w, map[string]interface{}{"address": q.Address, "retired": ok, "pool": atomic.LoadInt64(&stats.PoolSize), "target": config.TargetPool, "buckets": prefixCounts()})
	}))
	mux.HandleFunc("/api/logs", webAuth(func(w http.ResponseWriter, r *http.Request) {
		logsLock.RLock()
		x := append([]*ConnLog(nil), logs...)
		logsLock.RUnlock()
		if len(x) > 10 {
			x = x[len(x)-10:]
		}
		js(w, x)
	}))
	mux.HandleFunc("/api/active", webAuth(func(w http.ResponseWriter, r *http.Request) {
		activeLock.RLock()
		arr := []*ActiveConn{}
		for _, v := range active {
			if len(arr) >= 10 {
				break
			}
			c := *v
			c.Duration = fmt.Sprintf("%.1fs", time.Since(v.StartTime).Seconds())
			arr = append(arr, &c)
		}
		activeLock.RUnlock()
		js(w, arr)
	}))
	srv := &http.Server{Addr: ":" + config.WebPort, Handler: mux}
	go func() {
		if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			log.Printf("Web server failed: %v", e)
		}
	}()
	log.Printf("Web panel: http://0.0.0.0:%s", config.WebPort)
	return srv
}
func cleanupPool() {
	poolLock.RLock()
	arr := append([]net.IP(nil), ipv6Pool...)
	poolLock.RUnlock()
	for _, ip := range arr {
		delIP(ip)
	}
}
func main() {
	stats.StartTime = time.Now()
	exe, e := os.Executable()
	if e != nil {
		log.Fatalf("Unable to get executable path: %v", e)
	}
	dir := filepath.Dir(exe)
	configFilePath = filepath.Join(dir, "config.json")
	if _, e := os.Stat(configFilePath); e != nil {
		log.Println("Config file not found, starting first-time setup")
		if e := firstSetup(); e != nil {
			log.Fatalf("Setup failed: %v", e)
		}
		log.Println("Config saved, the install script will continue to start the service")
		return
	}
	if e := loadConfig(); e != nil {
		log.Fatalf("Failed to load config: %v", e)
	}
	if config.AllowedTargets == nil {
		config.AllowedTargets = parseAllowList([]string{defaultAllowedTargets})
	}
	initAllow()
	if len(allowEntries) == 0 {
		log.Printf("Allowlist: OPEN (no targets configured)")
	} else {
		log.Printf("Allowlist: %d entries, token %s", len(allowEntries), map[bool]string{true: "set", false: "NOT set"}[allowToken != ""])
		for _, e := range allowEntries {
			log.Printf("  allow: %s", e)
		}
	}
	
	// Parse every configured prefix before anything touches the pool.
	prefixPools = nil
	for _, ps := range effectivePrefixes() {
		_, n, perr := net.ParseCIDR(ps)
		if perr != nil {
			log.Fatalf("Unable to parse IPv6 prefix %q: %v", ps, perr)
		}
		prefixPools = append(prefixPools, n)
	}
	if len(prefixPools) == 0 {
		log.Fatalf("No IPv6 prefix configured (set ipv6_prefix or ipv6_prefixes)")
	}
	log.Printf("Prefix buckets: %d", len(prefixPools))
	for _, p := range prefixPools {
		log.Printf("  prefix: %s", p.String())
	}

	iface, e = netlink.LinkByName(config.Interface)
	if e != nil {
		log.Fatalf("Unable to find network interface: %v", e)
	}
	if config.NextHopAddr != "" {
		nh := net.ParseIP(config.NextHopAddr)
		if nh == nil {
			log.Fatalf("Invalid next-hop address: %s", config.NextHopAddr)
		}
		a := &netlink.Addr{IPNet: &net.IPNet{IP: nh, Mask: net.CIDRMask(64, 128)}, Flags: syscall.IFA_F_NODAD}
		if e := netlink.AddrAdd(iface, a); e != nil && !strings.Contains(e.Error(), "file exists") {
			log.Printf("Failed to add next-hop address: %v", e)
		}
	}
	log.Printf("Prefixa IPv6 Gateway v%s", appVersion)
	log.Printf("Config: proxy port %s, web port %s", config.Port, config.WebPort)
	log.Printf("Network: %d prefix(es) @ %s", len(prefixPools), config.Interface)
	cleanupStale()
	if e := initPool(); e != nil {
		log.Fatalf("Initialization failed: %v", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	discardQueue = make(chan net.IP, 5000)
	go discard(ctx)
	go backgroundFill(ctx)
	go autoRotate(ctx)
	web := startWeb(ctx)
	var wg sync.WaitGroup
	listeners := []net.Listener{}
	l, e := listen(ctx, config.Port, &wg)
	if e != nil {
		log.Fatalf("Failed to listen on main port: %v", e)
	}
	listeners = append(listeners, l)
	for _, p := range config.Ports {
		if p.Enabled && p.Port != "" && p.Port != config.Port {
			if l, e := listen(ctx, p.Port, &wg); e == nil {
				listeners = append(listeners, l)
			} else {
				log.Printf("Failed to listen on port %s: %v", p.Port, e)
			}
		}
	}
	if config.SignalToken != "" {
		log.Printf("429 signal endpoint: POST /__signal on proxy port %s (bearer token)", config.Port)
	}
	log.Println("Service ready")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("Shutting down")
	cancel()
	web.Shutdown(context.Background())
	for _, l := range listeners {
		l.Close()
	}
	wg.Wait()
	cleanupPool()
	log.Println("Shut down")
}
