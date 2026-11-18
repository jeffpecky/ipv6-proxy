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
	"os"
	"os/signal"
	"path/filepath"
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
	NextHopAddr     string       `json:"nexthop_addr"`
	Interface       string       `json:"interface"`
	InitialPool     int          `json:"initial_pool"`
	TargetPool      int          `json:"target_pool"`
	AutoRotate      bool         `json:"auto_rotate"`
	AutoRotateHours int          `json:"auto_rotate_hours"`
	AutoClean       bool         `json:"auto_clean"`
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
var prefixIP net.IP
var prefixNet *net.IPNet
var discardQueue chan net.IP
var rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))
var rngLock sync.Mutex

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
func genIP() net.IP {
	ip := make(net.IP, 16)
	copy(ip, prefixIP.To16())
	ones, _ := prefixNet.Mask.Size()
	b := ones / 8
	if b < 16 {
		_, _ = rand.Read(ip[b:])
	}
	if ones%8 != 0 && b < 16 {
		mask := byte(0xff << (8 - ones%8))
		ip[b] = (prefixIP[b] & mask) | (ip[b] &^ mask)
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
		if bits != 128 || ones != 128 || !prefixNet.Contains(a.IP) {
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
			if bits != 128 || ones != 128 || !prefixNet.Contains(a.IP) {
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
func proxy(client net.Conn, host string, port uint16, isSocks bool) {
	start := time.Now()
	cip := client.RemoteAddr().String()
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
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
			ip = getIP()
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
	proxy(c, host, port, true)
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
	if len(parts) < 3 {
		return
	}
	ok := false
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "proxy-authorization: basic ") {
			dec, e := base64.StdEncoding.DecodeString(strings.TrimSpace(line[27:]))
			if e == nil {
				kv := strings.SplitN(string(dec), ":", 2)
				if len(kv) == 2 && auth(listenPort, kv[0], kv[1]) {
					ok = true
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
	proxy(c, h, uint16(pn), false)
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
		js(w, map[string]interface{}{"active": atomic.LoadInt64(&stats.ActiveConns), "total": atomic.LoadInt64(&stats.TotalConns), "success": atomic.LoadInt64(&stats.SuccessConns), "failed": atomic.LoadInt64(&stats.FailedConns), "pool": atomic.LoadInt64(&stats.PoolSize), "target": config.TargetPool, "bytes_recv": atomic.LoadInt64(&stats.TotalBytesRecv), "bytes_sent": atomic.LoadInt64(&stats.TotalBytesSent), "auto_rotate": config.AutoRotate, "rotate_interval": config.AutoRotateHours, "uptime": fmt.Sprintf("%dd %dh %dm", int(up.Hours())/24, int(up.Hours())%24, int(up.Minutes())%60)})
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
	prefixIP, prefixNet, e = net.ParseCIDR(config.IPv6Prefix)
	if e != nil {
		log.Fatalf("Unable to parse IPv6 prefix: %v", e)
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
	log.Printf("Network: %s @ %s", config.IPv6Prefix, config.Interface)
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
