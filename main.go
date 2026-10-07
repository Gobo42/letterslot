// letterslot: token-link file sharing + public drop box.
//
// Public listener (put behind a reverse proxy):
//
//	GET  /dl/<token>   download a shared file (no index, unknown token = 404)
//	GET  /upload/      upload form
//	POST /upload/      multipart upload into the incoming dir
//
// Admin listener (LAN only, never proxy it):
//
//	GET  /             files, links, incoming uploads
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const tokenLen = 8
const maxBadTokens = 2 // unknown-token lookups from one IP before it is blocked
const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type config struct {
	PublicAddr  string
	AdminAddr   string
	FilesDir    string
	IncomingDir string
	StatePath   string
	BaseURL     string
	MaxUpload   int64
	MinFree     int64
	UploadRate  int
	Allow       []netip.Prefix // never blocked, not rate limited
}

// ---------- state ----------

type Link struct {
	Path      string     `json:"path"` // slash-separated, relative to FilesDir
	Name      string     `json:"name"` // filename sent to the downloader
	Note      string     `json:"note,omitempty"`
	Created   time.Time  `json:"created"`
	Expires   *time.Time `json:"expires,omitempty"`
	Downloads int        `json:"downloads"`
	LastDL    *time.Time `json:"last_download,omitempty"`
}

func (l *Link) expired(now time.Time) bool { return l.Expires != nil && now.After(*l.Expires) }

type Upload struct {
	Original string    `json:"original"`
	Size     int64     `json:"size"`
	Time     time.Time `json:"time"`
	IP       string    `json:"ip"`
}

type Block struct {
	Time  time.Time `json:"time"`
	Tried string    `json:"tried"` // last bad token it asked for (truncated)
}

type State struct {
	Links   map[string]*Link   `json:"links"`
	Uploads map[string]*Upload `json:"uploads"` // keyed by stored filename in IncomingDir
	Blocked map[string]*Block  `json:"blocked"` // client IP -> why
}

type Store struct {
	mu   sync.Mutex
	path string
	s    State
}

func loadStore(path string) (*Store, error) {
	st := &Store{path: path, s: State{Links: map[string]*Link{}, Uploads: map[string]*Upload{}, Blocked: map[string]*Block{}}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &st.s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if st.s.Links == nil {
		st.s.Links = map[string]*Link{}
	}
	if st.s.Uploads == nil {
		st.s.Uploads = map[string]*Upload{}
	}
	if st.s.Blocked == nil {
		st.s.Blocked = map[string]*Block{}
	}
	return st, nil
}

// saveLocked writes state atomically. Caller holds mu.
func (st *Store) saveLocked() error {
	b, err := json.MarshalIndent(&st.s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(st.path), ".state-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), st.path)
}

// update runs fn under the lock and persists the result.
func (st *Store) update(fn func(s *State) error) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := fn(&st.s); err != nil {
		return err
	}
	return st.saveLocked()
}

// view runs fn under the lock without saving.
func (st *Store) view(fn func(s *State)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(&st.s)
}

// ---------- helpers ----------

func randString(n int) string {
	var sb strings.Builder
	max := big.NewInt(int64(len(base62)))
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		sb.WriteByte(base62[v.Int64()])
	}
	return sb.String()
}

func validToken(t string) bool {
	if len(t) != tokenLen && len(t) != 16 { // 16 = legacy links minted before the 8-char switch
		return false
	}
	for i := 0; i < len(t); i++ {
		if !strings.ContainsRune(base62, rune(t[i])) {
			return false
		}
	}
	return true
}

// sanitizeName reduces an untrusted filename to a safe single path element.
func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = name[strings.LastIndex(name, "/")+1:]
	var sb strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			sb.WriteRune(r)
		case r == ' ':
			sb.WriteByte('_')
		}
	}
	out := strings.TrimLeft(sb.String(), ".")
	if len(out) > 120 {
		ext := filepath.Ext(out)
		if len(ext) > 20 {
			ext = ""
		}
		out = out[:120-len(ext)] + ext
	}
	if out == "" {
		out = "upload"
	}
	return out
}

func freeBytes(dir string) int64 {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		return -1
	}
	return int64(fs.Bavail) * int64(fs.Bsize)
}

func humanSize(n int64) string {
	if n < 0 {
		return "?"
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"TIB", 1 << 40}, {"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10}, {"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}} {
		if strings.HasSuffix(s, u.suf) {
			mult = u.m
			s = strings.TrimSuffix(s, u.suf)
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return n * mult, nil
}

func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" && net.ParseIP(ip) != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- rate limiter (uploads per IP per hour) ----------

type limiter struct {
	mu    sync.Mutex
	limit int
	hits  map[string][]time.Time
}

func (l *limiter) allow(ip string) bool {
	if l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cut := now.Add(-time.Hour)
	h := l.hits[ip]
	i := 0
	for i < len(h) && h[i].Before(cut) {
		i++
	}
	h = h[i:]
	if len(h) >= l.limit {
		l.hits[ip] = h
		return false
	}
	l.hits[ip] = append(h, now)
	if len(l.hits) > 10000 { // crude cleanup
		for k, v := range l.hits {
			if len(v) == 0 || v[len(v)-1].Before(cut) {
				delete(l.hits, k)
			}
		}
	}
	return true
}

// ---------- server ----------

func loadAllow(path string) ([]netip.Prefix, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for i, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			a, err2 := netip.ParseAddr(line)
			if err2 != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *server) allowed(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range s.cfg.Allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type server struct {
	cfg      config
	store    *Store
	files    *os.Root
	incoming *os.Root
	lim      *limiter
	failMu   sync.Mutex
	fails    map[string]int // bad-token lookups per IP since start
}

func main() {
	var cfg config
	var maxUp, minFree string
	flag.StringVar(&cfg.PublicAddr, "public", "0.0.0.0:8080", "public listen address (proxied)")
	flag.StringVar(&cfg.AdminAddr, "admin", "0.0.0.0:80", "admin listen address (LAN only)")
	flag.StringVar(&cfg.FilesDir, "files", "/srv/share/files", "directory of files you share (scp here)")
	flag.StringVar(&cfg.IncomingDir, "incoming", "/srv/share/incoming", "directory public uploads land in")
	flag.StringVar(&cfg.StatePath, "state", "/var/lib/letterslot/state.json", "state file")
	flag.StringVar(&cfg.BaseURL, "base-url", "https://share.example.com", "public base URL used to display links")
	flag.StringVar(&maxUp, "max-upload", "2G", "max size of one upload request")
	flag.StringVar(&minFree, "min-free", "4G", "refuse uploads when free space in incoming dir drops below this")
	flag.IntVar(&cfg.UploadRate, "upload-rate", 20, "max upload requests per IP per hour (0 = unlimited)")
	var allow string
	flag.StringVar(&allow, "allow-file", "", "file of IPs/CIDRs, one per line (# comments ok), never blocked or upload-rate-limited; read at startup")
	flag.Parse()

	var err error
	if cfg.MaxUpload, err = parseSize(maxUp); err != nil {
		fatal("max-upload", err)
	}
	if cfg.MinFree, err = parseSize(minFree); err != nil {
		fatal("min-free", err)
	}
	if allow != "" {
		if cfg.Allow, err = loadAllow(allow); err != nil {
			fatal("allow-file", err)
		}
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	store, err := loadStore(cfg.StatePath)
	if err != nil {
		fatal("load state", err)
	}
	files, err := os.OpenRoot(cfg.FilesDir)
	if err != nil {
		fatal("open files dir", err)
	}
	incoming, err := os.OpenRoot(cfg.IncomingDir)
	if err != nil {
		fatal("open incoming dir", err)
	}
	s := &server{cfg: cfg, store: store, files: files, incoming: incoming,
		lim: &limiter{limit: cfg.UploadRate, hits: map[string][]time.Time{}}, fails: map[string]int{}}

	pub := &http.Server{
		Addr:              cfg.PublicAddr,
		Handler:           s.publicMux(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	adm := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           s.adminMux(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 2)
	for _, srv := range []*http.Server{pub, adm} {
		go func(srv *http.Server) {
			slog.Info("listening", "addr", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", srv.Addr, err)
			}
		}(srv)
	}
	select {
	case <-ctx.Done():
	case err := <-errc:
		slog.Error("server failed", "err", err)
	}
	shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pub.Shutdown(shCtx)
	adm.Shutdown(shCtx)
}

func fatal(what string, err error) {
	slog.Error(what, "err", err)
	os.Exit(1)
}
