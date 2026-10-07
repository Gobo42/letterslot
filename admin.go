package main

import (
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *server) adminMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.adminIndex)
	mux.HandleFunc("POST /link", s.adminCreateLink)
	mux.HandleFunc("POST /revoke", s.adminRevoke)
	mux.HandleFunc("POST /unblock", s.adminUnblock)
	mux.HandleFunc("GET /incoming/{name}", s.adminGetUpload)
	mux.HandleFunc("POST /incoming/delete", s.adminDeleteUpload)
	mux.HandleFunc("POST /incoming/publish", s.adminPublishUpload)
	return sameOrigin(mux)
}

// sameOrigin blocks cross-site POSTs (a random web page making your browser
// hit the admin API on the LAN).
func sameOrigin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
				if sfs != "same-origin" && sfs != "none" {
					http.Error(w, "cross-origin request blocked", http.StatusForbidden)
					return
				}
			} else if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					http.Error(w, "cross-origin request blocked", http.StatusForbidden)
					return
				}
			}
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

type linkRow struct {
	Token   string
	URL     string
	Link    Link
	Expired bool
}

type fileRow struct {
	Path  string
	Size  int64
	Mod   time.Time
	Links []linkRow
}

type blockRow struct {
	IP    string
	Block Block
}

type uploadRow struct {
	Stored   string
	Original string
	Size     int64
	Time     time.Time
	IP       string
}

func (s *server) adminIndex(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	var files []*fileRow
	byPath := map[string]*fileRow{}
	err := fs.WalkDir(s.files.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p != "." && strings.HasPrefix(d.Name(), ".") { // skip dotfiles / rsync temp files
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		fr := &fileRow{Path: p, Size: fi.Size(), Mod: fi.ModTime()}
		files = append(files, fr)
		byPath[p] = fr
		return nil
	})
	if err != nil {
		slog.Error("walk files", "err", err)
	}

	var orphans []linkRow
	var uploads []uploadRow
	var blocked []blockRow
	known := map[string]bool{}
	s.store.view(func(st *State) {
		for tok, l := range st.Links {
			lr := linkRow{Token: tok, URL: s.cfg.BaseURL + "/dl/" + tok, Link: *l, Expired: l.expired(now)}
			if fr := byPath[l.Path]; fr != nil {
				fr.Links = append(fr.Links, lr)
			} else {
				orphans = append(orphans, lr)
			}
		}
		for ip, b := range st.Blocked {
			blocked = append(blocked, blockRow{ip, *b})
		}
		for name, u := range st.Uploads {
			known[name] = true
			uploads = append(uploads, uploadRow{Stored: name, Original: u.Original, Size: u.Size, Time: u.Time, IP: u.IP})
		}
	})
	// Include anything in incoming/ that isn't in state, and drop state entries whose file is gone.
	if ents, err := fs.ReadDir(s.incoming.FS(), "."); err == nil {
		present := map[string]bool{}
		for _, e := range ents {
			if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			present[e.Name()] = true
			if !known[e.Name()] {
				if fi, err := e.Info(); err == nil {
					uploads = append(uploads, uploadRow{Stored: e.Name(), Original: e.Name(), Size: fi.Size(), Time: fi.ModTime(), IP: "?"})
				}
			}
		}
		kept := uploads[:0]
		for _, u := range uploads {
			if present[u.Stored] {
				kept = append(kept, u)
			}
		}
		uploads = kept
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Mod.After(files[j].Mod) })
	for _, f := range files {
		sort.Slice(f.Links, func(i, j int) bool { return f.Links[i].Link.Created.After(f.Links[j].Link.Created) })
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].Link.Created.After(orphans[j].Link.Created) })
	sort.Slice(blocked, func(i, j int) bool { return blocked[i].Block.Time.After(blocked[j].Block.Time) })
	sort.Slice(uploads, func(i, j int) bool { return uploads[i].Time.After(uploads[j].Time) })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	err = adminTmpl.Execute(w, map[string]any{
		"Files":    files,
		"Orphans":  orphans,
		"Uploads":  uploads,
		"Blocked":  blocked,
		"FilesDir": s.cfg.FilesDir,
		"Free":     humanSize(freeBytes(s.cfg.FilesDir)),
		"Flash":    r.URL.Query().Get("msg"),
	})
	if err != nil {
		slog.Error("render admin", "err", err)
	}
}

func back(w http.ResponseWriter, r *http.Request, msg, anchor string) {
	u := "/"
	if msg != "" {
		u += "?msg=" + url.QueryEscape(msg)
	}
	if anchor != "" {
		u += "#" + anchor
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (s *server) adminCreateLink(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("path")
	if p == "" || !fs.ValidPath(p) || p == "." {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	fi, err := s.files.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		http.Error(w, "no such file", http.StatusBadRequest)
		return
	}
	l := &Link{Path: p, Name: path.Base(p), Note: strings.TrimSpace(r.FormValue("note")), Created: time.Now()}
	if n := strings.TrimSpace(r.FormValue("name")); n != "" {
		l.Name = n
	}
	if d, _ := strconv.Atoi(r.FormValue("days")); d > 0 {
		exp := time.Now().Add(time.Duration(d) * 24 * time.Hour)
		l.Expires = &exp
	}
	var tok string
	err = s.store.update(func(st *State) error {
		for {
			tok = randString(tokenLen)
			if st.Links[tok] == nil {
				break
			}
		}
		st.Links[tok] = l
		return nil
	})
	if err != nil {
		http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("link created", "token", tok, "path", p)
	back(w, r, "", "t-"+tok)
}

func (s *server) adminRevoke(w http.ResponseWriter, r *http.Request) {
	tok := r.FormValue("token")
	var p string
	err := s.store.update(func(st *State) error {
		if l := st.Links[tok]; l != nil {
			p = l.Path
		}
		delete(st.Links, tok)
		return nil
	})
	if err != nil {
		http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("link revoked", "token", tok, "path", p)
	back(w, r, "Link revoked", "")
}

func (s *server) adminUnblock(w http.ResponseWriter, r *http.Request) {
	ip := r.FormValue("ip")
	err := s.store.update(func(st *State) error { delete(st.Blocked, ip); return nil })
	if err != nil {
		http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.failMu.Lock()
	delete(s.fails, ip)
	s.failMu.Unlock()
	slog.Info("ip unblocked", "ip", ip)
	back(w, r, "Unblocked "+ip, "blocked")
}

func validUploadName(name string) bool {
	return name != "" && name == filepath.Base(name) && !strings.HasPrefix(name, ".")
}

func (s *server) adminGetUpload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validUploadName(name) {
		http.NotFound(w, r)
		return
	}
	f, err := s.incoming.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	dl := name
	s.store.view(func(st *State) {
		if u := st.Uploads[name]; u != nil {
			dl = sanitizeName(u.Original)
		}
	})
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": dl}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, dl, fi.ModTime(), f)
}

func (s *server) adminDeleteUpload(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if !validUploadName(name) {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	if err := s.incoming.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, "delete failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.update(func(st *State) error { delete(st.Uploads, name); return nil })
	slog.Info("upload deleted", "name", name)
	back(w, r, "Upload deleted", "uploads")
}

// adminPublishUpload moves an upload into the files dir (under its original
// name, sanitized) so you can make a link for it.
func (s *server) adminPublishUpload(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if !validUploadName(name) {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	target := name
	s.store.view(func(st *State) {
		if u := st.Uploads[name]; u != nil {
			target = sanitizeName(u.Original)
		}
	})
	ext := filepath.Ext(target)
	stem := strings.TrimSuffix(target, ext)
	for i := 1; ; i++ {
		if _, err := s.files.Stat(target); errors.Is(err, os.ErrNotExist) {
			break
		}
		target = stem + "-" + strconv.Itoa(i) + ext
	}
	src := filepath.Join(s.cfg.IncomingDir, name)
	dst := filepath.Join(s.cfg.FilesDir, target)
	if err := os.Rename(src, dst); err != nil {
		http.Error(w, "move failed (incoming and files must be on the same filesystem): "+err.Error(), http.StatusInternalServerError)
		return
	}
	os.Chmod(dst, 0o644)
	s.store.update(func(st *State) error { delete(st.Uploads, name); return nil })
	slog.Info("upload published", "name", name, "to", target)
	back(w, r, "Moved to files/"+target, "")
}

var adminFuncs = template.FuncMap{
	"size": humanSize,
	"when": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Local().Format("2006-01-02 15:04")
	},
	"whenp": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Local().Format("2006-01-02 15:04")
	},
}

var adminTmpl = template.Must(template.New("admin").Funcs(adminFuncs).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>letterslot admin</title>
<style>
:root{--bg:#f6f7f9;--fg:#1b1f24;--muted:#5f6b7a;--card:#fff;--line:#d9dee5;--acc:#2f6fdb;--bad:#c0392b;--ok:#1e8e3e;--hl:#fff7d6}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e6e9ed;--muted:#9aa5b1;--card:#1b1f24;--line:#2c323a;--acc:#6ea0ff;--bad:#ff6b5e;--ok:#4cc26e;--hl:#3a3320}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:20px 16px 60px}
h1{font-size:20px;margin:0}h2{font-size:16px;margin:28px 0 8px}
.top{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap}
.muted{color:var(--muted)}.bad{color:var(--bad)}.ok{color:var(--ok)}
.flash{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--ok);padding:8px 12px;margin:12px 0;border-radius:6px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:10px;overflow:hidden}
.fh{display:flex;gap:12px;align-items:center;padding:10px 12px;flex-wrap:wrap}
.fh .name{font-weight:600;word-break:break-all;flex:1 1 300px}
.links{border-top:1px solid var(--line)}
.lr{display:flex;gap:10px;align-items:center;padding:6px 12px;border-top:1px solid var(--line);flex-wrap:wrap}
.lr:first-child{border-top:0}.lr:target{background:var(--hl)}
.lr input.url{font:12px ui-monospace,monospace;flex:1 1 360px;min-width:0;padding:4px 6px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--fg)}
.lr.expired input.url{text-decoration:line-through;color:var(--muted)}
form.inline{display:inline-flex;gap:6px;align-items:center;margin:0;flex-wrap:wrap}
select,input[type=text]{font:inherit;padding:3px 6px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--fg)}
button{font:inherit;padding:3px 10px;border-radius:4px;border:1px solid var(--line);background:var(--bg);color:var(--fg);cursor:pointer}
button.pri{background:var(--acc);border-color:var(--acc);color:#fff}
button.del{color:var(--bad)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px}
th,td{text-align:left;padding:6px 10px;border-top:1px solid var(--line);vertical-align:middle}
th{border-top:0;color:var(--muted);font-weight:500}
td.name{word-break:break-all}
.empty{padding:14px;color:var(--muted)}
</style></head><body><main>
<div class="top"><h1>letterslot</h1><span class="muted">{{.FilesDir}} · {{.Free}} free</span></div>
{{with .Flash}}<div class="flash">{{.}}</div>{{end}}

<h2>Shared files</h2>
{{range .Files}}
<div class="card">
  <div class="fh">
    <span class="name">{{.Path}}</span>
    <span class="muted">{{size .Size}} · {{when .Mod}}</span>
    <form class="inline" method="post" action="/link">
      <input type="hidden" name="path" value="{{.Path}}">
      <select name="days" title="Expiry">
        <option value="0">never expires</option><option value="1">1 day</option><option value="7">7 days</option>
        <option value="30">30 days</option><option value="90">90 days</option>
      </select>
      <input type="text" name="note" placeholder="note (who it's for)" size="16">
      <button class="pri" type="submit">New link</button>
    </form>
  </div>
  {{if .Links}}<div class="links">{{range .Links}}
    <div class="lr{{if .Expired}} expired{{end}}" id="t-{{.Token}}">
      <input class="url" type="text" readonly value="{{.URL}}" onclick="this.select()">
      <button type="button" onclick="cp(this)">Copy</button>
      <span class="muted">{{.Link.Downloads}} dl{{with .Link.LastDL}} · last {{whenp .}}{{end}}</span>
      <span class="muted">{{if .Expired}}<span class="bad">expired</span>{{else if .Link.Expires}}expires {{whenp .Link.Expires}}{{else}}no expiry{{end}}</span>
      {{with .Link.Note}}<span>{{.}}</span>{{end}}
      <form class="inline" method="post" action="/revoke" onsubmit="return confirm('Revoke this link?')">
        <input type="hidden" name="token" value="{{.Token}}"><button class="del" type="submit">Revoke</button>
      </form>
    </div>{{end}}
  </div>{{end}}
</div>
{{else}}<div class="card"><div class="empty">No files yet. scp something into {{.FilesDir}}.</div></div>{{end}}

{{if .Orphans}}
<h2 class="bad">Links whose file is gone</h2>
<div class="card"><div class="links">{{range .Orphans}}
  <div class="lr" id="t-{{.Token}}">
    <span class="name">{{.Link.Path}}</span>
    <span class="muted">{{.Link.Downloads}} dl · created {{when .Link.Created}}</span>
    {{with .Link.Note}}<span>{{.}}</span>{{end}}
    <form class="inline" method="post" action="/revoke"><input type="hidden" name="token" value="{{.Token}}"><button class="del" type="submit">Remove</button></form>
  </div>{{end}}
</div></div>
{{end}}

<h2 id="uploads">Incoming uploads</h2>
{{if .Uploads}}
<table><tr><th>File</th><th>Size</th><th>Received</th><th>From</th><th></th></tr>
{{range .Uploads}}<tr>
  <td class="name"><a href="/incoming/{{.Stored}}">{{.Original}}</a></td>
  <td>{{size .Size}}</td><td>{{when .Time}}</td><td class="muted">{{.IP}}</td>
  <td><form class="inline" method="post" action="/incoming/publish"><input type="hidden" name="name" value="{{.Stored}}"><button type="submit" title="Move into shared files">Move to files</button></form>
      <form class="inline" method="post" action="/incoming/delete" onsubmit="return confirm('Delete this upload?')"><input type="hidden" name="name" value="{{.Stored}}"><button class="del" type="submit">Delete</button></form></td>
</tr>{{end}}</table>
{{else}}<div class="card"><div class="empty">No uploads.</div></div>{{end}}

<h2 id="blocked">Blocked IPs</h2>
{{if .Blocked}}
<table><tr><th>IP</th><th>Blocked</th><th>Last token tried</th><th></th></tr>
{{range .Blocked}}<tr><td>{{.IP}}</td><td>{{when .Block.Time}}</td><td class="muted">{{.Block.Tried}}</td>
  <td><form class="inline" method="post" action="/unblock"><input type="hidden" name="ip" value="{{.IP}}"><button type="submit">Unblock</button></form></td></tr>{{end}}</table>
{{else}}<div class="card"><div class="empty">None.</div></div>{{end}}
</main>
<script>
function cp(b){
  const i=b.previousElementSibling; i.select();
  const done=()=>{const t=b.textContent;b.textContent='Copied';setTimeout(()=>b.textContent=t,1200)};
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(i.value).then(done)}
  else{try{document.execCommand('copy');done()}catch(e){}}
}
</script>
</body></html>`))
