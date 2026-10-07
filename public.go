package main

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
)

func (s *server) publicMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dl/{token}", s.handleDownload)
	mux.HandleFunc("GET /upload/{$}", s.handleUploadForm)
	mux.HandleFunc("POST /upload/{$}", s.handleUpload)
	mux.HandleFunc("/", http.NotFound)
	blocked := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isBlocked(clientIP(r)) {
			http.NotFound(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	return publicHeaders(blocked)
}

func publicHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Robots-Tag", "noindex, nofollow")
		h.ServeHTTP(w, r)
	})
}

func (s *server) isBlocked(ip string) (b bool) {
	if s.allowed(ip) {
		return false
	}
	s.store.view(func(st *State) { b = st.Blocked[ip] != nil })
	return
}

// badToken records an unknown-token lookup and blocks the IP on the maxBadTokens-th.
func (s *server) badToken(ip, tok string) {
	if s.allowed(ip) {
		slog.Info("bad token (allowlisted)", "ip", ip, "token", tok)
		return
	}
	s.failMu.Lock()
	s.fails[ip]++
	n := s.fails[ip]
	s.failMu.Unlock()
	slog.Warn("bad token", "ip", ip, "token", tok, "count", n)
	if n < maxBadTokens {
		return
	}
	if len(tok) > 32 {
		tok = tok[:32]
	}
	s.store.update(func(st *State) error { st.Blocked[ip] = &Block{Time: time.Now(), Tried: tok}; return nil })
	slog.Warn("ip blocked", "ip", ip)
}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	if !validToken(tok) {
		s.badToken(clientIP(r), tok)
		http.NotFound(w, r)
		return
	}
	var link Link
	var ok bool
	s.store.view(func(st *State) {
		if l := st.Links[tok]; l != nil {
			link, ok = *l, true
		}
	})
	if !ok {
		s.badToken(clientIP(r), tok)
	}
	if !ok || link.expired(time.Now()) { // expired still exists, so a recipient's refresh isn't counted
		http.NotFound(w, r)
		return
	}
	f, err := s.files.Open(link.Path)
	if err != nil {
		slog.Warn("download: file missing", "token", tok, "path", link.Path, "err", err)
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}

	cd := mime.FormatMediaType("attachment", map[string]string{"filename": link.Name})
	if cd == "" {
		cd = "attachment"
	}
	w.Header().Set("Content-Disposition", cd)
	w.Header().Set("Cache-Control", "private, no-transform")

	// Count a download once per transfer that starts at byte 0 (resumes don't count).
	rg := r.Header.Get("Range")
	if r.Method == http.MethodGet && (rg == "" || strings.HasPrefix(rg, "bytes=0-")) {
		now := time.Now()
		if err := s.store.update(func(st *State) error {
			if l := st.Links[tok]; l != nil {
				l.Downloads++
				l.LastDL = &now
			}
			return nil
		}); err != nil {
			slog.Error("save state", "err", err)
		}
		slog.Info("download", "token", tok, "path", link.Path, "ip", clientIP(r), "size", fi.Size())
	}
	http.ServeContent(w, r, link.Name, fi.ModTime(), f)
}

const maxFilesPerRequest = 20

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.allowed(ip) && !s.lim.allow(ip) {
		slog.Warn("upload rate limited", "ip", ip)
		http.Error(w, "too many uploads, try again later", http.StatusTooManyRequests)
		return
	}
	if r.ContentLength > s.cfg.MaxUpload {
		http.Error(w, "upload too large (max "+humanSize(s.cfg.MaxUpload)+")", http.StatusRequestEntityTooLarge)
		return
	}
	if free := freeBytes(s.cfg.IncomingDir); free >= 0 && free < s.cfg.MinFree+max(r.ContentLength, 0) {
		slog.Warn("upload refused: low disk", "free", free, "ip", ip)
		http.Error(w, "server is out of space", http.StatusInsufficientStorage)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUpload)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected multipart/form-data with a \"file\" field", http.StatusBadRequest)
		return
	}

	type saved struct {
		Name string
		Size int64
	}
	var got []saved
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.uploadErr(w, err)
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			part.Close()
			continue
		}
		if len(got) >= maxFilesPerRequest {
			part.Close()
			http.Error(w, fmt.Sprintf("max %d files per upload", maxFilesPerRequest), http.StatusBadRequest)
			return
		}
		orig := part.FileName()
		stored := time.Now().Format("20060102-150405") + "_" + randString(6) + "_" + sanitizeName(orig)
		f, err := s.incoming.OpenFile(stored, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
		if err != nil {
			slog.Error("create upload", "err", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		n, cerr := io.Copy(f, part)
		if err := f.Close(); cerr == nil {
			cerr = err
		}
		part.Close()
		if cerr != nil {
			s.incoming.Remove(stored)
			s.uploadErr(w, cerr)
			return
		}
		if n == 0 {
			s.incoming.Remove(stored)
			continue
		}
		up := &Upload{Original: orig, Size: n, Time: time.Now(), IP: ip}
		if err := s.store.update(func(st *State) error { st.Uploads[stored] = up; return nil }); err != nil {
			slog.Error("save state", "err", err)
		}
		slog.Info("upload", "ip", ip, "original", orig, "stored", stored, "size", n)
		got = append(got, saved{orig, n})
	}

	if len(got) == 0 {
		http.Error(w, "no file received", http.StatusBadRequest)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		uploadDoneTmpl.Execute(w, got)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, g := range got {
		fmt.Fprintf(w, "received %s (%d bytes)\n", g.Name, g.Size)
	}
}

func (s *server) uploadErr(w http.ResponseWriter, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		http.Error(w, "upload too large (max "+humanSize(s.cfg.MaxUpload)+")", http.StatusRequestEntityTooLarge)
		return
	}
	slog.Warn("upload failed", "err", err)
	http.Error(w, "upload failed", http.StatusBadRequest)
}

func (s *server) handleUploadForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'")
	uploadFormTmpl.Execute(w, map[string]string{"Max": humanSize(s.cfg.MaxUpload)})
}

const pageCSS = `
:root{--bg:#f6f7f9;--fg:#1b1f24;--muted:#5f6b7a;--card:#fff;--line:#d9dee5;--acc:#2f6fdb;--bad:#c0392b;--ok:#1e8e3e}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e6e9ed;--muted:#9aa5b1;--card:#1b1f24;--line:#2c323a;--acc:#6ea0ff;--bad:#ff6b5e;--ok:#4cc26e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:560px;margin:8vh auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:24px}
h1{font-size:20px;margin:0 0 4px}p{color:var(--muted);margin:0 0 16px}
input[type=file]{width:100%;margin:8px 0 16px}
button{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:9px 18px;font:inherit;cursor:pointer}
button:disabled{opacity:.5}
progress{width:100%;height:10px;margin-top:16px;display:none}
#msg{margin-top:12px}.ok{color:var(--ok)}.bad{color:var(--bad)}
ul{padding-left:20px}
`

var uploadFormTmpl = template.Must(template.New("form").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Upload</title><style>` + pageCSS + `</style></head>
<body><main><div class="card">
<h1>Send me a file</h1>
<p>Max {{.Max}} per upload.</p>
<form id="f" method="post" action="/upload/" enctype="multipart/form-data">
<input type="file" name="file" id="file" multiple required>
<button id="btn" type="submit">Upload</button>
</form>
<progress id="prog" max="100" value="0"></progress>
<div id="msg"></div>
</div></main>
<script>
const f=document.getElementById('f'),btn=document.getElementById('btn'),prog=document.getElementById('prog'),msg=document.getElementById('msg');
f.addEventListener('submit',e=>{
  e.preventDefault();
  const x=new XMLHttpRequest();
  x.open('POST',f.action);
  x.setRequestHeader('Accept','text/plain');
  x.upload.onprogress=ev=>{if(ev.lengthComputable)prog.value=ev.loaded/ev.total*100};
  x.onload=()=>{btn.disabled=false;msg.className=x.status===200?'ok':'bad';msg.textContent=x.status===200?'Done. '+x.responseText:x.responseText||('Error '+x.status);if(x.status===200)f.reset()};
  x.onerror=()=>{btn.disabled=false;msg.className='bad';msg.textContent='Upload failed (network error).'};
  btn.disabled=true;prog.style.display='block';prog.value=0;msg.textContent='';
  x.send(new FormData(f));
});
</script></body></html>`))

var uploadDoneTmpl = template.Must(template.New("done").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Uploaded</title><style>` + pageCSS + `</style></head>
<body><main><div class="card"><h1>Thanks, got it</h1>
<ul>{{range .}}<li>{{.Name}} ({{.Size}} bytes)</li>{{end}}</ul>
<p><a href="/upload/">Upload more</a></p></div></main></body></html>`))
