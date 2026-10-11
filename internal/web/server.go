// Package web serves the imageboard to the local browser. The server only
// listens on loopback and renders plain HTML from templates; it makes no
// requests to other sites and loads no third-party code.
package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/randwardatake/p2psite/internal/blob"
	"github.com/randwardatake/p2psite/internal/board"
	"github.com/randwardatake/p2psite/internal/manifest"
	"github.com/randwardatake/p2psite/internal/media"
	"github.com/randwardatake/p2psite/internal/node"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	previewReplies = 5
	csp            = "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)

// Server is the local web frontend.
type Server struct {
	node   *node.Node
	poster ed25519.PrivateKey
	mod    ed25519.PrivateKey // nil unless this node holds a moderator key
	log    *slog.Logger
	csrf   string
	tmpl   *template.Template
	hosts  map[string]bool
	mux    *http.ServeMux
	boards *http.ServeMux
}

// Config holds the frontend settings.
type Config struct {
	// Addr is the loopback address to listen on, e.g. 127.0.0.1:8088.
	Addr string
	// PosterKey is the secret every per-thread poster key is derived from.
	PosterKey ed25519.PrivateKey
	// ModKey is optional; with it the UI shows delete buttons.
	ModKey ed25519.PrivateKey
	Logger *slog.Logger
}

// New builds the frontend.
func New(n *node.Node, cfg Config) (*Server, error) {
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("web address %s must be a loopback address such as 127.0.0.1", cfg.Addr)
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return nil, err
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{
		node: n, poster: cfg.PosterKey, mod: cfg.ModKey, log: cfg.Logger,
		csrf: hex.EncodeToString(tok),
		// Accept only our own loopback names. This blocks DNS-rebinding
		// pages that would otherwise reach the local server.
		hosts: map[string]bool{
			cfg.Addr: true, "localhost:" + port: true, "127.0.0.1:" + port: true, "[::1]:" + port: true,
		},
	}
	if s.mod != nil && !n.Manifest().Payload.IsModerator(publicKey(s.mod)) {
		s.log.Warn("moderator key is not listed in the manifest; delete buttons disabled")
		s.mod = nil
	}
	s.tmpl, err = template.New("").Funcs(template.FuncMap{
		"body":     renderBody,
		"short":    board.ShortID,
		"time":     fmtTime,
		"size":     fmtSize,
		"add":      func(a, b int) int { return a + b },
		"poster":   func(p *board.Post) string { return p.PosterID() },
		"name":     func(p *board.Post) string { return cmpOr(p.Name, "Anonymous") },
		"snippet":  snippet,
		"nl2br":    nl2br,
		"filename": func(im *board.ImageRef) string { return cmpOr(im.Filename, "image") },
		"pc":       postContext,
		"form":     formContext,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

type postCtx struct {
	Post          *board.Post
	OP, Link, Mod bool
	CSRF          string
}

func postContext(p *page, post *board.Post, op, link bool) postCtx {
	return postCtx{Post: post, OP: op, Link: link, Mod: p.Mod, CSRF: p.CSRF}
}

type formCtx struct {
	Board         manifest.Board
	CSRF, Thread  string
	MaxChars      int
	MaxImage      string
	ImageRequired bool
}

func formContext(p *page, thread string) formCtx {
	l := p.Manifest.Limits
	return formCtx{
		Board: p.Board, CSRF: p.CSRF, Thread: thread, MaxChars: l.MaxBodyChars,
		MaxImage: fmtSize(l.MaxImageBytes), ImageRequired: l.OPImageRequired,
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func publicKey(sk ed25519.PrivateKey) []byte { return sk.Public().(ed25519.PublicKey) }

func (s *Server) routes() {
	// Board URLs (/linux/, /linux/thread/x) share their shape with fixed
	// paths like /static/x, so they live on a separate mux and ServeHTTP
	// picks one by the first path segment.
	m := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	m.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	m.HandleFunc("GET /{$}", s.home)
	m.HandleFunc("GET /status", s.status)
	m.HandleFunc("GET /blob/{cid}", s.blob)
	m.HandleFunc("POST /mod/delete", s.modDelete)
	s.mux = m

	b := http.NewServeMux()
	b.HandleFunc("GET /{board}/{$}", s.index)
	b.HandleFunc("GET /{board}/catalog", s.catalog)
	b.HandleFunc("GET /{board}/thread/{id}", s.thread)
	b.HandleFunc("GET /{board}/post/{id}", s.gotoPost)
	b.HandleFunc("POST /{board}/post", s.post)
	b.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, http.StatusNotFound, "There is nothing here.")
	})
	s.boards = b
}

// ServeHTTP applies host checks and security headers to every request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.hosts[r.Host] {
		http.Error(w, "unexpected Host header", http.StatusMisdirectedRequest)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if r.Method == http.MethodPost && !s.sameOrigin(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if manifest.ReservedPath(first) {
		s.mux.ServeHTTP(w, r)
		return
	}
	s.boards.ServeHTTP(w, r)
}

func (s *Server) sameOrigin(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	switch origin := r.Header.Get("Origin"); origin {
	case "":
		// Non-browser clients send neither header.
		return site == "" || site == "same-origin"
	case "null":
		// Browsers send "null" when a referrer policy hides the origin;
		// Sec-Fetch-Site still tells us where the request came from.
		return site == "same-origin"
	default:
		u, err := url.Parse(origin)
		return err == nil && s.hosts[u.Host]
	}
}

func (s *Server) checkCSRF(r *http.Request) bool {
	return subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) == 1
}

// Listen binds the loopback address, so callers can report a port clash
// before announcing that the UI is ready.
func Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// Serve runs the server on ln until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type page struct {
	Title    string
	Manifest *manifest.Payload
	Board    manifest.Board
	CSRF     string
	Mod      bool
	Peers    int
	Data     any
}

func (s *Server) page(title string) *page {
	return &page{
		Title: title, Manifest: s.node.Store.Manifest(), CSRF: s.csrf,
		Mod: s.mod != nil, Peers: s.node.PeerCount(),
	}
}

func (s *Server) render(w http.ResponseWriter, status int, name string, p *page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, p); err != nil {
		s.log.Error("render", "template", name, "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, status int, msg string) {
	p := s.page("Error")
	p.Data = msg
	s.render(w, status, "error.html", p)
}

func (s *Server) boardOf(w http.ResponseWriter, r *http.Request) (manifest.Board, bool) {
	b, ok := s.node.Store.Manifest().Board(r.PathValue("board"))
	if !ok {
		s.fail(w, http.StatusNotFound, "There is no such board.")
	}
	return b, ok
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	p := s.page("")
	p.Data = s.node.Store.Stats()
	s.render(w, http.StatusOK, "home.html", p)
}

type indexData struct {
	Threads []board.ThreadView
	Page    int
	Pages   []int
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	b, ok := s.boardOf(w, r)
	if !ok {
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("page"))
	threads, pages := s.node.Store.Page(b.ID, n, previewReplies)
	p := s.page("/" + b.ID + "/ - " + b.Title)
	p.Board = b
	p.Data = indexData{Threads: threads, Page: n, Pages: make([]int, max(pages, 1))}
	s.render(w, http.StatusOK, "index.html", p)
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	b, ok := s.boardOf(w, r)
	if !ok {
		return
	}
	p := s.page("/" + b.ID + "/ - Catalog")
	p.Board = b
	p.Data = s.node.Store.Catalog(b.ID)
	s.render(w, http.StatusOK, "catalog.html", p)
}

func (s *Server) thread(w http.ResponseWriter, r *http.Request) {
	b, ok := s.boardOf(w, r)
	if !ok {
		return
	}
	tv, ok := s.node.Store.Thread(r.PathValue("id"))
	if !ok || tv.OP == nil || tv.OP.Board != b.ID {
		s.fail(w, http.StatusNotFound, "This thread does not exist. It may have been deleted or fallen off the board.")
		return
	}
	title := tv.OP.Subject
	if title == "" {
		title = snippet(tv.OP.Body, 40)
	}
	p := s.page("/" + b.ID + "/ - " + title)
	p.Board = b
	p.Data = tv
	s.render(w, http.StatusOK, "thread.html", p)
}

func (s *Server) gotoPost(w http.ResponseWriter, r *http.Request) {
	b, ok := s.boardOf(w, r)
	if !ok {
		return
	}
	id, thread, ok := s.node.Store.Resolve(r.PathValue("id"))
	if !ok {
		s.fail(w, http.StatusNotFound, "That post is not on this node.")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/%s/thread/%s#p%s", b.ID, thread, board.ShortID(id)), http.StatusSeeOther)
}

func (s *Server) blob(w http.ResponseWriter, r *http.Request) {
	c := r.PathValue("cid")
	if !s.node.Store.Referenced(c) {
		http.NotFound(w, r)
		return
	}
	data, err := s.node.Blobs.Get(c)
	if err != nil || blob.Verify(c, data) != nil {
		http.Error(w, "image is still downloading", http.StatusNotFound)
		return
	}
	ct := http.DetectContentType(data)
	switch ct {
	case "image/jpeg", "image/png", "image/gif":
	default:
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Write(data)
}

func (s *Server) post(w http.ResponseWriter, r *http.Request) {
	b, ok := s.boardOf(w, r)
	if !ok {
		return
	}
	lim := s.node.Store.Manifest().Limits
	r.Body = http.MaxBytesReader(w, r.Body, lim.MaxImageBytes+256<<10)
	if err := r.ParseMultipartForm(lim.MaxImageBytes + 256<<10); err != nil {
		s.fail(w, http.StatusBadRequest, "The upload is too large or malformed. Images may be at most "+fmtSize(lim.MaxImageBytes)+".")
		return
	}
	if !s.checkCSRF(r) {
		s.fail(w, http.StatusForbidden, "The form expired. Go back, reload the page and try again.")
		return
	}
	p := &board.Post{
		Board:   b.ID,
		Thread:  r.FormValue("thread"),
		Subject: strings.TrimSpace(r.FormValue("subject")),
		Name:    strings.TrimSpace(r.FormValue("name")),
		Body:    strings.TrimRight(strings.ReplaceAll(r.FormValue("body"), "\r\n", "\n"), " \n"),
		Sage:    strings.EqualFold(strings.TrimSpace(r.FormValue("options")), "sage"),
		Time:    time.Now().Unix(),
	}
	if p.Name == "Anonymous" {
		p.Name = ""
	}
	var salt []byte
	if p.Thread != "" {
		p.Subject = ""
		if salt, ok = s.node.Store.ThreadSalt(p.Thread); !ok {
			s.fail(w, http.StatusNotFound, "The thread you replied to no longer exists.")
			return
		}
	}

	var stored []string
	if f, hdr, err := r.FormFile("file"); err == nil {
		data, err := io.ReadAll(io.LimitReader(f, lim.MaxImageBytes+1))
		f.Close()
		if err != nil {
			s.fail(w, http.StatusBadRequest, "Could not read the uploaded file.")
			return
		}
		res, err := media.Process(data, lim.MaxImageBytes)
		if err != nil {
			s.fail(w, http.StatusBadRequest, "Image rejected: "+err.Error()+".")
			return
		}
		full, err1 := s.node.Blobs.Put(res.Data)
		thumb, err2 := s.node.Blobs.Put(res.Thumb)
		if err := errors.Join(err1, err2); err != nil {
			s.fail(w, http.StatusInternalServerError, "Could not store the image.")
			return
		}
		stored = []string{full, thumb}
		p.Image = &board.ImageRef{
			CID: full, ThumbCID: thumb, Mime: res.Mime, Width: res.Width, Height: res.Height,
			Size: int64(len(res.Data)), Filename: cleanFilename(hdr.Filename),
		}
	} else if !errors.Is(err, http.ErrMissingFile) {
		s.fail(w, http.StatusBadRequest, "Could not read the uploaded file.")
		return
	}

	if err := p.Seal(s.poster, salt, lim.PoWBits); err != nil {
		s.fail(w, http.StatusInternalServerError, "Could not sign the post.")
		return
	}
	if err := p.Validate(s.node.Store.Manifest(), time.Now()); err != nil {
		s.dropBlobs(stored)
		s.fail(w, http.StatusBadRequest, "Post rejected: "+err.Error()+".")
		return
	}
	if err := s.node.PublishPost(r.Context(), p); err != nil {
		s.dropBlobs(stored)
		s.fail(w, http.StatusBadRequest, "Post rejected: "+err.Error()+".")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/%s/thread/%s#p%s", b.ID, p.ThreadID(), board.ShortID(p.ID())), http.StatusSeeOther)
}

func (s *Server) dropBlobs(cids []string) {
	for _, c := range cids {
		if !s.node.Store.Referenced(c) {
			s.node.Blobs.Delete(c)
		}
	}
}

func (s *Server) modDelete(w http.ResponseWriter, r *http.Request) {
	if s.mod == nil {
		s.fail(w, http.StatusForbidden, "This node has no moderator key.")
		return
	}
	if !s.checkCSRF(r) {
		s.fail(w, http.StatusForbidden, "The form expired. Go back, reload the page and try again.")
		return
	}
	id, thread, ok := s.node.Store.Resolve(r.FormValue("id"))
	if !ok {
		s.fail(w, http.StatusNotFound, "That post is not on this node.")
		return
	}
	pst, ok := s.node.Store.Post(id)
	if !ok {
		s.fail(w, http.StatusNotFound, "That post is not on this node.")
		return
	}
	reason := strings.ToValidUTF8(strings.TrimSpace(r.FormValue("reason")), "")
	ts := &board.Tombstone{Target: id, Board: pst.Board, Time: time.Now().Unix(), Reason: truncateUTF8(reason, board.MaxReason)}
	ts.Sign(s.mod)
	if err := s.node.PublishTombstone(r.Context(), ts); err != nil {
		s.fail(w, http.StatusInternalServerError, "Delete failed: "+err.Error())
		return
	}
	if id == thread {
		http.Redirect(w, r, "/"+pst.Board+"/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/%s/thread/%s", pst.Board, thread), http.StatusSeeOther)
}

type statusData struct {
	PeerID   string
	Addrs    []string
	Peers    []string
	AllConns int
	Stats    board.Stats
	Seq      uint64
	BlobSize string
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	h := s.node.Host()
	d := statusData{PeerID: h.ID().String(), Addrs: s.node.Addrs(), Stats: s.node.Store.Stats(), Seq: s.node.Manifest().Payload.Seq}
	for _, pid := range s.node.Members() {
		d.Peers = append(d.Peers, pid.String())
	}
	d.AllConns = s.node.AllPeerCount()
	if n, err := s.node.Blobs.Size(); err == nil {
		d.BlobSize = fmtSize(n)
	}
	p := s.page("Node status")
	p.Data = d
	s.render(w, http.StatusOK, "status.html", p)
}

func cleanFilename(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if r := []rune(name); len(r) > 100 {
		name = string(r[:100])
	}
	return name
}

// truncateUTF8 cuts s to at most n bytes without splitting a character.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func fmtTime(unix int64) string {
	return time.Unix(unix, 0).Format("01/02/06(Mon)15:04:05")
}

func fmtSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

func snippet(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func nl2br(s string) template.HTML {
	return template.HTML(strings.ReplaceAll(template.HTMLEscapeString(s), "\n", "<br>"))
}
