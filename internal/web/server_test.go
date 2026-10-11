package web

import (
	"bytes"
	"image"
	"image/png"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/randwardatake/free-as-a-bird/internal/keys"
	"github.com/randwardatake/free-as-a-bird/internal/manifest"
	"github.com/randwardatake/free-as-a-bird/internal/node"
)

const addr = "127.0.0.1:8099"

func newServer(t *testing.T, withMod bool) *Server {
	t.Helper()
	maint, _ := keys.Generate()
	mod, _ := keys.Generate()
	l := manifest.DefaultLimits
	l.PoWBits = 4
	m := &manifest.Signed{Payload: manifest.Payload{
		Network: "webtest", Seq: 1, Threshold: 1,
		Maintainers: []keys.PublicKey{keys.Public(maint)},
		Moderators:  []keys.PublicKey{keys.Public(mod)},
		Boards:      []manifest.Board{{ID: "linux", Title: "Linux"}},
		Limits:      l,
	}}
	m.Sign(maint)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, node.ManifestFile), m.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	n, err := node.New(node.Config{DataDir: dir, ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	poster, _ := keys.Generate()
	cfg := Config{Addr: addr, PosterKey: poster, Logger: quiet}
	if withMod {
		cfg.ModKey = mod
	}
	s, err := New(n, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func do(s *Server, r *http.Request) *httptest.ResponseRecorder {
	if r.Host == "example.com" {
		r.Host = addr
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func pngBytes() []byte {
	var buf bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 20, 20))
	for i := range img.Pix {
		img.Pix[i] = 200
	}
	png.Encode(&buf, img)
	return buf.Bytes()
}

func postForm(t *testing.T, s *Server, fields map[string]string, file []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	if file != nil {
		fw, _ := mw.CreateFormFile("file", "../../etc/evil name.png")
		fw.Write(file)
	}
	mw.Close()
	r := httptest.NewRequest("POST", "/linux/post", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "http://"+addr)
	return r
}

func TestHostAndOriginChecks(t *testing.T) {
	s := newServer(t, false)
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "attacker.example:8099"
	if w := do(s, r); w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign Host: %d", w.Code)
	}
	w := do(s, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("home: %d csp=%q", w.Code, w.Header().Get("Content-Security-Policy"))
	}

	req := postForm(t, s, map[string]string{"csrf": s.csrf, "body": "x"}, nil)
	req.Header.Set("Origin", "https://attacker.example")
	if w := do(s, req); w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin post: %d", w.Code)
	}
	if w := do(s, postForm(t, s, map[string]string{"csrf": "wrong", "body": "x"}, nil)); w.Code != http.StatusForbidden {
		t.Fatalf("bad csrf: %d", w.Code)
	}
}

func TestCreateThreadReplyAndRender(t *testing.T) {
	s := newServer(t, false)
	w := do(s, postForm(t, s, map[string]string{"csrf": s.csrf, "subject": "First", "body": ">green\n<script>x</script>"}, pngBytes()))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create thread: %d %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	threadID := regexp.MustCompile(`/thread/([a-z2-7]+)`).FindStringSubmatch(loc)[1]

	w = do(s, postForm(t, s, map[string]string{"csrf": s.csrf, "thread": threadID, "body": "reply"}, nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("reply: %d %s", w.Code, w.Body.String())
	}
	page := do(s, httptest.NewRequest("GET", "/linux/thread/"+threadID, nil)).Body.String()
	for _, want := range []string{`class="subject">First`, `class="greentext">&gt;green`, `&lt;script&gt;`, "reply", `>evil name.png<`} {
		if !strings.Contains(page, want) {
			t.Errorf("thread page missing %q", want)
		}
	}
	if strings.Contains(page, "<script>x") {
		t.Error("unescaped script in page")
	}
	if strings.Contains(page, `action="/mod/delete"`) {
		t.Error("delete buttons shown without a moderator key")
	}
	thumb := regexp.MustCompile(`img src="(/blob/[a-z0-9]+)"`).FindStringSubmatch(page)[1]
	if w := do(s, httptest.NewRequest("GET", thumb, nil)); w.Code != 200 || w.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatalf("thumbnail: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if w := do(s, httptest.NewRequest("GET", "/blob/bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy", nil)); w.Code != 404 {
		t.Fatalf("unreferenced blob served: %d", w.Code)
	}
}

func TestThreadNeedsImage(t *testing.T) {
	s := newServer(t, false)
	w := do(s, postForm(t, s, map[string]string{"csrf": s.csrf, "body": "no image"}, nil))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "needs an image") {
		t.Fatalf("thread without image: %d", w.Code)
	}
}

func TestModeratorDelete(t *testing.T) {
	s := newServer(t, true)
	w := do(s, postForm(t, s, map[string]string{"csrf": s.csrf, "body": "bad"}, pngBytes()))
	threadID := regexp.MustCompile(`/thread/([a-z2-7]+)`).FindStringSubmatch(w.Header().Get("Location"))[1]
	page := do(s, httptest.NewRequest("GET", "/linux/thread/"+threadID, nil)).Body.String()
	if !strings.Contains(page, `action="/mod/delete"`) {
		t.Fatal("no delete button in moderator mode")
	}
	form := strings.NewReader("csrf=" + s.csrf + "&id=" + threadID + "&reason=test")
	r := httptest.NewRequest("POST", "/mod/delete", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://"+addr)
	if w := do(s, r); w.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if w := do(s, httptest.NewRequest("GET", "/linux/thread/"+threadID, nil)); w.Code != 404 {
		t.Fatalf("deleted thread still shown: %d", w.Code)
	}
}

func TestReservedAndUnknownPaths(t *testing.T) {
	s := newServer(t, false)
	for path, code := range map[string]int{
		"/static/style.css": 200, "/static/app.js": 200, "/status": 200,
		"/nope/": 404, "/linux/": 200, "/linux/catalog": 200, "/linux/thread/zzz": 404,
	} {
		if w := do(s, httptest.NewRequest("GET", path, nil)); w.Code != code {
			t.Errorf("GET %s: %d, want %d", path, w.Code, code)
		}
	}
}

func TestCleanFilename(t *testing.T) {
	for in, want := range map[string]string{
		"../../etc/passwd":    "passwd",
		`C:\Users\me\cat.png`: "cat.png",
		"a\x01b\nc.png":       "abc.png",
		"plain.gif":           "plain.gif",
	} {
		if got := cleanFilename(in); got != want {
			t.Errorf("cleanFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// Browsers send "Origin: null" on form posts when the page's referrer policy
// is no-referrer, so the check must fall back to Sec-Fetch-Site.
func TestOriginNullFromBrowser(t *testing.T) {
	s := newServer(t, false)
	cases := []struct {
		origin, site string
		want         int
	}{
		{"null", "same-origin", http.StatusSeeOther},
		{"null", "cross-site", http.StatusForbidden},
		{"null", "", http.StatusForbidden},
		{"http://" + addr, "same-origin", http.StatusSeeOther},
	}
	for _, c := range cases {
		r := postForm(t, s, map[string]string{"csrf": s.csrf, "subject": "x", "body": "x"}, pngBytes())
		r.Header.Set("Origin", c.origin)
		if c.site != "" {
			r.Header.Set("Sec-Fetch-Site", c.site)
		}
		if w := do(s, r); w.Code != c.want {
			t.Errorf("Origin %q, Sec-Fetch-Site %q: got %d, want %d", c.origin, c.site, w.Code, c.want)
		}
	}
}

// A reason cut at the byte limit must not split a character, or the
// tombstone fails validation and the delete is refused.
func TestModeratorDeleteMultibyteReason(t *testing.T) {
	s := newServer(t, true)
	w := do(s, postForm(t, s, map[string]string{"csrf": s.csrf, "body": "bad"}, pngBytes()))
	threadID := regexp.MustCompile(`/thread/([a-z2-7]+)`).FindStringSubmatch(w.Header().Get("Location"))[1]
	reason := strings.Repeat("a", 199) + "ş" // 201 bytes; byte 200 is inside "ş"
	form := strings.NewReader("csrf=" + s.csrf + "&id=" + threadID + "&reason=" + url.QueryEscape(reason))
	r := httptest.NewRequest("POST", "/mod/delete", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://"+addr)
	if w := do(s, r); w.Code != http.StatusSeeOther {
		t.Fatalf("delete with multibyte reason: %d %s", w.Code, w.Body.String())
	}
}

func TestTruncateUTF8(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc"},
		{"abc", 2, "ab"},
		{"aş", 2, "a"},
		{"şş", 3, "ş"},
		{"ş", 1, ""},
	} {
		if got := truncateUTF8(c.in, c.n); got != c.want {
			t.Errorf("truncateUTF8(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}
