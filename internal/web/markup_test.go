package web

import (
	"strings"
	"testing"
)

func TestRenderBody(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "hello"},
		{">implying", `<span class="greentext">&gt;implying</span>`},
		{">>abcdefghij", `<a class="quotelink" href="/linux/post/abcdefghij" data-id="abcdefghij">&gt;&gt;abcdefghij</a>`},
		{"a\nb", "a<br>b"},
		{"[spoiler]x[/spoiler]", `<span class="spoiler">x</span>`},
		{"[code]\nif a < b {}\n[/code]", `<pre class="code">if a &lt; b {}</pre>`},
		{"see https://kernel.org/x", `see <span class="url">https://kernel.org/x</span>`},
	}
	for _, c := range cases {
		if got := string(renderBody(c.in, "linux")); got != c.want {
			t.Errorf("renderBody(%q)\n got %s\nwant %s", c.in, got, c.want)
		}
	}
}

func TestRenderBodyEscapes(t *testing.T) {
	attacks := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`[spoiler]<b onmouseover=x>[/spoiler]`,
		`[code]</pre><script>x</script>[/code]`,
		`>>abcdefghij" onmouseover="x`,
		`https://a.b/"><script>`,
		`[spoiler][code]<x>[/code][/spoiler]`,
	}
	for _, a := range attacks {
		out := string(renderBody(a, "linux"))
		for _, bad := range []string{"<script", "<img", "<b ", "\" onmouseover", "<x>"} {
			if strings.Contains(out, bad) {
				t.Errorf("renderBody(%q) produced %q", a, out)
			}
		}
	}
}

func FuzzRenderBody(f *testing.F) {
	f.Add("[code]<a>[/code] >x >>abcdefgh [spoiler]<i>[/spoiler]")
	f.Fuzz(func(t *testing.T, s string) {
		out := string(renderBody(s, "linux"))
		// Every '<' in the output must start one of our own tags.
		for i := 0; i < len(out); i++ {
			if out[i] != '<' {
				continue
			}
			rest := out[i:]
			ok := false
			for _, tag := range []string{"<br>", `<pre class="code">`, "</pre>", `<span class="`, "</span>", `<a class="quotelink" href="/linux/post/`, "</a>"} {
				if strings.HasPrefix(rest, tag) {
					ok = true
					break
				}
			}
			if !ok {
				t.Fatalf("unexpected tag in output %q for input %q", rest, s)
			}
		}
	})
}
