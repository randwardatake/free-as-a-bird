package web

import (
	"html"
	"html/template"
	"regexp"
	"strings"
)

// Post formatting. The body is HTML-escaped before any markup is applied,
// so the only tags in the output are the ones produced here.
//
//	>text            greentext line
//	>>id             link to a post (short or full id)
//	[spoiler]x[/spoiler]
//	[code]...[/code] preformatted block, may span lines

var (
	codeRe    = regexp.MustCompile(`(?s)\[code\](.*?)\[/code\]`)
	quoteRe   = regexp.MustCompile(`&gt;&gt;([a-z2-7]{6,52})`)
	spoilerRe = regexp.MustCompile(`\[spoiler\](.*?)\[/spoiler\]`)
	urlRe     = regexp.MustCompile(`https?://[^\s<>"']+`)
)

// renderBody converts a post body to safe HTML. board is used to build
// quote links.
func renderBody(body, board string) template.HTML {
	var b strings.Builder
	last := 0
	for _, m := range codeRe.FindAllStringSubmatchIndex(body, -1) {
		renderText(&b, body[last:m[0]], board)
		b.WriteString(`<pre class="code">`)
		b.WriteString(html.EscapeString(strings.Trim(body[m[2]:m[3]], "\n")))
		b.WriteString(`</pre>`)
		last = m[1]
	}
	renderText(&b, body[last:], board)
	return template.HTML(b.String())
}

func renderText(b *strings.Builder, text, board string) {
	text = strings.Trim(text, "\n")
	if text == "" {
		return
	}
	for i, line := range strings.Split(text, "\n") {
		if i > 0 {
			b.WriteString("<br>")
		}
		esc := html.EscapeString(line)
		esc = urlRe.ReplaceAllStringFunc(esc, func(u string) string {
			// Links are shown, not clickable: following them would leave
			// the local node and reveal the reader's address to that site.
			return `<span class="url">` + u + `</span>`
		})
		esc = quoteRe.ReplaceAllString(esc, `<a class="quotelink" href="/`+board+`/post/$1" data-id="$1">&gt;&gt;$1</a>`)
		esc = spoilerRe.ReplaceAllString(esc, `<span class="spoiler">$1</span>`)
		if strings.HasPrefix(esc, "&gt;") && !strings.HasPrefix(esc, "&gt;&gt;") {
			esc = `<span class="greentext">` + esc + `</span>`
		}
		b.WriteString(esc)
	}
}
