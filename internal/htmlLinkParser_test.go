package internal

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func hrefs(r Result) []string {
	out := make([]string, len(r.Links))
	for i, l := range r.Links {
		out[i] = l.Href
	}
	return out
}

func TestExtractLinks(t *testing.T) {
	tests := []struct {
		name, doc string
		want      []string
	}{
		// Tags and attributes.
		{"quote styles", `<a href="/a">x</a><a href='/b'>y</a><a href=/c>z</a>`, []string{"/a", "/b", "/c"}},
		{"uppercase", `<A HREF="/up">x</A>`, []string{"/up"}},
		{"spaces around =", `<a  href = "/sp" >x</a>`, []string{"/sp"}},
		{"unquoted value keeps slash", `<a href=/foo/>x</a>`, []string{"/foo/"}},
		{"> inside quoted value", `<a title="a>b" href="/x">x</a>`, []string{"/x"}},
		{"first duplicate wins", `<a href="/first" href="/second">x</a>`, []string{"/first"}},
		{"slash instead of space", `<a/href="/slash">x</a>`, []string{"/slash"}},
		{"other attributes around", `<a data-x='1' class=btn href="/h" id=z>x</a>`, []string{"/h"}},
		{"no space after quote", `<a href="/q"class="c">x</a>`, []string{"/q"}},
		{"newline in tag", "<a\nhref=\"/nl\"\n>x</a>", []string{"/nl"}},

		// Things that are not markup.
		{"comment", `<!-- <a href="/c"> --><a href="/real">x</a>`, []string{"/real"}},
		{"empty comments", `<!--><a href="/e1"><!---><a href="/e2">`, []string{"/e1", "/e2"}},
		{"comment ended by --!>", `<!-- <a href="/h"> --!><a href="/after">`, []string{"/after"}},
		{"comment with extra dashes", `<!-- x ---><a href="/d">`, []string{"/d"}},
		{"conditional comment", `<!--[if IE]><a href="/ie"><![endif]-->`, nil},
		{"script body", `<script>var s = "<a href='/js'>";</script><a href="/ok">x</a>`, []string{"/ok"}},
		{"script not closed by </scripty>", `<script>x</scripty><a href="/hidden"></script><a href="/shown">`, []string{"/shown"}},
		{"script end tag with space", `<SCRIPT>"<a href=/x>"</SCRIPT ><a href=/y>`, []string{"/y"}},
		{"self-closing script still raw text", `<script src=x /><a href="/gone"></script><a href="/back">`, []string{"/back"}},
		{"style body", `<style>a{}</style><a href="/s">x</a>`, []string{"/s"}},
		{"textarea body", `<textarea><a href="/t"></textarea><a href="/u">x</a>`, []string{"/u"}},
		{"title body", `<title><a href="/ti"></title>`, nil},
		{"cdata", `<![CDATA[ <a href="/cd"> ]]><a href="/z">x</a>`, []string{"/z"}},
		{"processing instruction", `<?xml version="1.0"?><a href="/x">x</a>`, []string{"/x"}},
		{"doctype", `<!DOCTYPE html><a href="/d">x</a>`, []string{"/d"}},
		{"stray < in text", `a < b <a href="/lt">x</a> 3<4 <3`, []string{"/lt"}},
		{"end tag is skipped", `</a href="/e"><a href="/f">x</a>`, []string{"/f"}},
		{"plaintext swallows the rest", `<a href="/p1"><plaintext><a href="/p2">`, []string{"/p1"}},

		// Which elements count.
		{"area iframe frame", `<area href="/ar"><iframe src="/if"></iframe><frame src="/fr">`, []string{"/ar", "/if", "/fr"}},
		{"iframe content is text", `<iframe src="/if"><a href="/inside"></iframe><a href="/out">x</a>`, []string{"/if", "/out"}},
		{"img and script src are not links", `<img src="/i.png"><script src="/j.js"></script>`, nil},

		// Values.
		{"trimmed", `<a href="  /trim  ">x</a>`, []string{"/trim"}},
		{"empty and fragment-only skipped", `<a href="">a</a><a href="#top">b</a><a href="  #x ">c</a><a href>d</a><a href="/keep">e</a>`, []string{"/keep"}},
		{"valueless first duplicate", `<a href href="/x">x</a>`, nil},

		// Entities in href.
		{"amp entity", `<a href="/p?a=1&amp;b=2">x</a>`, []string{"/p?a=1&b=2"}},
		{"legacy entity name kept", `<a href="/p?a=1&copy=2&region=us&section=3">x</a>`, []string{"/p?a=1&copy=2&region=us&section=3"}},
		{"numeric entity", `<a href='/p?id=5&#38;x=1&#x26;y=2'>x</a>`, []string{"/p?id=5&x=1&y=2"}},
		{"entity with semicolon", `<a href="/&copy;">x</a>`, []string{"/©"}},

		// Truncated input.
		{"cut in value", `<a href="/ok">x</a><a href="/cut`, []string{"/ok"}},
		{"cut after name", `<a href="/ok">x</a><a`, []string{"/ok"}},
		{"cut after =", `<a href="/ok">x</a><a href=`, []string{"/ok"}},
		{"cut before >", `<a href="/ok">x</a><a href="/no"`, []string{"/ok"}},
		{"unclosed comment", `<a href="/ok">x</a><!-- <a href="/n">`, []string{"/ok"}},
		{"unclosed script", `<a href="/ok">x</a><script><a href="/n">`, []string{"/ok"}},
		{"lone <", `<a href="/ok">x</a><`, []string{"/ok"}},
		{"empty input", ``, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hrefs(ExtractLinks([]byte(tc.doc), 0))
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBase(t *testing.T) {
	tests := []struct{ name, doc, want string }{
		{"first wins", `<base href="http://cdn.x/"><base href="http://other/">`, "http://cdn.x/"},
		{"skips base without href", `<base target="_blank"><base href="/b/">`, "/b/"},
		{"entity decoded", `<base href="/b?a=1&amp;b=2">`, "/b?a=1&b=2"},
		{"none", `<a href="/x">x</a>`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractLinks([]byte(tc.doc), 0).Base; got != tc.want {
				t.Errorf("Base = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRelAndLinkTags(t *testing.T) {
	r := ExtractLinks([]byte(`
		<link rel=canonical href="/canon"><link rel="canonical" href="/second">
		<link rel="next" href="/page2"><link rel="alternate PREV" href="/page0">
		<link rel="stylesheet" href="/s.css"><link rel="icon" href="/i.ico">
		<a rel="nofollow" href="/n">a</a>
		<a rel="noopener NoFollow" href="/n2">b</a>
		<a rel="nofollowx" href="/n3">c</a>
		<a href="/plain">d</a>`), 0)

	if r.Canonical != "/canon" {
		t.Errorf("Canonical = %q, want /canon", r.Canonical)
	}
	want := []Link{
		{"/page2", KindPage, false},
		{"/page0", KindPage, false},
		{"/n", KindAnchor, true},
		{"/n2", KindAnchor, true},
		{"/n3", KindAnchor, false},
		{"/plain", KindAnchor, false},
	}
	if !slices.Equal(r.Links, want) {
		t.Errorf("links = %+v\nwant    %+v", r.Links, want)
	}
}

func TestMetaRobots(t *testing.T) {
	tests := []struct {
		name, meta string
		noFollow   bool
	}{
		{"nofollow", `<meta name="robots" content="index, NoFollow">`, true},
		{"none", `<meta name="robots" content="none">`, true},
		{"case of name", `<meta NAME="Robots" content="nofollow">`, true},
		{"noindex only", `<meta name="robots" content="noindex">`, false},
		{"similar word", `<meta name="robots" content="nofollowx">`, false},
		{"other meta", `<meta name="description" content="nofollow">`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := ExtractLinks([]byte(tc.meta+`<a href="/x">x</a>`), 0)
			if r.NoFollow != tc.noFollow {
				t.Errorf("NoFollow = %v, want %v", r.NoFollow, tc.noFollow)
			}
			if tc.noFollow && r.Links != nil {
				t.Errorf("links should be dropped, got %+v", r.Links)
			}
			if !tc.noFollow && !slices.Equal(hrefs(r), []string{"/x"}) {
				t.Errorf("links = %q, want [/x]", hrefs(r))
			}
		})
	}
}

func TestMetaRefresh(t *testing.T) {
	tests := []struct{ name, content, want string }{
		{"url=", `0; url=/r1`, "/r1"},
		{"quoted, upper case", `5;URL='/r2'`, "/r2"},
		{"comma", `0,/r3`, "/r3"},
		{"no separator word", `3; /r4`, "/r4"},
		{"spaces", `  2 ;  url = /r5 `, "/r5"},
		{"delay only", `3`, ""},
		{"url without =", `0; url /r6`, ""},
		{"fragment only", `0; url=#x`, ""},
		{"no delay", `url=/r7`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf(`<meta http-equiv="Refresh" content="%s">`, tc.content)
			r := ExtractLinks([]byte(doc), 0)
			if tc.want == "" {
				if len(r.Links) != 0 {
					t.Errorf("want no link, got %+v", r.Links)
				}
				return
			}
			want := []Link{{tc.want, KindRefresh, false}}
			if !slices.Equal(r.Links, want) {
				t.Errorf("got %+v, want %+v", r.Links, want)
			}
		})
	}
}

func TestMaxLinks(t *testing.T) {
	doc := []byte(strings.Repeat(`<a href="/x">x</a>`, 10))
	if got := len(ExtractLinks(doc, 3).Links); got != 3 {
		t.Errorf("max 3: got %d links", got)
	}
	big := []byte(strings.Repeat(`<a href="/x">x</a>`, DefaultMaxLinks+50))
	if got := len(ExtractLinks(big, 0).Links); got != DefaultMaxLinks {
		t.Errorf("default max: got %d links, want %d", got, DefaultMaxLinks)
	}
}

// Cutting a page short must never invent links: everything found in a prefix
// of the document has to be found in the whole document too.
func TestPrefixesNeverInventLinks(t *testing.T) {
	doc := `<!DOCTYPE html><html><head><base href="/b/"><title>t <a href="/title"></title>
<link rel=next href="/n"><style>a{}</style><script>var x="<a href='/js'>";</script></head>
<body><!-- <a href="/c"> --><a href="/one" rel=nofollow>1</a><a title="a>b" href='/two?x=1&amp;y=2'>2</a>
<A HREF=/three/>3</A><area href="/area"><iframe src="/f"><a href="/in"></iframe><textarea><a href="/ta"></textarea>
<![CDATA[ <a href="/cd"> ]]><a/href="/four">4</a><meta http-equiv=refresh content="0; url=/ref"></body></html>`
	full := ExtractLinks([]byte(doc), 0)
	if len(full.Links) < 6 {
		t.Fatalf("sample document should yield several links, got %q", hrefs(full))
	}
	for n := 0; n <= len(doc); n++ {
		part := ExtractLinks([]byte(doc[:n]), 0)
		for _, l := range part.Links {
			if !slices.Contains(full.Links, l) {
				t.Fatalf("prefix of %d bytes invented link %+v", n, l)
			}
		}
	}
}

func TestDecodeAttr(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/p?a=1&amp;b=2", "/p?a=1&b=2"},
		{"/p?id=5&#38;y=1", "/p?id=5&y=1"},
		{"/p?id=5&#x26;y=1", "/p?id=5&y=1"},
		{"/p?a=1&copy=2", "/p?a=1&copy=2"},
		{"/p?a=1&region=us", "/p?a=1&region=us"},
		{"/p?a=1&section=3", "/p?a=1&section=3"},
		{"/p?a=1&notify=1", "/p?a=1&notify=1"},
		{"/p?a=1&currency=usd", "/p?a=1&currency=usd"},
		{"/p?a=1&timestamp=9", "/p?a=1&timestamp=9"},
		{"/p?a=1&parameter=x", "/p?a=1&parameter=x"},
		{"/p?a=1&b=2", "/p?a=1&b=2"},
		{"/p?a=1&&b=2&", "/p?a=1&&b=2&"},
		{"/p?x=&copy;y", "/p?x=©y"},
		{"/p?x=&unknownname;y", "/p?x=&unknownname;y"},
		{"/no/entities", "/no/entities"},
		{"&", "&"},
		{"&;", "&;"},
		{"&#;", "&#;"},
	}
	for _, tc := range tests {
		if got := decodeAttr([]byte(tc.in)); got != tc.want {
			t.Errorf("decodeAttr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func FuzzExtractLinks(f *testing.F) {
	for _, s := range []string{
		`<a href="/x">x</a>`, `<!-- <a href=x> -->`, `<script><a href=x></script>`,
		`<a title="a>b" href='/y'>`, `<meta http-equiv=refresh content="0;url=/z">`,
		`<base href=/b><link rel=next href=/n>`, `<a href="/p?a=1&copy=2&amp;b">`,
		`<![CDATA[x]]><?pi?></x><plaintext>`, "<a\x00href=\"/\xff\">", `<`, `<a`, `<a href=`,
	} {
		f.Add([]byte(s), 3)
	}
	f.Fuzz(func(t *testing.T, body []byte, max int) {
		if max > 50 {
			max = 50
		}
		r := ExtractLinks(body, max)
		limit := max
		if limit <= 0 {
			limit = DefaultMaxLinks
		}
		if len(r.Links) > limit {
			t.Fatalf("%d links exceeds limit %d", len(r.Links), limit)
		}
		for _, l := range r.Links {
			if l.Href == "" || l.Kind == 0 {
				t.Fatalf("bad link %+v", l)
			}
			if l.Kind != KindRefresh && l.Href[0] == '#' {
				t.Fatalf("fragment-only href kept: %+v", l)
			}
		}
		if r.NoFollow && r.Links != nil {
			t.Fatalf("nofollow page returned links")
		}
	})
}

func BenchmarkExtractLinks(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html><head><title>Bench</title><link rel="canonical" href="https://example.com/p">`)
	sb.WriteString(`<style>`)
	sb.WriteString(strings.Repeat(`.a{color:red;margin:0} `, 400))
	sb.WriteString(`</style><script>`)
	sb.WriteString(strings.Repeat(`var s = "<a href='/not-a-link'>"; `, 300))
	sb.WriteString(`</script></head><body>`)
	for i := range 400 {
		fmt.Fprintf(&sb, `<div class="item c%d"><p>Some text <b>here</b> and there, 3 < 4.</p>`, i)
		fmt.Fprintf(&sb, `<a class="link" href="/page/%d?sort=asc&amp;ref=nav" rel="noopener">Page %d</a>`, i, i)
		sb.WriteString(`<img src="/i.png" alt="x"><!-- a comment with <a href="/hidden"> --></div>`)
	}
	sb.WriteString(`</body></html>`)
	page := []byte(sb.String())

	b.SetBytes(int64(len(page)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r := ExtractLinks(page, 0); len(r.Links) != 400 {
			b.Fatalf("got %d links", len(r.Links))
		}
	}
}
