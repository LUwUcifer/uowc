package internal

import (
	"bytes"
	"html"
	"strings"
)

// This file extracts links from raw HTML with a single forward pass over the byte slice
// It follows the HTML tokenizer rules where they matter for finding links:
//
//   - comments, doctype, CDATA and processing instructions hold no links
//   - the contents of <script>, <style>, <textarea>, <title>, <iframe>, <xmp>,
//     <noembed> and <noframes> are text, not markup, and <plaintext> swallows
//     the rest of the document
//   - a '>' inside a quoted attribute value does not end the tag
//   - the first occurrence of a repeated attribute wins
//   - a tag cut off by the end of the input is discarded, never half-read
//
// The scanner is policy-free: it returns hrefs exactly as written (entity
// decoded, trimmed) and leaves resolving, filtering and deduplication to
// Sanitizer.Sanitize and the caller.

// DefaultMaxLinks caps the links returned per page when the caller passes a
// non-positive limit, so a link-bomb page cannot flood the frontier.
const DefaultMaxLinks = 5000

// LinkKind says where a link was found.
type LinkKind uint8

const (
	KindAnchor  LinkKind = iota + 1 // <a href>, <area href>
	KindFrame                       // <iframe src>, <frame src>
	KindPage                        // <link rel="next"> and <link rel="prev">
	KindRefresh                     // <meta http-equiv="refresh" content="N; url=...">
)

// Link is one extracted link. Href is entity-decoded and trimmed but still
// unresolved, so it can be relative.
type Link struct {
	Href     string
	Kind     LinkKind
	NoFollow bool // the element had rel="nofollow"
}

// Result is everything ExtractLinks learned about a page.
type Result struct {
	// Base is the first <base href>, or "". Resolve it against the page URL and
	// pass the result as the base argument of Sanitize.
	Base string
	// Canonical is the first <link rel="canonical" href>, or "".
	Canonical string
	// NoFollow is true when <meta name="robots"> says nofollow (or none). The
	// scan stops at that point and Links is nil: the page asked not to have its
	// links followed.
	NoFollow bool
	Links    []Link
}

// ExtractLinks scans body and returns its links in document order. maxLinks
// bounds the result; a value <= 0 means DefaultMaxLinks. It never panics and
// never reads past the end of body, whatever the input.
func ExtractLinks(body []byte, maxLinks int) Result {
	if maxLinks <= 0 {
		maxLinks = DefaultMaxLinks
	}
	e := extractor{b: body, max: maxLinks}
	e.res.Links = make([]Link, 0, 32)
	e.run()
	return e.res
}

type extractor struct {
	b       []byte
	i       int
	max     int
	done    bool // stop scanning: link limit reached or page said nofollow
	hasBase bool
	res     Result
}

var (
	commentOpen = []byte("<!--")
	cdataOpen   = []byte("<![CDATA[")
	cdataClose  = []byte("]]>")
	dashDash    = []byte("--")
)

// run is the top-level loop: jump to the next '<' and dispatch on what follows.
// Every branch advances e.i, so it always terminates.
func (e *extractor) run() {
	b := e.b
	for e.i < len(b) && !e.done {
		j := bytes.IndexByte(b[e.i:], '<')
		if j < 0 {
			return
		}
		e.i += j
		if e.i+1 >= len(b) {
			return
		}
		switch c := b[e.i+1]; {
		case c == '!':
			e.i = skipMarkup(b, e.i)
		case c == '?', c == '/':
			// Processing instruction or end tag: skip to the next '>'.
			e.i = skipPast(b, e.i+2, '>')
		case isLetter(c):
			e.startTag()
		default:
			e.i++ // a bare '<' in text, such as "a < b" or "3<4"
		}
	}
}

// startTag handles a start tag whose '<' is at e.i.
func (e *extractor) startTag() {
	b := e.b
	start := e.i + 1
	k := start
	for k < len(b) && !isTagNameEnd(b[k]) {
		k++
	}
	name := b[start:k]
	tag := classifyTag(name)

	var a tagAttrs
	next, closed := scanAttrs(b, k, tag.collects(), &a)
	if !closed {
		e.i = len(b) // cut off mid-tag: discard it and stop
		return
	}
	e.i = next

	switch tag {
	case tagA, tagArea:
		if a.hasHref {
			e.addAttr(KindAnchor, a.href, relHasToken(a.rel, "nofollow"))
		}
	case tagIframe:
		if a.hasSrc {
			e.addAttr(KindFrame, a.src, false)
		}
		e.skipRawText(name) // iframe content is text, not markup
	case tagFrame:
		if a.hasSrc {
			e.addAttr(KindFrame, a.src, false)
		}
	case tagBase:
		// The first <base> that has an href is the one that counts.
		if a.hasHref && !e.hasBase {
			e.hasBase = true
			e.res.Base = decodeAttr(trimBytes(a.href))
		}
	case tagLink:
		e.linkTag(&a)
	case tagMeta:
		e.metaTag(&a)
	case tagRaw:
		e.skipRawText(name)
	case tagPlaintext:
		e.i = len(b)
	default:
	}
}

func (e *extractor) linkTag(a *tagAttrs) {
	if !a.hasHref {
		return
	}
	if relHasToken(a.rel, "canonical") && e.res.Canonical == "" {
		e.res.Canonical = decodeAttr(trimBytes(a.href))
	}
	if relHasToken(a.rel, "next") || relHasToken(a.rel, "prev") {
		e.addAttr(KindPage, a.href, false)
	}
}

func (e *extractor) metaTag(a *tagAttrs) {
	if a.hasName && eqFold(a.name, "robots") && a.hasContent && robotsNoFollow(a.content) {
		e.res.NoFollow = true
		e.res.Links = nil
		e.done = true
		return
	}
	if a.hasHTTPEquiv && eqFold(a.httpEquiv, "refresh") && a.hasContent {
		if t := refreshTarget(decodeAttr(a.content)); t != "" && t[0] != '#' {
			e.push(Link{Href: t, Kind: KindRefresh})
		}
	}
}

// addAttr records a link taken from an attribute value. Empty and
// fragment-only hrefs point at the page itself and are dropped here; every
// other rejection (javascript:, mailto:, bad hosts...) is the sanitizer's job.
func (e *extractor) addAttr(kind LinkKind, v []byte, nofollow bool) {
	v = trimBytes(v)
	if len(v) == 0 || v[0] == '#' {
		return
	}
	e.push(Link{Href: decodeAttr(v), Kind: kind, NoFollow: nofollow})
}

func (e *extractor) push(l Link) {
	e.res.Links = append(e.res.Links, l)
	if len(e.res.Links) >= e.max {
		e.done = true
	}
}

// skipRawText moves e.i to the '<' of the matching end tag, or to the end of
// the input when there is none. The main loop then skips the end tag itself.
func (e *extractor) skipRawText(name []byte) {
	if idx := findCloseTag(e.b, e.i, name); idx >= 0 {
		e.i = idx
	} else {
		e.i = len(e.b)
	}
}

// ---------------------------------------------------------------------------
// Tag classification
// ---------------------------------------------------------------------------

type tagKind uint8

const (
	tagOther tagKind = iota
	// Tags whose attributes we read. Keep these contiguous: collects() relies
	// on the ordering.
	tagA
	tagArea
	tagIframe
	tagFrame
	tagBase
	tagLink
	tagMeta
	// Tags whose content is text, not markup.
	tagRaw
	tagPlaintext
)

func (t tagKind) collects() bool { return t >= tagA && t <= tagMeta }

func classifyTag(n []byte) tagKind {
	switch {
	case eqFold(n, "a"):
		return tagA
	case eqFold(n, "area"):
		return tagArea
	case eqFold(n, "iframe"):
		return tagIframe
	case eqFold(n, "frame"):
		return tagFrame
	case eqFold(n, "base"):
		return tagBase
	case eqFold(n, "link"):
		return tagLink
	case eqFold(n, "meta"):
		return tagMeta
	case eqFold(n, "script"), eqFold(n, "style"), eqFold(n, "textarea"), eqFold(n, "title"),
		eqFold(n, "xmp"), eqFold(n, "noembed"), eqFold(n, "noframes"):
		return tagRaw
	case eqFold(n, "plaintext"):
		return tagPlaintext
	}
	return tagOther
}

// ---------------------------------------------------------------------------
// Attribute scanning
// ---------------------------------------------------------------------------

// tagAttrs holds the attributes the scanner cares about. The has* flags make
// "first occurrence wins" exact even when the first value is empty.
type tagAttrs struct {
	href, src, rel, name, content, httpEquiv                   []byte
	hasHref, hasSrc, hasRel, hasName, hasContent, hasHTTPEquiv bool
}

func (a *tagAttrs) set(name, val []byte) {
	switch {
	case eqFold(name, "href"):
		if !a.hasHref {
			a.href, a.hasHref = val, true
		}
	case eqFold(name, "src"):
		if !a.hasSrc {
			a.src, a.hasSrc = val, true
		}
	case eqFold(name, "rel"):
		if !a.hasRel {
			a.rel, a.hasRel = val, true
		}
	case eqFold(name, "name"):
		if !a.hasName {
			a.name, a.hasName = val, true
		}
	case eqFold(name, "content"):
		if !a.hasContent {
			a.content, a.hasContent = val, true
		}
	case eqFold(name, "http-equiv"):
		if !a.hasHTTPEquiv {
			a.httpEquiv, a.hasHTTPEquiv = val, true
		}
	}
}

// scanAttrs reads attributes starting at i (just after the tag name) up to the
// closing '>'. It returns the index after the '>' and whether the tag was
// properly closed; closed is false if the input ended first. When collect is
// false the attributes are skipped, not stored.
func scanAttrs(b []byte, i int, collect bool, a *tagAttrs) (next int, closed bool) {
	n := len(b)
	for {
		// Skip whitespace and stray '/' (as in "<br/>" or "<a/href=x>").
		for i < n && (isHTMLSpace(b[i]) || b[i] == '/') {
			i++
		}
		if i >= n {
			return n, false
		}
		if b[i] == '>' {
			return i + 1, true
		}

		// Attribute name. The first byte is always part of the name, even '='.
		ns := i
		i++
		for i < n && !isAttrNameEnd(b[i]) {
			i++
		}
		name := b[ns:i]
		for i < n && isHTMLSpace(b[i]) {
			i++
		}

		var val []byte
		if i < n && b[i] == '=' {
			i++
			for i < n && isHTMLSpace(b[i]) {
				i++
			}
			if i >= n {
				return n, false
			}
			switch q := b[i]; q {
			case '"', '\'':
				end := bytes.IndexByte(b[i+1:], q)
				if end < 0 {
					return n, false // unterminated quote: cut off
				}
				val = b[i+1 : i+1+end]
				i += end + 2
			case '>':
				val = b[i:i] // "href=>": empty value, '>' ends the tag next
			default:
				vs := i
				for i < n && !isHTMLSpace(b[i]) && b[i] != '>' {
					i++
				}
				val = b[vs:i]
			}
		}
		if collect {
			a.set(name, val)
		}
	}
}

// findCloseTag returns the index of the '<' of the first "</name" at or after
// from that is followed by whitespace, '/', '>' or the end of input, comparing
// names case-insensitively. It returns -1 if there is none.
func findCloseTag(b []byte, from int, name []byte) int {
	for from < len(b) {
		j := bytes.IndexByte(b[from:], '<')
		if j < 0 {
			return -1
		}
		p := from + j
		q := p + 2 + len(name)
		if p+1 < len(b) && b[p+1] == '/' && q <= len(b) &&
			eqFoldBytes(b[p+2:q], name) && (q == len(b) || isTagNameEnd(b[q])) {
			return p
		}
		from = p + 1
	}
	return -1
}

// ---------------------------------------------------------------------------
// Skipping non-link markup
// ---------------------------------------------------------------------------

// skipMarkup skips a "<!" construct starting at i: a comment, CDATA section,
// doctype or other bogus comment, and returns the index just after it.
func skipMarkup(b []byte, i int) int {
	rest := b[i:]
	switch {
	case bytes.HasPrefix(rest, commentOpen):
		return skipComment(b, i+len(commentOpen))
	case bytes.HasPrefix(rest, cdataOpen):
		from := i + len(cdataOpen)
		if k := bytes.Index(b[from:], cdataClose); k >= 0 {
			return from + k + len(cdataClose)
		}
	}
	return skipPast(b, i+2, '>')
}

// skipComment returns the index after the end of a comment whose body starts
// at from. Besides "-->", HTML also ends a comment with "--!>", and "<!-->"
// and "<!--->" are complete (empty) comments.
func skipComment(b []byte, from int) int {
	if from < len(b) && b[from] == '>' {
		return from + 1
	}
	if from+1 < len(b) && b[from] == '-' && b[from+1] == '>' {
		return from + 2
	}
	for i := from; ; {
		k := bytes.Index(b[i:], dashDash)
		if k < 0 {
			return len(b)
		}
		p := i + k + 2 // just after the "--"
		if p < len(b) && b[p] == '>' {
			return p + 1
		}
		if p+1 < len(b) && b[p] == '!' && b[p+1] == '>' {
			return p + 2
		}
		i += k + 1 // retry one byte later so "--->" is still found
	}
}

// skipPast returns the index just after the next ch at or after from, or the
// end of the input if there is none.
func skipPast(b []byte, from int, ch byte) int {
	idx := bytes.IndexByte(b[from:], ch)
	if idx < 0 {
		return len(b)
	}
	return from + idx + 1
}

// ---------------------------------------------------------------------------
// Attribute values: rel, robots, refresh
// ---------------------------------------------------------------------------

// relHasToken reports whether the space-separated rel value contains token
// (lowercase), ignoring case.
func relHasToken(rel []byte, token string) bool {
	for len(rel) > 0 {
		for len(rel) > 0 && isHTMLSpace(rel[0]) {
			rel = rel[1:]
		}
		end := 0
		for end < len(rel) && !isHTMLSpace(rel[end]) {
			end++
		}
		if end > 0 && eqFold(rel[:end], token) {
			return true
		}
		rel = rel[end:]
	}
	return false
}

// robotsNoFollow reports whether a robots meta content value, a comma
// separated list such as "noindex, nofollow", asks for links to be ignored.
func robotsNoFollow(content []byte) bool {
	for len(content) > 0 {
		var tok []byte
		if c := bytes.IndexByte(content, ','); c >= 0 {
			tok, content = content[:c], content[c+1:]
		} else {
			tok, content = content, nil
		}
		tok = trimBytes(tok)
		if eqFold(tok, "nofollow") || eqFold(tok, "none") {
			return true
		}
	}
	return false
}

// refreshTarget extracts the URL from a meta refresh content value such as
// "5; url=/next", "0;URL='/next'" or "0,/next". It returns "" when the value
// is only a delay (a reload of the same page) or is malformed.
func refreshTarget(c string) string {
	i := skipSpaceStr(c, 0)
	start := i
	for i < len(c) && (c[i] >= '0' && c[i] <= '9' || c[i] == '.') {
		i++
	}
	if i == start || i >= len(c) {
		return ""
	}
	i = skipSpaceStr(c, i)
	if i < len(c) && (c[i] == ';' || c[i] == ',') {
		i++
	}
	i = skipSpaceStr(c, i)
	if len(c)-i >= 3 && strings.EqualFold(c[i:i+3], "url") {
		j := skipSpaceStr(c, i+3)
		if j >= len(c) || c[j] != '=' {
			return ""
		}
		i = skipSpaceStr(c, j+1)
	}
	if i < len(c) && (c[i] == '"' || c[i] == '\'') {
		q := c[i]
		i++
		if end := strings.IndexByte(c[i:], q); end >= 0 {
			return strings.TrimSpace(c[i : i+end])
		}
	}
	return strings.TrimSpace(c[i:])
}

func skipSpaceStr(s string, i int) int {
	for i < len(s) && isHTMLSpace(s[i]) {
		i++
	}
	return i
}

// ---------------------------------------------------------------------------
// Entity decoding for attribute values
// ---------------------------------------------------------------------------

// decodeAttr decodes HTML entities in an attribute value the way a browser
// does for URLs, which differs from html.UnescapeString.
//
// html.UnescapeString also decodes "legacy" entities that have no trailing
// semicolon, so "?a=1&region=us" becomes "?a=1®ion=us" (&reg), "&section=3"
// becomes "§ion=3" (&sect) and "&copy=2" becomes "©=2". Browsers deliberately
// do not decode those inside attribute values. This function decodes only
// references that end in ';' (&amp; &#38; &#x26; &copy;) and leaves every
// other '&' untouched.
//
// It uses html.UnescapeString purely as the entity table, on one small
// "&name;" candidate at a time. Rare gaps against browsers: a semicolon-less
// "&amp" and a semicolon-less numeric reference such as "&#38y" stay as
// written.
func decodeAttr(v []byte) string {
	if bytes.IndexByte(v, '&') < 0 {
		return string(v) // fast path: most hrefs contain no entity
	}
	var b strings.Builder
	b.Grow(len(v))
	for len(v) > 0 {
		i := bytes.IndexByte(v, '&')
		if i < 0 {
			b.Write(v)
			break
		}
		b.Write(v[:i])
		v = v[i:] // v[0] == '&'

		// Look for "&name;" or "&#digits;" within a short window.
		end := -1
		for j := 1; j < len(v) && j <= 32; j++ {
			c := v[j]
			if c == ';' {
				end = j
				break
			}
			if !(isAlnum(c) || (j == 1 && c == '#')) {
				break
			}
		}
		if end > 1 {
			// Unchanged by UnescapeString if it is not a known entity.
			b.WriteString(html.UnescapeString(string(v[:end+1])))
			v = v[end+1:]
		} else {
			b.WriteByte('&')
			v = v[1:]
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

func isHTMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func isTagNameEnd(c byte) bool { return isHTMLSpace(c) || c == '/' || c == '>' }

func isAttrNameEnd(c byte) bool { return isHTMLSpace(c) || c == '/' || c == '>' || c == '=' }

func isLetter(c byte) bool { c |= 0x20; return c >= 'a' && c <= 'z' }

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// eqFold reports whether a equals lit ignoring ASCII case. lit must already be
// lowercase. It allocates nothing.
func eqFold(a []byte, lit string) bool {
	if len(a) != len(lit) {
		return false
	}
	for i := range a {
		if lowerByte(a[i]) != lit[i] {
			return false
		}
	}
	return true
}

// eqFoldBytes reports whether a and b are equal ignoring ASCII case.
func eqFoldBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerByte(a[i]) != lowerByte(b[i]) {
			return false
		}
	}
	return true
}

// trimBytes strips leading and trailing spaces and control characters, the
// same set Sanitize trims.
func trimBytes(b []byte) []byte {
	for len(b) > 0 && b[0] <= 0x20 {
		b = b[1:]
	}
	for len(b) > 0 && b[len(b)-1] <= 0x20 {
		b = b[:len(b)-1]
	}
	return b
}
