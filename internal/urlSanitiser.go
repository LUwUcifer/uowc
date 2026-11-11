package internal

import (
	"errors"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Reasons a link is rejected. Callers can use errors.Is to count rejections
// per reason for metrics (for example, a spike in ErrTrap marks a bad host).
var (
	ErrEmpty            = errors.New("url: empty or fragment-only")
	ErrTooLong          = errors.New("url: too long")
	ErrControlChars     = errors.New("url: control characters")
	ErrParse            = errors.New("url: unparseable")
	ErrNoBase           = errors.New("url: relative link without a valid base")
	ErrScheme           = errors.New("url: scheme is not http or https")
	ErrHost             = errors.New("url: invalid host")
	ErrPrivateHost      = errors.New("url: private, local or reserved host")
	ErrPort             = errors.New("url: invalid port")
	ErrSkippedExtension = errors.New("url: non-HTML file extension")
	ErrTrap             = errors.New("url: looks like a crawler trap")
)

type SanitizerConfig struct {
	MaxURLLength      int
	MaxPathSegments   int // deeper paths are treated as traps
	MaxSegmentRepeat  int // a segment appearing more often than this is a trap
	MaxQueryParams    int // more parameters than this is a trap
	AllowPrivateHosts bool

	// SkipExtensions lists lowercase extensions without the dot. nil means the
	// built-in list (isDefaultSkippedExt); pass an empty non-nil map to disable
	// extension filtering.
	SkipExtensions map[string]struct{}
}

func DefaultSanitizerConfig() SanitizerConfig {
	return SanitizerConfig{
		MaxURLLength:     2048,
		MaxPathSegments:  30,
		MaxSegmentRepeat: 3,
		MaxQueryParams:   20,
	}
}

// Sanitizer is immutable after construction and safe for concurrent use.
type Sanitizer struct {
	cfg SanitizerConfig
}

func NewSanitizer(cfg SanitizerConfig) *Sanitizer {
	d := DefaultSanitizerConfig()
	if cfg.MaxURLLength <= 0 {
		cfg.MaxURLLength = d.MaxURLLength
	}
	if cfg.MaxPathSegments <= 0 {
		cfg.MaxPathSegments = d.MaxPathSegments
	}
	if cfg.MaxSegmentRepeat <= 0 {
		cfg.MaxSegmentRepeat = d.MaxSegmentRepeat
	}
	if cfg.MaxQueryParams <= 0 {
		cfg.MaxQueryParams = d.MaxQueryParams
	}
	return &Sanitizer{cfg: cfg}
}

// skipExt reports whether a lowercase extension should be skipped. A nil
// config map means the built-in list.
func (s *Sanitizer) skipExt(ext string) bool {
	if s.cfg.SkipExtensions != nil {
		_, ok := s.cfg.SkipExtensions[ext]
		return ok
	}
	return isDefaultSkippedExt(ext)
}

// Sanitize resolves raw against base (which may be nil if raw is absolute)
// and returns the canonical URL plus its host key ("host" or "host:port"),
// which is what per-host queues and rate limiters should key on.
//
// Output is idempotent: sanitizing a canonical URL returns it unchanged.
// raw must already be HTML-entity decoded (the link scanner's job).
func (s *Sanitizer) Sanitize(base *url.URL, raw string) (canonical, hostKey string, err error) {
	// 1. Whitespace and control characters, as browsers treat them.
	raw = strings.TrimFunc(raw, func(r rune) bool {
		//0x00 - 0x20 are control characters (NUL, Tab, Space)
		return r <= 0x20
	})
	raw = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, raw)
	if raw == "" || raw[0] == '#' {
		return "", "", ErrEmpty
	}
	if len(raw) > s.cfg.MaxURLLength {
		return "", "", ErrTooLong
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "", "", ErrControlChars
		}
	}

	// 2. Backslashes before the query act as slashes in browsers.
	raw = fixBackslashes(raw)

	// 3. Parse, then branch on the link's own scheme. Each case validates the
	// scheme of the URL it ends up using, so no re-check is needed afterwards.
	ref, perr := url.Parse(raw)
	if perr != nil {
		return "", "", ErrParse
	}
	var u *url.URL
	switch ref.Scheme {
	case "http", "https":
		// Absolute link: it stands alone and the base is not needed.
		u = ref
	case "":
		// Relative link (path-relative, root-relative, query-only or
		// scheme-relative): resolve it against the page it was found on.
		if base == nil || (base.Scheme != "http" && base.Scheme != "https") {
			return "", "", ErrNoBase
		}
		u = base.ResolveReference(ref)
	default:
		// javascript:, mailto:, tel:, data:, ftp: and friends.
		return "", "", ErrScheme
	}
	if u.Opaque != "" {
		return "", "", ErrParse // e.g. "http:foo"
	}

	// 5. Host: lowercase, strip credentials and the trailing dot, validate.
	host, herr := s.checkHost(strings.ToLower(u.Hostname()))
	if herr != nil {
		return "", "", herr
	}

	// 6. Port: validate range, drop the default.
	hostKey = host
	if p := u.Port(); p != "" {
		n, aerr := strconv.Atoi(p)
		if aerr != nil || n < 1 || n > 65535 {
			return "", "", ErrPort
		}
		//port 80 is default for http, 443 for https, others point to different ports/pages
		isDefault := (u.Scheme == "http" && n == 80) || (u.Scheme == "https" && n == 443)
		if !isDefault {
			hostKey = host + ":" + strconv.Itoa(n)
		}
	}

	// 7. Path and query. The fragment is dropped by never copying it.
	path, perr2 := s.cleanPath(u.EscapedPath())
	if perr2 != nil {
		return "", "", perr2
	}
	query, qerr := s.cleanQuery(u.RawQuery)
	if qerr != nil {
		return "", "", qerr
	}

	var b strings.Builder
	b.Grow(len(u.Scheme) + 3 + len(hostKey) + len(path) + 1 + len(query))
	b.WriteString(u.Scheme)
	b.WriteString("://")
	b.WriteString(hostKey)
	b.WriteString(path)
	if query != "" {
		b.WriteByte('?')
		b.WriteString(query)
	}
	canonical = b.String()
	if len(canonical) > s.cfg.MaxURLLength {
		return "", "", ErrTooLong
	}
	return canonical, hostKey, nil
}

func fixBackslashes(raw string) string {
	end := strings.IndexAny(raw, "?#")
	if end < 0 {
		end = len(raw)
	}
	if !strings.Contains(raw[:end], `\`) {
		return raw
	}
	return strings.ReplaceAll(raw[:end], `\`, "/") + raw[end:]
}

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10")

	privateSuffixes = []string{
		".localhost", ".local", ".internal", ".lan", ".localdomain", ".home.arpa", ".corp",
	}
)

// checkHost validates an already lowercased hostname and returns its
// canonical form (IPv6 literals come back bracketed).
func (s *Sanitizer) checkHost(h string) (string, error) {
	if h == "" {
		return "", ErrHost
	}

	// IPv6 literal.
	if strings.Contains(h, ":") {
		addr, err := netip.ParseAddr(h)
		if err != nil || addr.Zone() != "" {
			return "", ErrHost
		}
		//If IP Addr is IPv6 wrapping of IPv4, return IPv4
		addr = addr.Unmap()
		if !s.cfg.AllowPrivateHosts && !isPublicAddr(addr) {
			return "", ErrPrivateHost
		}
		if addr.Is4() {
			return addr.String(), nil
		}
		return "[" + addr.String() + "]", nil
	}

	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return "", ErrHost
	}
	// Plain ASCII only. This rejects non-ASCII (IDN) hosts
	//Todo: Implement IDN hosts
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'
		if !ok {
			return "", ErrHost
		}
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", ErrHost
		}
	}

	// A numeric last label means the host is meant as an IP address. Only
	// strict dotted-quad IPv4 is accepted, which rejects decimal, octal and
	// hex tricks such as 2130706433, 0177.0.0.1 and 0x7f.0.0.1.
	last := labels[len(labels)-1]
	if allDigits(last) || strings.HasPrefix(last, "0x") {
		addr, err := netip.ParseAddr(h)
		if err != nil || !addr.Is4() {
			return "", ErrHost
		}
		if !s.cfg.AllowPrivateHosts && !isPublicAddr(addr) {
			return "", ErrPrivateHost
		}
		return addr.String(), nil
	}

	if !s.cfg.AllowPrivateHosts {
		if len(labels) < 2 { // single-label intranet names
			return "", ErrPrivateHost
		}
		if h == "localhost" {
			return "", ErrPrivateHost
		}
		for _, suf := range privateSuffixes {
			if strings.HasSuffix(h, suf) {
				return "", ErrPrivateHost
			}
		}
	}
	return h, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isPublicAddr(a netip.Addr) bool {
	if a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() && cgnat.Contains(a) {
		return false
	}
	return a.IsGlobalUnicast()
}

// sessionPathKeys are path parameters such as /page;jsessionid=XYZ.
var sessionPathKeys = map[string]struct{}{
	"jsessionid": {}, "phpsessid": {}, "sid": {}, "sessionid": {},
}

func (s *Sanitizer) cleanPath(escaped string) (string, error) {
	if escaped == "" {
		return "/", nil
	}
	p, err := normalizeEscapes(escaped)
	if err != nil {
		return "", err
	}
	if p[0] != '/' {
		p = "/" + p
	}

	trailing := strings.HasSuffix(p, "/")
	segs := strings.Split(p, "/")[1:]
	out := make([]string, 0, len(segs))
	repeats := make(map[string]int, len(segs))

	for i, seg := range segs {
		isLast := i == len(segs)-1
		switch seg {
		case "", ".":
			// Collapses "//" and drops "./". A trailing "." keeps the slash.
			if isLast && seg == "." {
				trailing = true
			}
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if isLast {
				trailing = true
			}
			continue
		}
		if idx := strings.IndexByte(seg, ';'); idx >= 0 {
			key, _, _ := strings.Cut(seg[idx+1:], "=")
			if _, drop := sessionPathKeys[strings.ToLower(key)]; drop {
				seg = seg[:idx]
				if seg == "" {
					continue
				}
			}
		}
		repeats[seg]++
		if repeats[seg] > s.cfg.MaxSegmentRepeat {
			return "", ErrTrap
		}
		out = append(out, seg)
		if len(out) > s.cfg.MaxPathSegments {
			return "", ErrTrap
		}
	}

	if len(out) == 0 {
		return "/", nil
	}
	if !trailing {
		last := out[len(out)-1]
		if dot := strings.LastIndexByte(last, '.'); dot >= 0 && dot < len(last)-1 {
			if s.skipExt(strings.ToLower(last[dot+1:])) {
				return "", ErrSkippedExtension
			}
		}
	}
	res := "/" + strings.Join(out, "/")
	if trailing {
		res += "/"
	}
	return res, nil
}

// normalizeEscapes decodes escapes of unreserved characters (%41 -> A),
// uppercases the hex of the rest (%2f -> %2F) and rejects encoded control
// bytes such as %00.
//
// Why this is needed even though url.Parse already ran:
//
//   - url.Parse accepts well-formed escapes of ANY byte, including encoded
//     control characters. It rejects a raw NUL but accepts "%00", "%0a" and
//     "%7f", so they must be rejected here (ErrControlChars).
//   - url.Parse keeps the original spelling of escapes, so "/%7euser",
//     "/~user" and "/%7Euser" would be three different strings and three
//     separate entries in the dedupe set. Decoding unreserved characters and
//     uppercasing the remaining hex gives every spelling one canonical form.
//
// The two ErrParse returns below (truncated escape, non-hex digits) are
// defensive and cannot be reached through Sanitize: url.Parse already fails on
// malformed escapes in the path, and EscapedPath() returns either that
// validated text or a fresh re-encoding of the decoded path. They stay
// because this function is standalone. If it is ever called on a string that
// did not come from url.Parse (a sitemap entry, a robots.txt rule), the bounds
// check is the difference between an error and an index-out-of-range panic.
//
// The query string is not handled here: url.Parse does not validate it at all,
// so malformed escapes like "?q=%zz" do reach cleanQuery, which falls back to
// the raw text instead of failing.
func normalizeEscapes(s string) (string, error) {
	const upper = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		// Defensive: needs two hex digits after '%', i.e. indexes i+1 and i+2
		// must both be valid (see the function comment for why this cannot
		// trigger via Sanitize).
		if i+2 >= len(s) {
			return "", ErrParse
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			return "", ErrParse
		}
		d := (hi << 4) | lo
		switch {
		case d < 0x20 || d == 0x7f:
			return "", ErrControlChars
		case isUnreserved(d):
			b.WriteByte(d)
		default:
			b.WriteByte('%')
			b.WriteByte(upper[hi])
			b.WriteByte(upper[lo])
		}
		i += 2
	}
	return b.String(), nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func isUnreserved(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

var dropParams = map[string]struct{}{
	// Ad and analytics click IDs.
	"fbclid": {}, "gclid": {}, "gclsrc": {}, "dclid": {}, "gbraid": {}, "wbraid": {},
	"msclkid": {}, "yclid": {}, "twclid": {}, "ttclid": {}, "li_fat_id": {}, "igshid": {},
	"mc_cid": {}, "mc_eid": {}, "_ga": {}, "_gl": {}, "_hsenc": {}, "_hsmi": {},
	"hsctatracking": {}, "mkt_tok": {}, "vero_id": {}, "oly_anon_id": {}, "oly_enc_id": {},
	"spm": {}, "ref_src": {},
	// Session identifiers.
	"phpsessid": {}, "jsessionid": {}, "sid": {}, "sessionid": {}, "session_id": {}, "sessid": {},
}

func isDropParam(lowerKey string) bool {
	if strings.HasPrefix(lowerKey, "utm_") || strings.HasPrefix(lowerKey, "aspsessionid") {
		return true
	}
	_, ok := dropParams[lowerKey]
	return ok
}

type queryPair struct {
	key, val string
	hasEq    bool
}

// cleanQuery drops tracking and session parameters, sorts the rest by key
// (stable, so repeated keys keep their order) and re-encodes consistently.
func (s *Sanitizer) cleanQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	pairs := make([]queryPair, 0, 8)
	for part := range strings.SplitSeq(raw, "&") {
		if part == "" {
			continue
		}
		k, v, hasEq := strings.Cut(part, "=")
		// url.Parse does not validate the query, so malformed escapes such as
		// "?q=%zz" reach this point. On a failed unescape keep the raw text
		// rather than rejecting the whole link over one bad parameter.
		dk, err := url.QueryUnescape(k)
		if err != nil {
			dk = k
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			dv = v
		}
		if dk == "" && dv == "" {
			continue
		}
		if isDropParam(strings.ToLower(dk)) {
			continue
		}
		pairs = append(pairs, queryPair{dk, dv, hasEq})
		if len(pairs) > s.cfg.MaxQueryParams {
			return "", ErrTrap
		}
	}
	if len(pairs) == 0 {
		return "", nil
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].key < pairs[j].key })

	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p.key))
		if p.hasEq {
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(p.val))
		}
	}
	return b.String(), nil
}

// isDefaultSkippedExt reports whether ext (lowercase, no dot) is a non-HTML
// file type that is not worth fetching. A switch needs no setup, allocates
// nothing and cannot be mutated.
func isDefaultSkippedExt(ext string) bool {
	switch ext {
	case
		// images
		"jpg", "jpeg", "png", "gif", "webp", "svg", "ico", "bmp", "tif", "tiff", "avif", "heic",
		// audio and video
		"mp3", "mp4", "m4a", "wav", "flac", "ogg", "avi", "mov", "mkv", "webm", "wmv",
		// archives and binaries
		"zip", "gz", "tgz", "tar", "rar", "7z", "bz2", "xz", "exe", "dmg", "iso", "msi",
		"apk", "bin", "deb", "rpm",
		// fonts and web assets
		"woff", "woff2", "ttf", "otf", "eot", "css", "js", "map",
		// documents
		"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx":
		return true
	}
	return false
}
