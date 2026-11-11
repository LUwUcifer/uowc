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

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

// Sanitize resolves raw against base (which may be nil if raw is absolute)
// and returns the canonical URL plus its host key ("host" or "host:port"),
// which is what per-host queues and rate limiters should key on.
//
// Output is idempotent: sanitising a canonical URL returns it unchanged.
// raw must already be HTML-entity decoded (the link scanner's job).
//
// Stages, each of which can reject the link with one of the Err* values:
//
//	cleanRaw      whitespace, control characters, length, backslashes
//	resolveURL    parse, scheme check, resolve relative links against base
//	checkHost     hostname or IP validation, private-address filtering
//	buildHostKey  port validation, default port dropped
//	cleanPath     dot segments, escapes, session IDs, traps, extensions
//	cleanQuery    tracking params dropped, remainder sorted and re-encoded
//	assemble      build the string, final length check
//
// The fragment and any credentials are dropped by never being copied.
func (s *Sanitizer) Sanitize(base *url.URL, raw string) (canonical, hostKey string, err error) {
	raw, err = s.cleanRaw(raw)
	if err != nil {
		return "", "", err
	}
	u, err := resolveURL(base, raw)
	if err != nil {
		return "", "", err
	}
	host, err := s.checkHost(strings.ToLower(u.Hostname()))
	if err != nil {
		return "", "", err
	}
	hostKey, err = buildHostKey(u, host)
	if err != nil {
		return "", "", err
	}
	path, err := s.cleanPath(u.EscapedPath())
	if err != nil {
		return "", "", err
	}
	query, err := s.cleanQuery(u.RawQuery)
	if err != nil {
		return "", "", err
	}
	canonical, err = s.assemble(u.Scheme, hostKey, path, query)
	if err != nil {
		return "", "", err
	}
	return canonical, hostKey, nil
}

// ---------------------------------------------------------------------------
// Stage 1: raw input hygiene
// ---------------------------------------------------------------------------

// cleanRaw trims and screens the raw href before it is parsed.
func (s *Sanitizer) cleanRaw(raw string) (string, error) {
	raw = strings.TrimFunc(raw, isTrimmable)
	raw = strings.Map(dropLineBreaks, raw)
	if raw == "" || raw[0] == '#' {
		return "", ErrEmpty
	}
	if len(raw) > s.cfg.MaxURLLength {
		return "", ErrTooLong
	}
	if hasControlByte(raw) {
		return "", ErrControlChars
	}
	return fixBackslashes(raw), nil
}

// isTrimmable matches the space character and every ASCII control character
// (0x00 to 0x1F). Browsers strip exactly these from both ends of a URL, so
// unicode.IsSpace would be wrong: it misses NUL and friends, and it would
// strip U+00A0, which browsers keep.
func isTrimmable(r rune) bool { return r <= 0x20 }

// dropLineBreaks removes tab, newline and carriage return anywhere in the
// string, as browsers do.
func dropLineBreaks(r rune) rune {
	if r == '\t' || r == '\n' || r == '\r' {
		return -1
	}
	return r
}

// hasControlByte reports whether s contains an ASCII control byte or DEL.
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// fixBackslashes turns backslashes before the query or fragment into slashes,
// as browsers do.
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

// ---------------------------------------------------------------------------
// Stage 2: parse and resolve
// ---------------------------------------------------------------------------

// resolveURL parses raw and branches on the link's own scheme. Each case
// validates the scheme of the URL it ends up using, so no re-check is needed
// afterwards.
func resolveURL(base *url.URL, raw string) (*url.URL, error) {
	ref, err := url.Parse(raw)
	if err != nil {
		return nil, ErrParse
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
			return nil, ErrNoBase
		}
		u = base.ResolveReference(ref)
	default:
		// javascript:, mailto:, tel:, data:, ftp: and friends.
		return nil, ErrScheme
	}
	if u.Opaque != "" {
		return nil, ErrParse // e.g. "http:foo"
	}
	return u, nil
}

// ---------------------------------------------------------------------------
// Stage 3: host
// ---------------------------------------------------------------------------

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
	if strings.Contains(h, ":") {
		return s.checkIPv6Literal(h)
	}

	h = strings.TrimSuffix(h, ".")
	labels, err := splitHostLabels(h)
	if err != nil {
		return "", err
	}

	// A numeric last label means the host is meant as an IP address.
	if last := labels[len(labels)-1]; allDigits(last) || strings.HasPrefix(last, "0x") {
		return s.checkIPv4Literal(h)
	}
	if err := s.checkPrivateName(h, labels); err != nil {
		return "", err
	}
	return h, nil
}

// checkIPv6Literal validates a bare IPv6 address (brackets already removed by
// url.Hostname) and returns it bracketed. IPv4-mapped addresses are unwrapped
// and checked as IPv4.
func (s *Sanitizer) checkIPv6Literal(h string) (string, error) {
	addr, err := netip.ParseAddr(h)
	if err != nil || addr.Zone() != "" {
		return "", ErrHost
	}
	addr = addr.Unmap()
	if err := s.checkAddr(addr); err != nil {
		return "", err
	}
	if addr.Is4() {
		return addr.String(), nil
	}
	return "[" + addr.String() + "]", nil
}

// checkIPv4Literal accepts only strict dotted-quad IPv4, which rejects the
// decimal, octal and hex tricks such as 2130706433, 0177.0.0.1 and 0x7f.0.0.1.
func (s *Sanitizer) checkIPv4Literal(h string) (string, error) {
	addr, err := netip.ParseAddr(h)
	if err != nil || !addr.Is4() {
		return "", ErrHost
	}
	if err := s.checkAddr(addr); err != nil {
		return "", err
	}
	return addr.String(), nil
}

// checkAddr rejects loopback, private, link-local and other non-public
// addresses unless AllowPrivateHosts is set.
func (s *Sanitizer) checkAddr(addr netip.Addr) error {
	if !s.cfg.AllowPrivateHosts && !isPublicAddr(addr) {
		return ErrPrivateHost
	}
	return nil
}

// splitHostLabels checks the overall length, the character set and each dot
// separated label of a hostname (trailing dot already removed).
//
// Only plain ASCII is allowed. That rejects non-ASCII (IDN) hosts
//Todo: Implement IDN hosts

func splitHostLabels(h string) ([]string, error) {
	if h == "" || len(h) > 253 {
		return nil, ErrHost
	}
	for i := 0; i < len(h); i++ {
		if !isHostByte(h[i]) {
			return nil, ErrHost
		}
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return nil, ErrHost
		}
	}
	return labels, nil
}

func isHostByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'
}

// checkPrivateName rejects intranet-style names unless AllowPrivateHosts is
// set. A single-label name (including "localhost") is an intranet name, and
// the suffix list covers "anything.localhost", ".local" and similar.
func (s *Sanitizer) checkPrivateName(h string, labels []string) error {
	if s.cfg.AllowPrivateHosts {
		return nil
	}
	if len(labels) < 2 {
		return ErrPrivateHost
	}
	for _, suf := range privateSuffixes {
		if strings.HasSuffix(h, suf) {
			return ErrPrivateHost
		}
	}
	return nil
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

// ---------------------------------------------------------------------------
// Stage 4: port and host key
// ---------------------------------------------------------------------------

// buildHostKey returns "host" or "host:port". The port is validated and
// dropped when it is the default for the scheme, so "example.com:80" and
// "example.com" over http share one key. A non-default port is a different
// server, so it stays in the key.
func buildHostKey(u *url.URL, host string) (string, error) {
	p := u.Port()
	if p == "" {
		return host, nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", ErrPort
	}
	if isDefaultPort(u.Scheme, n) {
		return host, nil
	}
	return host + ":" + strconv.Itoa(n), nil
}

// isDefaultPort reports whether n is the implied port for the scheme.
func isDefaultPort(scheme string, n int) bool {
	return (scheme == "http" && n == 80) || (scheme == "https" && n == 443)
}

// ---------------------------------------------------------------------------
// Stage 5: path
// ---------------------------------------------------------------------------

// sessionPathKeys are path parameters such as /page;jsessionid=XYZ.
var sessionPathKeys = map[string]struct{}{
	"jsessionid": {}, "phpsessid": {}, "sid": {}, "sessionid": {},
}

// cleanPath normalises an escaped path: escapes, dot segments, session IDs,
// trap limits and non-HTML extensions. An empty path becomes "/".
func (s *Sanitizer) cleanPath(escaped string) (string, error) {
	if escaped == "" {
		return "/", nil
	}
	p, err := normalizeEscapes(escaped)
	if err != nil {
		return "", err
	}
	segs, trailing, err := s.collapseSegments(p)
	if err != nil {
		return "", err
	}
	if len(segs) == 0 {
		return "/", nil
	}
	if !trailing && s.hasSkippedExtension(segs[len(segs)-1]) {
		return "", ErrSkippedExtension
	}
	return joinPath(segs, trailing), nil
}

// collapseSegments splits p on "/", resolves "." and "..", collapses "//",
// strips path session IDs and enforces the trap limits. trailing reports
// whether the path should end in a slash.
func (s *Sanitizer) collapseSegments(p string) (segs []string, trailing bool, err error) {
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	trailing = strings.HasSuffix(p, "/")
	parts := strings.Split(p, "/")[1:]
	segs = make([]string, 0, len(parts))
	repeats := make(map[string]int, len(parts))

	for i, seg := range parts {
		isLast := i == len(parts)-1
		switch seg {
		case "", ".":
			// Collapses "//" and drops "./". A trailing "." keeps the slash.
			if isLast && seg == "." {
				trailing = true
			}
			continue
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
			if isLast {
				trailing = true
			}
			continue
		}
		if seg = stripSessionParam(seg); seg == "" {
			continue
		}
		repeats[seg]++
		if repeats[seg] > s.cfg.MaxSegmentRepeat {
			return nil, false, ErrTrap
		}
		segs = append(segs, seg)
		if len(segs) > s.cfg.MaxPathSegments {
			return nil, false, ErrTrap
		}
	}
	return segs, trailing, nil
}

// stripSessionParam removes a path parameter such as ";jsessionid=ABC" from a
// segment. Other ";" parameters are left alone.
func stripSessionParam(seg string) string {
	idx := strings.IndexByte(seg, ';')
	if idx < 0 {
		return seg
	}
	key, _, _ := strings.Cut(seg[idx+1:], "=")
	if _, drop := sessionPathKeys[strings.ToLower(key)]; drop {
		return seg[:idx]
	}
	return seg
}

// hasSkippedExtension reports whether the last segment ends in an extension
// that is not worth fetching, such as ".png" or ".pdf".
func (s *Sanitizer) hasSkippedExtension(last string) bool {
	dot := strings.LastIndexByte(last, '.')
	if dot < 0 || dot == len(last)-1 {
		return false
	}
	return s.skipExt(strings.ToLower(last[dot+1:]))
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

// joinPath rebuilds the path from its segments. segs must not be empty.
func joinPath(segs []string, trailing bool) string {
	res := "/" + strings.Join(segs, "/")
	if trailing {
		res += "/"
	}
	return res
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
		// Combine the two hex digits into one byte: %2F -> (2<<4)|15 = 0x2F.
		d := hi<<4 | lo
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

// ---------------------------------------------------------------------------
// Stage 6: query
// ---------------------------------------------------------------------------

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

// isDropParam reports whether a lowercase parameter name is tracking or
// session noise that does not change the page.
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
	pairs, err := s.parseQuery(raw)
	if err != nil || len(pairs) == 0 {
		return "", err
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].key < pairs[j].key })
	return encodeQuery(pairs), nil
}

// parseQuery splits the raw query into decoded key/value pairs, skipping empty
// and tracking parameters and enforcing the parameter limit.
func (s *Sanitizer) parseQuery(raw string) ([]queryPair, error) {
	pairs := make([]queryPair, 0, 8)
	for _, part := range strings.Split(raw, "&") {
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
			return nil, ErrTrap
		}
	}
	return pairs, nil
}

// encodeQuery re-encodes pairs as "k=v&k2=v2". A key that had no "=" in the
// input stays without one.
func encodeQuery(pairs []queryPair) string {
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
	return b.String()
}

// ---------------------------------------------------------------------------
// Stage 7: assemble
// ---------------------------------------------------------------------------

// assemble builds scheme://hostKey/path[?query] and enforces the length limit
// on the result. The input length was checked in cleanRaw, but normalisation
// can make the output longer (non-ASCII bytes and spaces become %XX).
func (s *Sanitizer) assemble(scheme, hostKey, path, query string) (string, error) {
	var b strings.Builder
	b.Grow(len(scheme) + 3 + len(hostKey) + len(path) + 1 + len(query))
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(hostKey)
	b.WriteString(path)
	if query != "" {
		b.WriteByte('?')
		b.WriteString(query)
	}
	if b.Len() > s.cfg.MaxURLLength {
		return "", ErrTooLong
	}
	return b.String(), nil
}

// ---------------------------------------------------------------------------
// Built-in extension list
// ---------------------------------------------------------------------------

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
