package internal

import (
	"errors"
	"net/url"
	"testing"
)

func TestSanitizeAccepts(t *testing.T) {
	base, _ := url.Parse("http://example.com/a/b/page.html")
	s := NewSanitizer(SanitizerConfig{})

	tests := []struct{ name, in, want, wantHost string }{
		{"parent relative", "../x", "http://example.com/a/x", "example.com"},
		{"root relative sorted query", "/y?b=2&a=1", "http://example.com/y?a=1&b=2", "example.com"},
		{"scheme relative", "//cdn.example.com/p", "http://cdn.example.com/p", "cdn.example.com"},
		{"case, default port, fragment", "HTTP://EXAMPLE.COM:80/Path#frag", "http://example.com/Path", "example.com"},
		{"https default port", "https://example.com:443/", "https://example.com/", "example.com"},
		{"non-default port kept", "https://example.com:8443/x", "https://example.com:8443/x", "example.com:8443"},
		{"empty path", "http://example.com", "http://example.com/", "example.com"},
		{"unreserved decoded", "http://example.com/%7euser/%41", "http://example.com/~user/A", "example.com"},
		{"reserved escape uppercased", "http://example.com/a%2fb", "http://example.com/a%2Fb", "example.com"},
		{"dot segments and double slash", "http://example.com/a//b/./c/../d", "http://example.com/a/b/d", "example.com"},
		{"encoded dot segments", "http://example.com/a/%2e%2e/b", "http://example.com/b", "example.com"},
		{"path session id", "http://example.com/x;jsessionid=ABC", "http://example.com/x", "example.com"},
		{"tracking params dropped", "http://example.com/?utm_source=a&id=3&fbclid=z", "http://example.com/?id=3", "example.com"},
		{"only tracking params", "http://example.com/p?utm_medium=x", "http://example.com/p", "example.com"},
		{"repeated keys stay ordered", "http://example.com/?q=a+b&q=a%20c", "http://example.com/?q=a+b&q=a+c", "example.com"},
		{"credentials stripped", "http://user:pw@example.com/", "http://example.com/", "example.com"},
		{"trailing dot host", "http://example.com./", "http://example.com/", "example.com"},
		{"space in path", "http://example.com/a b", "http://example.com/a%20b", "example.com"},
		{"backslashes", `http://example.com\a\b`, "http://example.com/a/b", "example.com"},
		{"whitespace inside and around", " http://exa\nmple.com/ ", "http://example.com/", "example.com"},
		{"trailing slash preserved", "/dir/", "http://example.com/dir/", "example.com"},
		{"public ip", "http://93.184.216.34/", "http://93.184.216.34/", "93.184.216.34"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, host, err := s.Sanitize(base, tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if host != tc.wantHost {
				t.Errorf("host %q, want %q", host, tc.wantHost)
			}
			again, _, err := s.Sanitize(nil, got)
			if err != nil || again != got {
				t.Errorf("not idempotent: %q -> %q (%v)", got, again, err)
			}
		})
	}
}

func TestSanitizeRejects(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	s := NewSanitizer(SanitizerConfig{})

	tests := []struct {
		name, in string
		want     error
	}{
		{"empty", "", ErrEmpty},
		{"fragment only", "#top", ErrEmpty},
		{"javascript", "javascript:alert(1)", ErrScheme},
		{"mailto", "mailto:a@b.com", ErrScheme},
		{"tel", "tel:123", ErrScheme},
		{"data", "data:text/html,x", ErrScheme},
		{"ftp", "ftp://example.com/", ErrScheme},
		{"control char", "http://example.com/a\x00b", ErrControlChars},
		{"encoded nul", "http://example.com/a%00b", ErrControlChars},
		{"localhost", "http://localhost/", ErrPrivateHost},
		{"loopback ip", "http://127.0.0.1/", ErrPrivateHost},
		{"private ip", "http://10.0.0.1/", ErrPrivateHost},
		{"cloud metadata", "http://169.254.169.254/latest", ErrPrivateHost},
		{"cgnat", "http://100.64.0.1/", ErrPrivateHost},
		{"ipv6 loopback", "http://[::1]/", ErrPrivateHost},
		{"intranet name", "http://intranet/", ErrPrivateHost},
		{".local", "http://printer.local/", ErrPrivateHost},
		{"decimal ip", "http://2130706433/", ErrHost},
		{"hex ip", "http://0x7f.0.0.1/", ErrHost},
		{"octal ip", "http://0177.0.0.1/", ErrHost},
		{"non-ascii host", "http://exämple.com/", ErrHost},
		{"empty host", "http:///path", ErrHost},
		{"port zero", "http://example.com:0/", ErrPort},
		{"port too big", "http://example.com:99999/", ErrPort},
		{"image", "http://example.com/logo.png", ErrSkippedExtension},
		{"pdf upper-case", "http://example.com/doc.PDF", ErrSkippedExtension},
		{"repeating path", "http://example.com/a/b/a/b/a/b/a/b", ErrTrap},
		{"too many params", "http://example.com/?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10&k=11&l=12&m=13&n=14&o=15&p=16&q=17&r=18&s=19&t=20&u=21", ErrTrap},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := s.Sanitize(base, tc.in)
			if !errors.Is(err, tc.want) {
				t.Errorf("got (%q, %v), want error %v", got, err, tc.want)
			}
		})
	}
}

func TestSanitizeNeedsBase(t *testing.T) {
	s := NewSanitizer(SanitizerConfig{})
	if _, _, err := s.Sanitize(nil, "/relative"); !errors.Is(err, ErrNoBase) {
		t.Errorf("got %v, want ErrNoBase", err)
	}
}

func TestSanitizeAllowPrivate(t *testing.T) {
	s := NewSanitizer(SanitizerConfig{AllowPrivateHosts: true})
	got, _, err := s.Sanitize(nil, "http://localhost:8080/x")
	if err != nil || got != "http://localhost:8080/x" {
		t.Errorf("got (%q, %v)", got, err)
	}
}
