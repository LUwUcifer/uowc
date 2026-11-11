package internal

import (
	"fmt"
	"net/url"
)

// ExampleExtractLinks shows the scanner feeding the sanitiser: extract the
// raw hrefs, resolve <base> against the page URL, then sanitise every link.
func ExampleExtractLinks() {
	san := NewSanitizer(SanitizerConfig{})
	pageURL, _ := url.Parse("http://example.com/blog/post.html")

	doc := []byte(`<a href="../about?utm_source=x">About</a>
<a href="/shop?a=1&region=us&amp;b=2">Shop</a>
<a href="javascript:void(0)">js</a>
<a href="https://other.org:443/x#top">Other</a>
<a href="/logo.png">logo</a>`)

	res := ExtractLinks(doc, 0)

	base := pageURL
	if res.Base != "" {
		if b, err := pageURL.Parse(res.Base); err == nil {
			base = b
		}
	}
	for _, l := range res.Links {
		canonical, hostKey, err := san.Sanitize(base, l.Href)
		if err != nil {
			fmt.Println("skip:", l.Href, "->", err)
			continue
		}
		fmt.Println(canonical, hostKey)
	}

	// Output:
	// http://example.com/about example.com
	// http://example.com/shop?a=1&b=2&region=us example.com
	// skip: javascript:void(0) -> url: scheme is not http or https
	// https://other.org/x other.org
	// skip: /logo.png -> url: non-HTML file extension
}
