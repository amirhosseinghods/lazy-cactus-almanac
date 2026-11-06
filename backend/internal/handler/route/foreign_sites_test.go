package route

import (
	"regexp"
	"testing"
)

func TestNormalizeSite(t *testing.T) {
	cases := map[string]string{
		"ChatGPT.com":                "chatgpt.com",
		"https://www.x.com/home?a=1": "www.x.com",
		"https://x.com:8443/a":       "x.com",
		"*.openai.com":               "*.openai.com",
		"https://*.openai.com/x":     "*.openai.com",
		"star*.example.com":          "star*.example.com",
		"example.*":                  "example.*",
		"example.com/path":           "example.com",
		"1.2.3.4":                    "1.2.3.4",
		"10.0.0.0/8":                 "10.0.0.0/8",
		"*":                          "",
		"*.*":                        "",
		"**.example.com":             "",
		"not a site":                 "",
		"localhost":                  "",
		"::1":                        "",
		"":                           "",
	}
	for in, want := range cases {
		if got := normalizeSite(in); got != want {
			t.Errorf("normalizeSite(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWildcardRegexp(t *testing.T) {
	cases := []struct {
		pattern string
		match   []string
		noMatch []string
	}{
		{"*.example.com", []string{"example.com", "a.example.com", "a.b.example.com"}, []string{"badexample.com", "example.com.evil.net"}},
		{"star*.example.com", []string{"star.example.com", "starlink.example.com"}, []string{"a.star.example.com", "example.com"}},
		{"example.*", []string{"example.com", "example.co.uk"}, []string{"www.example.com", "example"}},
		{"*.cdn-*.net", []string{"cdn-1.net", "x.cdn-eu.net"}, []string{"cdn.net"}},
	}
	for _, c := range cases {
		re := regexp.MustCompile(wildcardRegexp(c.pattern))
		for _, n := range c.match {
			if !re.MatchString(n) {
				t.Errorf("%s (%s) should match %s", c.pattern, re, n)
			}
		}
		for _, n := range c.noMatch {
			if re.MatchString(n) {
				t.Errorf("%s (%s) should not match %s", c.pattern, re, n)
			}
		}
	}
}

func TestSiteAddresses(t *testing.T) {
	resolved := map[string][]string{"shop.example": {"130.193.77.35"}}
	cases := map[string][]string{
		"130.193.77.35":   {"130.193.77.35"},
		"130.193.77.0/24": {"130.193.77.0/24"},
		"shop.example":    {"130.193.77.35"},
		"*.shop.example":  {"130.193.77.35"},
		"star*.example":   nil,
	}
	for in, want := range cases {
		got := siteAddresses(in, resolved)
		if len(got) != len(want) || (len(want) > 0 && got[0] != want[0]) {
			t.Errorf("siteAddresses(%q) = %v, want %v", in, got, want)
		}
	}
}
