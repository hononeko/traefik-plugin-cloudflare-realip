package traefik_plugin_cloudflare_realip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

var testCIDRs = []string{"173.245.48.0/20", "2400:cb00::/32"}

type seen struct {
	xff, xRealIP, cfConnectingIP, forwarded, trueClientIP string
	called                                                bool
}

func serve(t *testing.T, remoteAddr string, headers map[string]string) seen {
	t.Helper()

	var got seen
	next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		got = seen{
			xff:            req.Header.Get(headerXForwardedFor),
			xRealIP:        req.Header.Get(headerXRealIP),
			cfConnectingIP: req.Header.Get(headerCFConnectingIP),
			forwarded:      req.Header.Get("Forwarded"),
			trueClientIP:   req.Header.Get("True-Client-Ip"),
			called:         true,
		}
	})

	handler, err := New(context.Background(), next, &Config{TrustedCIDRs: testCIDRs}, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://auth.example.com/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !got.called {
		t.Fatal("next handler was not called")
	}
	return got
}

func TestServeHTTP(t *testing.T) {
	forged := map[string]string{
		headerXForwardedFor: "192.168.1.244, 203.0.113.7",
		headerXRealIP:       "192.168.1.244",
		"Forwarded":         "for=192.168.1.244",
		"True-Client-Ip":    "192.168.1.244",
	}
	with := func(extra map[string]string) map[string]string {
		h := map[string]string{}
		for k, v := range forged {
			h[k] = v
		}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       seen
	}{
		{
			name:       "trusted peer uses CF-Connecting-IP",
			remoteAddr: "173.245.49.10:443",
			headers:    with(map[string]string{headerCFConnectingIP: "203.0.113.7"}),
			want:       seen{xff: "203.0.113.7", xRealIP: "203.0.113.7", cfConnectingIP: "203.0.113.7"},
		},
		{
			name:       "trusted peer normalises CF-Connecting-IP",
			remoteAddr: "173.245.49.10:443",
			headers:    map[string]string{headerCFConnectingIP: " ::ffff:203.0.113.7 "},
			want:       seen{xff: "203.0.113.7", xRealIP: "203.0.113.7", cfConnectingIP: "203.0.113.7"},
		},
		{
			name:       "trusted IPv6 peer",
			remoteAddr: "[2400:cb00:2049::1]:443",
			headers:    map[string]string{headerCFConnectingIP: "2606:4700:10::42"},
			want:       seen{xff: "2606:4700:10::42", xRealIP: "2606:4700:10::42", cfConnectingIP: "2606:4700:10::42"},
		},
		{
			name:       "trusted IPv4-mapped peer",
			remoteAddr: "[::ffff:173.245.49.10]:443",
			headers:    map[string]string{headerCFConnectingIP: "203.0.113.7"},
			want:       seen{xff: "203.0.113.7", xRealIP: "203.0.113.7", cfConnectingIP: "203.0.113.7"},
		},
		{
			name:       "trusted peer without CF-Connecting-IP falls back to the peer",
			remoteAddr: "173.245.49.10:443",
			headers:    forged,
			want:       seen{xff: "173.245.49.10", xRealIP: "173.245.49.10", cfConnectingIP: "173.245.49.10"},
		},
		{
			name:       "trusted peer with an invalid CF-Connecting-IP falls back to the peer",
			remoteAddr: "173.245.49.10:443",
			headers:    map[string]string{headerCFConnectingIP: "not-an-ip"},
			want:       seen{xff: "173.245.49.10", xRealIP: "173.245.49.10", cfConnectingIP: "173.245.49.10"},
		},
		{
			name:       "trusted peer claiming a private client falls back to the peer",
			remoteAddr: "173.245.49.10:443",
			headers:    map[string]string{headerCFConnectingIP: "192.168.1.10"},
			want:       seen{xff: "173.245.49.10", xRealIP: "173.245.49.10", cfConnectingIP: "173.245.49.10"},
		},
		{
			name:       "trusted peer claiming a CGNAT client falls back to the peer",
			remoteAddr: "173.245.49.10:443",
			headers:    map[string]string{headerCFConnectingIP: "100.64.1.1"},
			want:       seen{xff: "173.245.49.10", xRealIP: "173.245.49.10", cfConnectingIP: "173.245.49.10"},
		},
		{
			name:       "untrusted peer becomes the client",
			remoteAddr: "198.51.100.9:51000",
			headers:    with(map[string]string{headerCFConnectingIP: "203.0.113.7"}),
			want:       seen{xff: "198.51.100.9", xRealIP: "198.51.100.9"},
		},
		{
			name:       "private untrusted peer is kept as is",
			remoteAddr: "10.10.1.218:40000",
			headers:    forged,
			want:       seen{xff: "10.10.1.218", xRealIP: "10.10.1.218"},
		},
		{
			name:       "unparsable RemoteAddr drops every client IP header",
			remoteAddr: "garbage",
			headers:    with(map[string]string{headerCFConnectingIP: "203.0.113.7"}),
			want:       seen{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serve(t, tt.remoteAddr, tt.headers)
			tt.want.called = true
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
	}{
		{name: "empty", cidrs: nil, wantErr: true},
		{name: "only blank entries", cidrs: []string{"", " "}, wantErr: true},
		{name: "missing prefix length", cidrs: []string{"1.2.3.4"}, wantErr: true},
		{name: "IPv4 catch-all", cidrs: []string{"0.0.0.0/0"}, wantErr: true},
		{name: "IPv6 catch-all", cidrs: []string{"::/0"}, wantErr: true},
		{name: "blank entries and spaces are ignored", cidrs: []string{" 173.245.48.0/20 ", "", "2400:cb00::/32"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(context.Background(), next, &Config{TrustedCIDRs: tt.cidrs}, "test")
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	if CreateConfig() == nil {
		t.Error("CreateConfig returned nil")
	}
}

func TestNewSortsLargestRangesFirst(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	cidrs := []string{"173.245.48.0/20", "104.16.0.0/13", "162.158.0.0/15", "2400:cb00::/32", "2a06:98c0::/29"}

	handler, err := New(context.Background(), next, &Config{TrustedCIDRs: cidrs}, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := handler.(*RealIP)

	var v4, v6 []string
	for _, p := range r.trustedV4 {
		v4 = append(v4, p.String())
	}
	for _, p := range r.trustedV6 {
		v6 = append(v6, p.String())
	}
	if want := "[104.16.0.0/13 162.158.0.0/15 173.245.48.0/20]"; fmt.Sprint(v4) != want {
		t.Errorf("IPv4 order %v, want %s", v4, want)
	}
	if want := "[2a06:98c0::/29 2400:cb00::/32]"; fmt.Sprint(v6) != want {
		t.Errorf("IPv6 order %v, want %s", v6, want)
	}
}

func TestPublicAddr(t *testing.T) {
	tests := map[string]bool{
		"203.0.113.7":      true,
		"2606:4700:10::42": true,
		"104.28.12.1":      true, // WARP egress, inside a Cloudflare range
		"10.1.2.3":         false,
		"172.16.0.1":       false,
		"192.168.1.10":     false,
		"100.64.0.1":       false,
		"127.0.0.1":        false,
		"169.254.1.1":      false,
		"0.0.0.0":          false,
		"224.0.0.1":        false,
		"::1":              false,
		"fe80::1":          false,
		"fd00::1":          false,
		"2001:db8::1%eth0": false,
		"":                 false,
	}
	for in, want := range tests {
		if _, got := publicAddr(in); got != want {
			t.Errorf("publicAddr(%q) = %v, want %v", in, got, want)
		}
	}
}
