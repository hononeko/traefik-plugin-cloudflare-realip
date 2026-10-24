// Package traefik_plugin_cloudflare_realip is a Traefik middleware plugin that sets the client IP headers from the
// TCP peer, or from Cloudflare's CF-Connecting-IP when the peer is a trusted Cloudflare address.
//
// Cloudflare appends the visitor's address to any X-Forwarded-For the visitor sent, so behind Cloudflare the
// left-most entry is chosen by the client. Backends that trust the left-most entry (such as Authelia) can be fed a
// forged address. CF-Connecting-IP is always set by Cloudflare itself.
package traefik_plugin_cloudflare_realip

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
)

const (
	headerCFConnectingIP = "Cf-Connecting-Ip"
	headerXForwardedFor  = "X-Forwarded-For"
	headerXRealIP        = "X-Real-Ip"
)

// strippedHeaders are other client IP claims, removed from every request so no backend can be fed one.
var strippedHeaders = []string{"Forwarded", "True-Client-Ip", "Cf-Connecting-Ipv6", "Cf-Pseudo-Ipv4"}

// sharedAddressSpace is the carrier-grade NAT range (RFC 6598), which netip doesn't count as private.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// Config is the plugin configuration.
type Config struct {
	// TrustedCIDRs are the networks whose CF-Connecting-IP is trusted: Cloudflare's published ranges.
	TrustedCIDRs []string `json:"trustedCIDRs,omitempty"`
}

// CreateConfig returns the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// RealIP sets the client IP headers of every request.
type RealIP struct {
	next      http.Handler
	trustedV4 []netip.Prefix
	trustedV6 []netip.Prefix
}

// New creates the middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	r := &RealIP{next: next}

	for _, cidr := range config.TrustedCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid trusted CIDR %q: %w", name, cidr, err)
		}
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("%s: trusted CIDR %q would trust every peer", name, cidr)
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4() {
			r.trustedV4 = append(r.trustedV4, prefix)
		} else {
			r.trustedV6 = append(r.trustedV6, prefix)
		}
	}

	if len(r.trustedV4)+len(r.trustedV6) == 0 {
		return nil, fmt.Errorf("%s: trustedCIDRs must not be empty", name)
	}

	// Largest ranges first: they carry most peers, and every lookup step is costly under yaegi.
	sort.SliceStable(r.trustedV4, func(i, j int) bool { return r.trustedV4[i].Bits() < r.trustedV4[j].Bits() })
	sort.SliceStable(r.trustedV6, func(i, j int) bool { return r.trustedV6[i].Bits() < r.trustedV6[j].Bits() })
	return r, nil
}

// ServeHTTP indexes req.Header directly with canonical names: under yaegi each http.Header method call costs far
// more than the work it does.
func (r *RealIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	header := req.Header
	for _, h := range strippedHeaders {
		delete(header, h)
	}

	peer, ok := remoteAddr(req.RemoteAddr)
	if !ok {
		delete(header, headerXForwardedFor)
		delete(header, headerXRealIP)
		delete(header, headerCFConnectingIP)
		r.next.ServeHTTP(rw, req)
		return
	}

	// The peer is the client unless it's Cloudflare vouching for a public address. Either way the headers are
	// replaced, so nothing the client sent survives.
	client := peer
	trusted := r.isTrusted(peer)
	if trusted {
		if values := header[headerCFConnectingIP]; len(values) > 0 {
			if ip, valid := publicAddr(values[0]); valid {
				client = ip
			}
		}
	}

	value := client.String()
	header[headerXForwardedFor] = []string{value}
	header[headerXRealIP] = []string{value}
	if trusted {
		header[headerCFConnectingIP] = []string{value}
	} else {
		delete(header, headerCFConnectingIP)
	}

	r.next.ServeHTTP(rw, req)
}

func (r *RealIP) isTrusted(ip netip.Addr) bool {
	trusted := r.trustedV6
	if ip.Is4() {
		trusted = r.trustedV4
	}
	for _, prefix := range trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteAddr parses the IP of a host:port RemoteAddr, as Traefik sets it, without zone and IPv4-mapping.
func remoteAddr(addr string) (netip.Addr, bool) {
	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil {
		return netip.Addr{}, false
	}
	return addrPort.Addr().WithZone("").Unmap(), true
}

// publicAddr parses a client IP claim, accepting only addresses a real visitor can have: no loopback, link-local,
// multicast, private or shared (CGNAT) addresses, which backends tend to treat as local.
func publicAddr(value string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || sharedAddressSpace.Contains(ip) {
		return netip.Addr{}, false
	}
	return ip, true
}
