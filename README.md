# traefik-plugin-cloudflare-realip

A Traefik middleware plugin that sets `X-Forwarded-For` and `X-Real-Ip` from the TCP peer, or from Cloudflare's
`CF-Connecting-IP` when the peer is in a trusted range (Cloudflare's).

## Why

Cloudflare appends the visitor's address to any `X-Forwarded-For` the visitor sent. A Traefik entrypoint that trusts
Cloudflare's ranges passes that header on, so the left-most entry is whatever the client chose:

```
X-Forwarded-For: 192.168.1.244, <real client>, <cloudflare edge>
```

Backends that take the left-most entry as the client IP, such as Authelia's regulation (login bans), can then be
fed any address: ban someone else's IP, or rotate the forged value to never be banned. `CF-Connecting-IP` is always
set by Cloudflare itself.

## Behaviour

Every request gets `X-Forwarded-For` and `X-Real-Ip` set to one client IP, whatever the client sent:

| TCP peer | `CF-Connecting-IP` | Client IP | `CF-Connecting-IP` passed on |
|---|---|---|---|
| in `trustedCIDRs` | a public address | that address | normalised |
| in `trustedCIDRs` | missing, invalid, or private/loopback/link-local/CGNAT | the peer | set to the peer |
| anything else | ignored | the peer | removed |

`Forwarded`, `True-Client-Ip`, `Cf-Connecting-Ipv6` and `Cf-Pseudo-Ipv4` are removed from every request, so no
backend reads a client IP claim the plugin didn't set. This doesn't depend on the entrypoint's `forwardedHeaders`
trust list.

Traefik appends the peer to `X-Forwarded-For` when proxying, so the backend receives `<client>, <cloudflare edge>`.
A rate limit with `sourceCriterion.ipStrategy.depth: 1`, or `requestHeaderName: X-Real-Ip`, keys on the client
either way.

## Limitations

- **Cloudflare's ranges are shared by every Cloudflare customer.** Anyone can proxy their own zone to your origin
  IP, so a peer in Cloudflare's ranges proves only that the request came through Cloudflare, not through your
  zone. That also bypasses your zone's WAF rules. To bind requests to your zone, enable
  [Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)
  with a zone-specific certificate and require it on the entrypoint (Traefik TLS option `clientAuth`).
- When a trusted peer sends no usable `CF-Connecting-IP` (for example with Cloudflare's "Remove visitor IP headers"
  transform), the client IP is the Cloudflare edge address, which many visitors share. Per-IP rate limits and bans
  then apply to all of them.
- Header names with underscores (`X_Forwarded_For`) aren't touched; some CGI/PHP/WSGI stacks map them onto
  `HTTP_X_FORWARDED_FOR`. Drop them at those backends if they're exposed.
- Traefik's `forwardAuth` middleware replaces `X-Forwarded-For` with the peer unless `trustForwardHeader: true`, so
  set it for auth servers such as Authelia to see the client IP.

## Configuration

`trustedCIDRs` (required): the networks allowed to set the client IP, normally
[Cloudflare's ranges](https://www.cloudflare.com/ips/). Don't include anything a client can send from directly.
Blank entries are ignored; a `/0` is rejected.

Static configuration (local plugin, e.g. from a `FROM scratch` image of this repository's source):

```yaml
experimental:
  localPlugins:
    cloudflarerealip:
      moduleName: github.com/hononeko/traefik-plugin-cloudflare-realip
```

Dynamic configuration, put first in the Cloudflare-facing entrypoint's middleware chain so every later middleware
sees the rewritten headers:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: cloudflare-realip
spec:
  plugin:
    cloudflarerealip:
      trustedCIDRs:
        - 173.245.48.0/20
        - 2400:cb00::/32
        # ...the rest of https://www.cloudflare.com/ips/
```

## Development

```sh
go test -race ./...     # unit tests
./test/e2e/run.sh       # loads the plugin into a real Traefik (Docker) and checks the headers the backend sees
```

CI also runs the tests under [yaegi](https://github.com/traefik/yaegi), the interpreter Traefik loads plugins with.
The package is named after the module (`traefik_plugin_cloudflare_realip`) because that's the name Traefik looks up;
a plugin that fails to load disables every plugin in that Traefik.

Releases are cut from `main` with the **Release** workflow; the version follows Conventional Commits.
