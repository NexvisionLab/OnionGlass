# Caddy with the DNS plugin that proves control of the domain, so it can get and renew a wildcard
# certificate by itself. Wildcard certificates cannot be validated any other way.
#
# The plugin is for Cloudflare, which is where the domain's DNS has to be hosted. To use another
# DNS provider, replace the plugin name here and the "dns" line in the Caddyfile. For a release
# build, pin both images by digest and the plugin by version.
FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/caddy-dns/cloudflare

FROM caddy:2-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
