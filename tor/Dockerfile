# Tor from the Tor Project's own package repository, so the gateway gets a current release with
# the onion service proof-of-work support that some sites need. The signing key is checked
# against its published fingerprint before it is trusted.
FROM debian:bookworm-slim

ARG TOR_KEY_FINGERPRINT=A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gpg \
    && curl -fsSL "https://deb.torproject.org/torproject.org/${TOR_KEY_FINGERPRINT}.asc" -o /tmp/tor.asc \
    && gpg --show-keys --with-colons /tmp/tor.asc | awk -F: '$1=="fpr"{print $10}' \
        | grep -qx "${TOR_KEY_FINGERPRINT}" \
    && gpg --dearmor < /tmp/tor.asc > /usr/share/keyrings/tor-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main" \
        > /etc/apt/sources.list.d/tor.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends tor \
    && apt-get purge -y --auto-remove curl gpg \
    && rm -rf /var/lib/apt/lists/* /tmp/*

COPY torrc /etc/tor/torrc

USER debian-tor
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
