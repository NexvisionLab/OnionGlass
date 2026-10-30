# The gateway image. Build and run it with compose.yaml, which also starts Tor and a proxy.
#
# Pin the base image by digest for a release build, for example:
#   docker pull python:3.12-slim-bookworm && docker inspect --format '{{index .RepoDigests 0}}' ...
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ONIONGLASS_IN_CONTAINER=1

RUN useradd --system --no-create-home --uid 10001 --shell /usr/sbin/nologin onionglass

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install .

USER onionglass
EXPOSE 8080

# Inside the container the gateway listens on all of the container's addresses. The compose file
# keeps it on a private network and publishes only the proxy, on the host's loopback address.
ENTRYPOINT ["onionglass"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--tor-host", "tor", "--tor-port", "9050"]
