# brainproxy-server with the brainproxy CLI it runs. Build from the repository root:
#   docker build -f docker/server.Dockerfile -t brainproxy-server .
#
# The brainproxy project publishes no container image, only static release binaries, so the CLI is
# downloaded here and checked against its SHA-256. Binaries exist for linux x86_64 and arm64; the
# matching one is picked from the build platform (docker buildx --platform linux/amd64,linux/arm64).
# To move to another CLI release, change the version and both checksums (from the release's
# brainproxy-<version>-linux-<arch>.sha256 files).
#
# Runs as UID 1000 and writes only under /work, so it works with a read-only root filesystem.
# HOME and BRAINPROXY_HOME for the CLI are set by the server, under /work.

ARG BRAINPROXY_VERSION=0.4.6
ARG BRAINPROXY_SHA256_X86_64=fecbff16ac16a25c0472789e34f6c63c103bf7568e00a1ed1088a1e96431c307
ARG BRAINPROXY_SHA256_ARM64=fca89ad6a3e3406dd17d3e136405b6bb00a05e8d3b03c0b3c56fe687832d3fd1

# The server, as a static musl binary like the CLI. The same images as brainproxy's own Dockerfile.
FROM rust:1.99.1-alpine3.24@sha256:7e9e2d068a107a2adafd19930011178d14a78326053cd4c3a9f7ad3fd049557d AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# The CLI release binary.
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS cli
ARG BRAINPROXY_VERSION
ARG BRAINPROXY_SHA256_X86_64
ARG BRAINPROXY_SHA256_ARM64
ARG TARGETARCH
# hadolint ignore=DL4006
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=x86_64; sum="$BRAINPROXY_SHA256_X86_64" ;; \
      arm64) arch=arm64;  sum="$BRAINPROXY_SHA256_ARM64" ;; \
      *) echo "no brainproxy release binary for $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    wget -q -O /brainproxy \
      "https://github.com/r4nd0mth1ngs/brainproxy/releases/download/v${BRAINPROXY_VERSION}/brainproxy-${BRAINPROXY_VERSION}-linux-${arch}"; \
    echo "${sum}  /brainproxy" | sha256sum -c -; \
    chmod 0755 /brainproxy

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
LABEL org.opencontainers.image.title="brainproxy-server" \
      org.opencontainers.image.source="https://github.com/r4nd0mth1ngs/brainproxy_server" \
      org.opencontainers.image.licenses="PolyForm-Shield-1.0.0"
# tini as PID 1: scans run as background CLI processes that outlive the command that started them,
# and something has to reap them when they end. ca-certificates for `remote run` over HTTPS.
RUN apk add --no-cache tini ca-certificates \
    && adduser -D -u 1000 brainproxy \
    && install -d -o brainproxy -g brainproxy /work
# No /etc/brainproxy/scope.json: it would override the system scope the server writes to /work.
COPY --from=cli /brainproxy /usr/local/bin/brainproxy
COPY --from=build /src/target/release/brainproxy-server /usr/local/bin/brainproxy-server
COPY LICENSE.md /usr/share/licenses/brainproxy-server/
USER 1000:1000
WORKDIR /work
VOLUME /work
EXPOSE 9090 9091
ENTRYPOINT ["/sbin/tini", "--", "brainproxy-server"]
CMD ["serve", "--listen", "0.0.0.0:9090", "--admin-listen", "0.0.0.0:9091", \
     "--admin-token-file", "/run/secrets/admin_token"]
