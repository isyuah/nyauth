ARG NODE_IMAGE=node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd
ARG GO_IMAGE=golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --prefer-offline
COPY web/ .
RUN npm run check && npm run build

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS go-builder
WORKDIR /app
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.4.0-dev
ARG VCS_REF=unknown
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /app/web/build ./web/build
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags=nodynamic -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${VCS_REF} -X github.com/nyasharp/nyauth/internal/buildinfo.Version=${VERSION} -X github.com/nyasharp/nyauth/internal/buildinfo.Commit=${VCS_REF}" \
    -o /nyauth ./cmd/nyauth

FROM ${RUNTIME_IMAGE}
ARG VERSION=0.4.0-dev
ARG VCS_REF=unknown
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/nyauth/media \
    && chown -R 65532:65532 /var/lib/nyauth
WORKDIR /app
COPY --from=go-builder /nyauth /usr/local/bin/nyauth
LABEL org.opencontainers.image.title="Nyauth" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/nyasharp/nyauth"
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=4 \
    CMD ["nyauth", "healthcheck", "-url", "http://127.0.0.1:8080/readyz", "-timeout", "3s"]
ENTRYPOINT ["nyauth"]
CMD ["serve"]
