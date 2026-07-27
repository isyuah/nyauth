FROM node:20-alpine AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --prefer-offline
COPY web/ .
RUN npm run check && npm run build

FROM golang:1.26.5-bookworm AS go-builder
WORKDIR /app
ARG VERSION=dev
ARG VCS_REF=unknown
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /app/web/build ./web/build
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${VCS_REF} -X github.com/nyasharp/nyauth/internal/buildinfo.Version=${VERSION} -X github.com/nyasharp/nyauth/internal/buildinfo.Commit=${VCS_REF}" \
    -o /nyauth ./cmd/nyauth

FROM debian:bookworm-slim
ARG VERSION=dev
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
