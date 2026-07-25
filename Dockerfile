FROM node:20-alpine AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --prefer-offline
COPY web/ .
RUN npm run build

FROM golang:1.26-bookworm AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /app/web/build ./web/build
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /nyauth ./cmd/nyauth

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=go-builder /nyauth /usr/local/bin/nyauth
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["nyauth"]
CMD ["serve", "-config", "/etc/nyauth/config.yaml"]
