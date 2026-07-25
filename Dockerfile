# Stage 1: Build SvelteKit Web UI
FROM node:20-alpine AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --prefer-offline
COPY web/ .
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.26-bookworm AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /app/web/build ./web/build
RUN CGO_ENABLED=0 GOOS=linux go build -o /nyauth ./cmd/nyauth

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=go-builder /nyauth /usr/local/bin/nyauth
COPY migrations/ /app/migrations/
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["nyauth"]
CMD ["-config", "/etc/nyauth/config.yaml"]
