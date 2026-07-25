.PHONY: build build-ui build-all run migrate clean test dev

# Default target
all: build

# Build Go binary
build:
	go build -o bin/nyauth.exe ./cmd/nyauth

# Build Go binary without embedded UI
build-server:
	go build -tags noembed -o bin/nyauth.exe ./cmd/nyauth

# Build Web UI
build-ui:
	cd web && npm install && npm run build

# Build everything (UI embedded in binary)
build-all: build-ui build

# Run the server
run:
	go run ./cmd/nyauth -config config.yaml

# Run with live reload (requires air)
dev:
	air -c .air.toml

# Run database migrations
migrate:
	go run ./cmd/nyauth -config config.yaml -migrate

# Clean build artifacts
clean:
	rm -rf bin/ web/build/ web/node_modules/

# Run tests
test:
	go test ./...

# Format code
fmt:
	go fmt ./...

# Lint
lint:
	golangci-lint run ./...

# Generate swagger docs (requires swag)
swagger:
	swag init -g cmd/nyauth/main.go -o docs

# Tidy dependencies
tidy:
	go mod tidy

# Development: run backend and frontend concurrently
dev-full:
	@echo "Starting backend and frontend..."
	@make run & cd web && npm run dev

# Docker
docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f nyauth
