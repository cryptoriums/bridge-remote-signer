FROM golang:1.25-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
COPY api/go.mod api/go.sum ./api/
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bridge-signer ./cmd/bridge-signer

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/bridge-signer /usr/local/bin/bridge-signer
ENTRYPOINT ["/usr/local/bin/bridge-signer"]
