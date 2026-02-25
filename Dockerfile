FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o aegisedge .

# ---
FROM alpine:3.19

RUN apk add --no-cache ca-certificates iptables ip6tables

WORKDIR /app
COPY --from=builder /build/aegisedge .
COPY --from=builder /build/config.json .

# Optional: copy GeoIP database if present
COPY --from=builder /build/GeoLite2-Country.mmdb* ./

EXPOSE 8080 9090 9091

ENTRYPOINT ["./aegisedge"]
