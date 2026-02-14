FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o slp-server ./cmd/slp-server/

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/slp-server /usr/local/bin/

EXPOSE 443/udp 8443/tcp 4000/udp

ENTRYPOINT ["slp-server"]
CMD ["-c", "/etc/slp/config.yaml"]
