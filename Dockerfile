FROM golang:1.19.3-alpine3.16 AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN go build -v -o /usr/local/bin/vault-pusher ./cmd/vault-pusher
RUN go build -v -o /usr/local/bin/tbot-monitor ./cmd/tbot-monitor

FROM alpine:3.16

RUN apk add --no-cache --update ca-certificates
COPY --from=build /usr/local/bin/vault-pusher /usr/local/bin/vault-pusher
COPY --from=build /usr/local/bin/tbot-monitor /usr/local/bin/tbot-monitor
