FROM golang:1.27.3-alpine@sha256:dbaa054703263d06c8b49576667418473b6231f8c0fa69dee103207fdb8e3654 AS builder

RUN apk add -U --no-cache ca-certificates gcc musl-dev git

WORKDIR /build
COPY . .

RUN CGO_ENABLED=1 go build -ldflags="-extldflags=-static" -tags sqlite_omit_load_extension


FROM scratch

COPY --from=builder /build/acme-dns /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 53/udp 53 80 443
ENTRYPOINT ["/acme-dns"]
VOLUME ["/etc/acme-dns", "/var/lib/acme-dns"]
