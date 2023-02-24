FROM golang:1-alpine AS build
WORKDIR /build
COPY . .
RUN GOPROXY=off CGO_ENABLED=0 go build -trimpath

# Using latest may break at some point, but will hopefully be convenient most of the time.
FROM alpine:latest
WORKDIR /mox
COPY --from=build /build/mox /bin/mox

RUN apk add --no-cache libcap-utils

# Allow binding to privileged ports, <1024.
RUN setcap 'cap_net_bind_service=+ep' /bin/mox

# SMTP for incoming message delivery.
EXPOSE 25/tcp
# SMTP/submission with TLS.
EXPOSE 465/tcp
# SMTP/submission without initial TLS.
EXPOSE 587/tcp
# HTTP for internal account and admin pages.
EXPOSE 80/tcp
# HTTPS for ACME (Let's Encrypt), MTA-STS and autoconfig.
EXPOSE 443/tcp
# IMAP with TLS.
EXPOSE 993/tcp
# IMAP without initial TLS.
EXPOSE 143/tcp
# Prometheus metrics.
EXPOSE 8010/tcp

CMD ["/bin/mox", "serve"]
