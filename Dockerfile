FROM golang:1-alpine AS build
WORKDIR /build
RUN apk add make
COPY . .
env GOPROXY=off
RUN make build

FROM alpine:3.17
WORKDIR /mox
COPY --from=build /build/mox /mox/mox
CMD ["/mox/mox", "serve"]
