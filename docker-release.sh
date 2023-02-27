#!/bin/sh

# Abort on error.
set -e

# We are using podman because docker generates errors when it's in the second
# stage and copies a non-linux/amd64 binary from the first stage that is
# linux/amd64.

# The platforms we build for (what alpine supports).
platforms=linux/amd64,linux/arm64,linux/arm,linux/386,linux/ppc64le,linux/s390x
# todo: linux/riscv64 currently absent for alpine:latest, only at alpine:edge

# We are building by "go install github.com/mjl-/mox@$moxversion", to ensure the
# binary gets a proper version stamped into its buildinfo. It also helps to ensure
# there is no accidental local change in the image.
moxversion=$(go list -mod mod -m github.com/mjl-/mox@$(git rev-parse HEAD) | cut -f2 -d' ')
echo Building mox $moxversion for $platforms, without local/uncommitted changes

# Ensure latest golang and alpine docker images.
podman image pull --quiet docker.io/golang:1-alpine
for i in $(echo $platforms | sed 's/,/ /g'); do
	podman image pull --quiet --platform $i docker.io/alpine:latest
done
# "Last pulled" apparently is the one used for "podman run" below, not the one
# that matches the platform. So pull for current platform again.
podman image pull --quiet docker.io/alpine:latest

# Get the goland and alpine versions from the docker images.
goversion=$(podman run golang:1-alpine go version | cut -f3 -d' ')
alpineversion=alpine$(podman run alpine:latest cat /etc/alpine-release)
# We assume the alpines for all platforms have the same version...
echo Building with $goversion and $alpineversion

test -d empty || mkdir empty
podman build --platform $platforms -f Dockerfile.release -v $HOME/go/pkg/sumdb:/go/pkg/sumbd:ro --build-arg moxversion=$moxversion --manifest docker.io/moxmail/mox:$moxversion-$goversion-$alpineversion empty

cat <<EOF

# Suggested commands to push images:

podman manifest push --all docker.io/moxmail/mox:$moxversion-$goversion-$alpineversion

podman tag docker.io/moxmail/mox:$moxversion-$goversion-$alpineversion docker.io/moxmail/mox:$moxversion
podman manifest push --all docker.io/moxmail/mox:$moxversion

podman tag docker.io/moxmail/mox:$moxversion docker.io/moxmail/mox:latest
podman manifest push --all docker.io/moxmail/mox:latest
EOF
