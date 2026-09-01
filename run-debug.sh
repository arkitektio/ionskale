#!/bin/sh
# Dev entrypoint: compiles ionscale from the bind-mounted source on every start,
# so a host-side edit only needs `docker compose restart ionscale`.
# `exec` (rather than `go run`) so SIGTERM reaches the server directly.
set -e
echo "=> Building ionscale from mounted source..."
# -buildvcs=false: /src is a root-owned host clone but we run as uid 100, so git
# refuses to read it ("dubious ownership") and VCS stamping fails the build.
go build -buildvcs=false -o /tmp/ionscale ./cmd/ionscale
echo "=> Starting ionscale server"
exec /tmp/ionscale server --config /etc/ionscale/config.yaml
