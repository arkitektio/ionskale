#!/bin/sh
# Dev entrypoint: compiles ionscale from the bind-mounted source on every start,
# so a host-side edit only needs `docker compose restart ionscale`.
# `exec` (rather than `go run`) so SIGTERM reaches the server directly.
set -e
echo "=> Building ionscale from mounted source..."
# -buildvcs=false: /src is a root-owned host clone but we run as uid 100, so git
# refuses to read it ("dubious ownership") and VCS stamping fails the build.
go build -buildvcs=false -o /tmp/ionscale ./cmd/ionscale
# ionscale resolves its OIDC provider while starting and exits non-zero if the
# issuer cannot be reached. On a cold stack the gateway in front of the issuer
# may still be obtaining its TLS certificate, which surfaces here as
# "remote error: tls: internal error" -- a race, not a real misconfiguration.
# Probe until the issuer answers rather than dying on it. Opt-in: with the
# variable unset the server starts immediately, as it always did.
if [ -n "${IONSCALE_WAIT_FOR_URL:-}" ]; then
	echo "=> Waiting for ${IONSCALE_WAIT_FOR_URL} ..."
	attempt=0
	until wget -q -O /dev/null "$IONSCALE_WAIT_FOR_URL"; do
		attempt=$((attempt + 1))
		if [ "$attempt" -ge "${IONSCALE_WAIT_FOR_RETRIES:-60}" ]; then
			echo "=> Gave up waiting for ${IONSCALE_WAIT_FOR_URL}" >&2
			exit 1
		fi
		sleep 2
	done
	echo "=> Issuer reachable after ${attempt} retries"
fi
echo "=> Starting ionscale server"
exec /tmp/ionscale server --config /etc/ionscale/config.yaml
