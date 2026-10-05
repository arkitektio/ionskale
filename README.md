# ionskale

The mesh control server of an [Arkitekt](https://arkitekt.live) deployment: a fork of
[ionscale](https://github.com/jsiebens/ionscale), the open source
[Tailscale](https://tailscale.com) control server.

Arkitekt gives each organization its own private network (a tailnet), so that its devices,
apps and services reach each other directly over [WireGuard](https://www.wireguard.com/).
ionskale is the coordination server those devices register with.
[lok](https://github.com/arkitektio/lok-server), the identity provider, drives it: it
creates a tailnet when an organization gets a mesh, keeps the tailnet's policy in step with
the organization's memberships, and revokes a member's machines when the membership ends.
Users sign in to ionskale through lok, over OIDC.

The Go module, the binary and the config keys keep upstream's name, `ionscale`. Only the
repository and the image are called `ionskale`.

## What the fork adds

- **Organization-scoped tailnets.** A tailnet is bound to one organization, at most one
  per organization, and is only ever offered to identities of that organization. The
  organization and its roles come from OIDC claims; accounts are resolved by subject *and*
  organization.
- **Service tokens.** Static `svc_…` bearer tokens let a backend drive the API over plain
  HTTP, without the CLI.
- **An API an identity provider can call idempotently**: `GetTailnetByOrganization`, a
  partial `UpdateTailnet` (with rename), `RevokeAccount`, DNS extra records, and each
  user's `external_id` for reconciling membership.
- **Tailnet lock** (TKA) on the control plane.
- **Server-side quarantine** of expired and unauthorized machines.
- **Audit logging**, and a `/healthz` endpoint.
- Sign-in pages in the look of Arkitekt's own.

Everything upstream does (ACLs, MagicDNS, subnet routers, exit nodes, Tailscale SSH, …) is
unchanged.

## Configuration

One YAML file, passed as `ionscale server --config <file>`. The reference is
[mkdocs/docs/configuration/index.md](mkdocs/docs/configuration/index.md), which covers the
fork's `auth.organizations` and `auth.service_tokens` blocks too. The other pages under
[mkdocs/docs/](mkdocs/docs/) are upstream's.

lok's side of the connection is the `ionscale` block of its `CONFIG.md`.

## Images

| | Built from | Runs |
| --- | --- | --- |
| `jhnnsrs/ionskale:latest` | `Dockerfile`: a prebuilt binary copied into alpine | `ionscale` (pass `server --config …`) |
| a local dev image | `Dockerfile.dev`: the Go toolchain | `run-debug.sh` |

`Dockerfile` cannot build from source; goreleaser builds the binary first. Every push to
`main` rebuilds `jhnnsrs/ionskale:latest` for amd64 and arm64 as a rolling release. There
are no versioned image tags.

The dev image expects this repository mounted at `/src` and a config at
`/etc/ionscale/config.yaml`. `run-debug.sh` compiles the server from the mount on every
start, so a change only needs a container restart. ionscale exits if it cannot reach its
OIDC issuer while starting; set `IONSCALE_WAIT_FOR_URL` to make the script wait for it
first (`IONSCALE_WAIT_FOR_RETRIES`, default 60, two seconds apart).

## Development

```sh
make init                             # install templ, buf and the protoc plugins
make generate                         # templ + buf, after changing templates or proto
make lint                             # buf lint
make breaking                         # proto compatibility against upstream
go test -v -short ./...               # unit tests
go test -v -timeout 30m ./tests       # integration tests, needs Docker
```

The integration tests run real Tailscale clients against the server.
`IONSCALE_TESTS_TS_TARGET_VERSION` selects the client version; CI runs a matrix of recent
ones on pull requests to `main`.

## Upstream

ionscale is written by [Johan Siebens](https://github.com/jsiebens/ionscale) and licensed
under the BSD 3-Clause License; see [LICENSE](LICENSE). This fork is published under the
same licence.

This is not an official Tailscale or Tailscale Inc. project.
