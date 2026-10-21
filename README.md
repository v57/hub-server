<h1>
  <img alt="Containerization logo" src="./icon.png" width="70" valign="middle">
  &nbsp;Hub Server
</h1>

`hub-server` is the Hub server (formerly `hub-pro`; it replaces the retired `hub-lite`).
- Device identity, deny by default and grants
- Load balancers
- Permissions
- Merge hubs

## Quick Start
#### [Run from Hub cli](https://github.com/v57/hub)

#### Run from Bun
```sh
bunx v57/hub-server
```
#### Run from Source
```sh
bun i && bun .
```

## Options
- `-h`, `--help`: print the options and exit
- `-p`, `--port <port>`: listen on a specific port or address
- `--merge <address>`: will merge api to another Hub.
- `--owner <id>`: set owner key.
- `--launcher <id>`: sets launcher key that allowed to host `launcher/*` APIs.
- `--pair`: write a new pairing code, replacing the old one, print it and exit.
- `--local`: local mode, see below.
## Environment
- `HUBLISTEN`: default listen address or port.
- `HUBOWNER`: owner key to trust at startup.
- `HUBLAUNCHER`: launcher key to trust at startup.
- `HUB_MODE=local`: local mode, like `--local`.
## Pairing
A hub without owners prints a pairing code at start (`Pairing code: K7Q-2MX`) and writes it to `data/pairing-code`.
The first client to send it becomes an owner:

- `hub/pair` (post, any keyed caller) `{ code }` → `{ owner: true, hubKey, name }`. Adds the caller's key to `owners`
  and, when the connection has a device certificate, approves that device and adds it too. Case, spaces and `-` are
  ignored. Errors: `invalid pairing code`, `no pairing code`.
- `hub/pair/new` (post, owners) → `{ code, expires }`: a new code replacing the old one.

`hub-server --pair` is a one-shot: it writes a new code to `data/`, prints it and exits, also while a hub runs on the
same `data/`. The running hub re-reads `data/pairing.json` on every attempt, so the new code works at once. A code is 6
symbols of Crockford base32, valid for one hour and one success. Every check takes at least 1 s and checks run one at a
time, and 10 wrong codes invalidate the code. Only its scrypt hash is stored (`data/pairing.json`, which also counts
the wrong codes). A still-valid code survives restarts.

## Local mode
`--local` (or `HUB_MODE=local`) is for development on one machine: the hub listens on `127.0.0.1` only (never other
interfaces), runs `default-allow`, treats the launcher key (`HUBLAUNCHER`) as an owner and makes no pairing code. None of
this is written to `data/`, so the same hub started normally keeps its stored mode and owners.

## Conformance harness
`test/conformance/e2e-hub.ts` checks a Hub server over the raw protocol (`Docs/Devices/protocol.md`): hub key and v1
auth, devices, caller identity, default deny, grants, groups, reporter, selection, error codes, `hub/grant/check`,
draining, revocation and pairing. It starts
the server twice in fresh temp directories, as `<command> --port <port> --owner <SPKI>` and without `--owner` (then it
reads `Pairing code: XXX-XXX` from stdout or `data/pairing-code`, then runs `<command> --pair` next to the running
server), and exits non-zero if a check fails.

```sh
bun run conformance
# another server, such as the Swift HubServer
HUB_SERVER_CMD='swift run --package-path ../HubServer hub-server-swift' bun run conformance
```

`HUB_SERVER_CMD` runs through `sh` (default: this repo's `index.ts`); `HUB_SERVER_START_TIMEOUT` is in seconds (30).

## Load balancers:
- `random` will call random service
- `counter` will call next service in the list
- `first` will call first available service in the list
- `available` same as `counter`, but checks for availability

## Permissions
- Owners can call all Hub commands and will bypass any service permissions
- Owners can allow services to host api
- Services can provide permission for each api, so only allowed connections can use it
- Owners can create permission groups and assign keys to it
- Lockdown mode blocks any non whitelisted users to connect to Hub

- Services check permissions of their own with `hub/grant/check { path, caller }` → `{ allowed }`: true for owners
  and for callers an owner granted the path (a `path` or `prefix` grant to their key, device, group or everyone).
  A service asks only about paths under the first segment of a path it registered (`posts/moderate` for a service
  of `posts/*`); owners ask about any path.

## Draining and errors
- `hub/service/update { draining: true }` stops a connection's paths from taking new calls while its running calls
  finish (graceful shutdown, or not ready); `draining: false` undoes it. A path whose last provider drains leaves
  `hub/api`, and calls to it wait for another provider for up to 30 s, so a restarted service picks them up.
- Errors keep their v1 messages and carry a code (channel wire v2): `unauthorized`, `forbidden` (`permissions
  required`), `not_found` (`api not found`), `unavailable` (`api not available`). A service's own error passes through
  with its `code` and `info`.

## Create hub service
[TypeScript](https://github.com/v57/hub-service) [Swift](https://github.com/v57/HubService)

```ts
import { Service } from 'hub-service'
new Service().post('hash/sha256', body => new Bun.SHA256().update(body).digest('hex')).start()
```

## Client api

```ts
import { Service } from 'hub-service'
const service = new Service().start()
const hash = await service.send('hash/sha256', 'Hello World')
console.log(hash)
```
