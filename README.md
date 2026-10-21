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
- `--pair`: print a new pairing code, replacing the old one.
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
- `hub/pair/new` (post, owners and the launcher key) → `{ code, expires }`: a new code replacing the old one.

A code is 6 symbols of Crockford base32, valid for one hour and one success. Every check takes at least 1 s and checks
run one at a time, and 10 wrong codes invalidate the code. Only its scrypt hash is stored (`data/pairing.json`). A
still-valid code survives restarts; `--pair` replaces it.

## Local mode
`--local` (or `HUB_MODE=local`) is for development on one machine: the hub listens on `127.0.0.1` only (never other
interfaces), runs `default-allow`, treats the launcher key (`HUBLAUNCHER`) as an owner and makes no pairing code. None of
this is written to `data/`, so the same hub started normally keeps its stored mode and owners.

## Conformance harness
`test/conformance/e2e-hub.ts` checks a Hub server over the raw protocol (`Docs/Devices/protocol.md`): hub key and v1
auth, devices, caller identity, default deny, grants, groups, reporter, selection, revocation and pairing. It starts
the server twice in fresh temp directories, as `<command> --port <port> --owner <SPKI>` and without `--owner` (then it
reads `Pairing code: XXX-XXX` from stdout or `data/pairing-code`), and exits non-zero if a check fails.

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
