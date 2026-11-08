# Testing

## Unit and integration tests

```sh
bun install
bun test                         # everything in test/ and src/network/*.test.ts
bun test test/pairing.test.ts    # one file
```

`bunfig.toml` preloads `test/setup.ts`, which moves every test run into a new temporary directory and points
`HUB_DEVICE_KEY` into it, so tests never read or write the hub's own `data/` or the machine's `~/.hub/device.key`.

Most tests start a real hub in the test process (`new Hub(port)` from `src/hub.ts`) and talk to it with the channel
client. `test/helpers.ts` has what they share: `makeKey` (an Ed25519 key), `token` (a v0 or v1 `auth` token),
`challenge` (a challenge from `hub/info`), `certificate` (a `device` header), `connect`, `first` and `until` (stream
values), `waitFor` and `freePort`. The stores are module-level singletons, so one test process runs one hub's state.

Fixtures: `test/fixtures/device-vectors.json` (certificates and safety codes) and `test/fixtures/join-admission.json`
(a join admission signed by the Go agent); `src/network/testdata/crypto-v1.json` holds the Hub Network signature
vectors. The protocol's own vectors are `Docs/Devices/vectors.json` in the Hub workspace.

Pairing tests run scrypt for real and have long timeouts; on a busy machine they take a while.

## Conformance harness

`test/conformance/e2e-hub.ts` checks a Hub server from the outside, over the raw protocol, the way any client sees
it. It is the bar for every server implementation: hub-server and the Swift HubServer both pass it.

```sh
bun run conformance              # against this repo's index.ts
```

What it covers: the hub key and its proof, v1 tokens, nonces and the v0 transition, device certificates, enrolment,
safety codes and requests, approval, names and the member directory, child devices, caller identity in
`context.hub`, default deny, grants and groups, `hub/grant/check`, the reporter role, provider selection, error codes,
draining, revocation, pairing (including `--pair` next to a running server), local mode, API descriptions, and
stores written by older versions. It prints `PASS` or `FAIL` per check and `n/m passed`, and exits non-zero if a check
fails.

How it runs the server under test:

- Each start uses a fresh temporary working directory, with `HUB_DEVICE_KEY` pointing into it and `HUBLISTEN`,
  `HUBOWNER` and `HUB_MODE` cleared.
- The command is run through `sh` as `<command> --port <port>`, with `--owner <SPKI>`, `--launcher <SPKI>` and
  `--local` as a check needs them.
- Without `--owner` the server must print `Pairing code: XXX-XXX` on stdout or write it to `data/pairing-code`, and
  `<command> --pair` in the same directory must print a new code and exit while the server runs.
- Some checks plant files in `data/` first (stores from older versions), so a server must read hub-server's store
  formats from `data/` in its working directory by default.
- Ports are picked at random from 20000 up (a base in 20000–25000, other servers at offsets of up to 6000).

| Variable | |
|---|---|
| `HUB_SERVER_CMD` | The command to test, run through `sh`. Default: `bun` with this repo's `index.ts` |
| `HUB_SERVER_START_TIMEOUT` | Seconds to wait for the server to answer `hub/info` (default 30) |

### Running it against another server

```sh
HUB_SERVER_CMD='swift run --package-path ../HubServer hub-server-swift' bun run conformance
```

The Swift HubServer has a script for this, `Scripts/conformance.sh`, which builds `hub-server-swift` and runs this
harness from a `../hub-server` checkout next to it (with `bun install` done here). A new server implementation should
take the same options as hub-server (`--port`, `--owner`, `--launcher`, `--local`, `--pair`), use `data/` in its
working directory, and pass every check.
