# Running hub-server

hub-server is a Bun program (`index.ts`, the package's `bin`). It keeps everything it stores in `data/` inside the
working directory, so the folder you start it in is the hub: start it in the same folder every time.

```sh
bunx v57/hub-server                 # from GitHub
bun i && bun .                      # from a clone (bun run start does the same)
bun . --port 2000 --owner <SPKI>    # with options
```

On start it loads `data/` (creating it, mode 0700), creates the hub key `data/auth` if there is none, and listens on
port 1997 on every interface. See [Data folder](data.md) for the files.

## Options

Parsed by `index.ts`, in any order. Unknown options are ignored.

| Option | |
|---|---|
| `-p`, `--port <port>` | The port to listen on. The value is read as a number, so a `host:port` address goes in `HUBLISTEN` instead. Default 1997 |
| `--owner <key>` | Adds this key to the stored `owners` group at start. A service SPKI or a device SPKI; the key's device id is added too. May be given more than once |
| `--launcher <key>` | The launcher key: it gets a grant on `launcher/*` and may host those paths. It's no owner. Overrides `HUBLAUNCHER` |
| `--local` | Local mode, below |
| `--pair` | Writes a new pairing code to `data/`, replacing the old one, prints it and exits. Works while a hub runs on the same `data/` |
| `--merge <address>` | Merges this hub's API into another hub, below. May be given more than once |
| `--proxy <address>` | Joins another hub as a proxy, below. May be given more than once |
| `-h`, `--help` | Prints the options and exits |

Owners given with `--owner` or `HUBOWNER` are written to `data/group-members.json`, so they stay owners on later starts
without the option. Remove an owner from the `owners` group with `hub/group/update/users { group: "owners", remove }`
or from the Hub app; a key still passed with `--owner` or `HUBOWNER` comes back at the next start.

## Environment variables

| Variable | |
|---|---|
| `HUBLISTEN` | The listen port or address when `--port` isn't given: `1997`, `0.0.0.0:1997`, `127.0.0.1:2000` |
| `HUBOWNER` | One owner key, added like `--owner` |
| `HUBLAUNCHER` | The launcher key, like `--launcher` |
| `HUB_MODE=local` | Local mode, like `--local` |
| `HUB_DEVICE_KEY` | Path of this machine's device key file. Default: `/var/lib/hub/device.key` for root on Linux, else `~/.hub/device.key`. Created if missing |
| `HUB_NET_AGENT_SOCKET` | The Unix socket where this machine's Hub Network agent proves itself. Default `/var/run/hub-net/agent.sock` on macOS, `/run/hub-net/agent.sock` elsewhere |
| `HUB_NET_APPLE_AGENT_ENABLED` | `false`, `0` or `off` leaves out the `hub/net/apple-agent/*` routes |
| `HUB_NET_APPLE_AGENT_PROTOCOL_VERSION` | When set, those routes are served only if it equals the Hub Network wire version (1) |

The device key makes the hub a device of its own: at start it enrols that device as approved, with the hub key as its
service and `hub-server` as its instance. Without a readable key file the hub runs with no device and logs why. The
file format and the protocol's rules for it are in protocol section 3.

## Pairing the first owner

A new hub has no owners. Each start of a hub without owners prints a pairing code and writes it to
`data/pairing-code`:

```
Pairing code: K7Q-2MX (valid until 2026-01-01T12:00:00.000Z)
```

The first client that sends it with `hub/pair` becomes an owner: its key, and its device when the connection carries
a device certificate (the device is approved too). The Hub app does this from "Connect to a Hub" with the address and
the code, or from a `hub://pair?a=<address>&c=<code>` link. The `hub` command's `hub pair` reads the code from
`data/pairing-code` on the same machine.

Rules (protocol section 12):

- A code is 6 symbols of Crockford base32, valid for one hour and one success. Case, spaces and `-` are ignored.
- Every check takes at least one second and checks run one at a time; 10 wrong codes invalidate the code.
- Only a scrypt hash is stored (`data/pairing.json`, 0600). A valid code survives restarts.
- A child device (protocol section 14) can't become an owner, and a merged hub's connection can't pair.

To add another owner later, an owner calls `hub/pair/new` (→ `{ code, expires }`) and hands the code over, or someone
on the hub's machine runs `hub-server --pair` in the hub's folder. The running hub re-reads `data/pairing.json` on
every attempt, so the new code works at once.

## Local mode

`--local` or `HUB_MODE=local` is for development on one machine:

- the hub listens on `127.0.0.1` only, keeping the port of `--port` or `HUBLISTEN`;
- it runs `default-allow` without writing it to `data/hub.json`, so the same folder started normally keeps its stored
  mode;
- nobody is an owner because of it. A local hub without owners makes a pairing code like any other.

## The launcher key

`hub-launcher` runs services on a machine and installs hub-server. It passes its own key in `HUBLAUNCHER`. That key
gets a stored grant on the prefix `launcher/` (`by: "launcher"`) in every mode, may host `launcher/*` paths without
an owner's approval, and its device is approved at once. A start with another key moves the grant; a key revoked with
its device gets none. The launcher's key holds no other rights.

## Merging and proxies

These connect two hubs. The connection uses this hub's key (`data/auth`) and a v1 token, sent only after the other
hub proved its key; that key is pinned in `data/hub.json` (`mergeKeys`).

- **Merge** (`--merge <address>`, or `hub/merge/add` with the address as body, owners only): this hub connects to the
  other one as a service and registers its services' paths there (except `auth/*` and `launcher/*`), so callers of
  the other hub reach this hub's services. Addresses added with `hub/merge/add` are stored in `hub.json` (`merge`) and reconnected at start; ones
  given with `--merge` aren't stored. `hub/merge/remove` drops one, `hub/merge/status` streams their state.
- **Proxy** (`--proxy <address>`, or `hub/proxy/add`): this hub connects to the other one and calls `hub/proxy/join`.
  An owner of the other hub can then call this hub's paths with `hub/proxy` (post or stream)
  `{ name: <this hub's key>, path, body }`. `hub/proxy/add` also writes the address to `hub.json` (`proxies`), but
  stored proxies aren't reconnected at start: pass `--proxy` again.

A request that arrives through a merge or proxy connection is never an owner's on the receiving hub: services see the
other hub's key as the caller, with `via` and the caller the other hub claims (protocol section 4).

## Deployment

There is no container image in this repo. Ways to run it:

- **With hub-launcher** (the usual way on a machine you use): the launcher installs hub-server pinned to a release,
  passes `HUBLAUNCHER`, shows the pairing code and keeps the server running. See the `hub` command's README.
- **As a plain process**: a clone in its own folder, started with `bun .` by your process manager, with the folder
  (and its `data/`) kept across updates. Back up `data/auth` with the stores: clients pin the hub key, and a new key
  is a new hub for every device that knew the old one.

Things to know when exposing it:

- The listener speaks plain WebSocket (`ws://`). Hub SDKs dial `ws://` only on loopback, Hub Network overlay and local
  network addresses and refuse others (protocol section 2, Plaintext); use `wss://` through a TLS proxy or the Hub
  Network to reach a hub from elsewhere.
- A first start is `default-deny` and has no owners until someone pairs: start it, pair from your device, then open it
  up with grants. See [Security](security.md).
