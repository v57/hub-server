# The data folder

hub-server keeps its state in `data/` in its working directory. There is no option to move it: start the server in
the folder you want. The folder is created with mode 0700 at start, and a folder an older version created with wider
permissions is made private.

The Swift [HubServer](https://github.com/v57/HubServer) uses the same file names and formats (its `--data` option or
`Configuration.dataDirectory` picks the folder), so a data folder works with either server.

## Files

| File | What |
|---|---|
| `auth` | The hub key: base64 of the Ed25519 PKCS#8 private key followed by its SPKI (protocol section 1), mode 0600. Made at the first start. Clients pin its public half, so losing it makes a new hub |
| `hub.json` | Settings: `security` (below), `merge` and `proxies` (addresses), `mergeKeys` (pinned keys of merged hubs), `api` (per path: `loadBalancer`), `pendingLimit` |
| `header.json` | `{ name }`, the hub's display name for `hub/header`. The host name on a first start |
| `devices.json` | `{ schema: 1, devices, services, revokedKeys }`: devices with their state, which device each service key runs on, and keys revoked with a device |
| `grants.json` | `{ schema: 1, grants, migrated }`: every grant, and which old stores were turned into grants |
| `group-members.json` | Members of each group (`key:<SPKI>` or `device:<id>`), including the built-in `owners` group |
| `groups.json` | `{ schema: 1, groups }`: which groups exist and whether a group is a person |
| `paths.json` | Permission names of paths, from services' `permissions` and the hub's protected built-ins. In `default-allow`, a named path is restricted |
| `services.json` | Hosting approvals: which keys may provide which paths |
| `whitelist.json` | `{ enabled, whitelist }`: the whitelist of keys |
| `v1-keys.json` | `{ schema: 1, keys }`: ids of keys that authenticated with v1, refused v0 for good (protocol section 2) |
| `network.json` | The Hub Network registry: members, allocations, shares and the rest of the network state |
| `local-agent.json` | The Hub Network agent binding of this machine |
| `hub-net-node.json` | The Hub Network coordinator an owner set, or `null` for the default |
| `pairing.json` | The current pairing code's scrypt hash, salt, expiry and wrong attempts, mode 0600 |
| `pairing-code` | The plain pairing code, mode 0600, for the launcher and `hub pair` on this machine. Deleted when used or expired |

Read once and turned into grants and members if present: `clients.json` (per-key call lists), the old format of
`groups.json` (group → paths) and `group_users.json` (one group per key). The files stay; `grants.json` records that
they were migrated.

### `hub.json` security

```json
{ "security": { "mode": "default-deny", "requireV1": false, "allowV0": true } }
```

- `mode`: `default-deny` or `default-allow`. A first start (neither `hub.json` nor `auth` exists) writes
  `default-deny`. A hub that ran before without a stored mode gets `default-allow`. Either way the mode is written at
  once, so it doesn't change on the next start.
- `requireV1` with `refuseV0: true`: an owner refused v0 tokens. `allowV0: true` when they're not refused.
- `v0Until`: an ISO 8601 time after which v0 tokens are refused, or `null` after an owner took v0 back. Missing while
  the server sets no end.

Local mode changes none of this: it runs `default-allow` in memory only.

## Writes and corrupt files

- A store is written to a temporary file that is then renamed over the old one, one write at a time, so a crash never
  leaves half a file. Changes are written about a second after they happen; `v1-keys.json` is written at once, and
  so is `hub.json` when a start sets the mode.
- A file that can't be read or parsed is moved aside to `<name>.corrupt-<unix time>` and loads as empty.
- A corrupt `hub.json`, `paths.json`, `whitelist.json`, `group-members.json`, `grants.json` or `devices.json` locks
  the hub down: `default-deny`, only owners may call service paths, and the whitelist (when its file is corrupt) lets
  only owners in. The lockdown is stored as `default-deny` and ends when an owner sets the mode
  (`hub/security/mode/set`). An owner given with `--owner` or `HUBOWNER` can still get in to do that.
- While `v1-keys.json` is corrupt, every key counts as on it, so no v0 token is taken.

## Other files

- The device key (`HUB_DEVICE_KEY`, else `~/.hub/device.key`, or `/var/lib/hub/device.key` for root on Linux) lives
  outside `data/`: it identifies the machine, not the hub, and other Hub programs on the machine share it.
- Back up `data/` as a whole. The stores refer to each other (grants name groups and devices, devices name keys).
