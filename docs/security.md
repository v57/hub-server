# Security: who may connect, host and call

This page describes the decisions hub-server makes and the APIs owners use to change them. The rules themselves are
protocol sections 2 (tokens), 4 (caller identity), 6 and 7 (APIs and their access), 8 (revocation), 9 (groups), 13
(device names) and 14 (child devices).

## Callers

A connection is one of:

- **anonymous**: no `auth` header;
- **keyed**: an `auth` token signed by a service key (an Ed25519 SPKI);
- **device-attached**: keyed, with a `device` certificate from a device the hub approved. Its caller also names the
  device.

Every request the hub forwards to a service carries the caller in `context.hub.caller`: `key`, `device`
(`{ id, name }`), `groups` and `owner`. The hub replaces any `hub` a client put in the context. Services read it as
the request's `caller` in the SDKs.

**Owners** are the members of the built-in group `owners`, by key (`key:<SPKI>`) or by device (`device:<id>`). They
come from `--owner` / `HUBOWNER`, from pairing ([Running](running.md#pairing-the-first-owner)), and from other owners
adding them. A child device (protocol section 14) is never an owner, and neither is a caller that arrives through a
merged hub.

## Modes

The mode decides calls to service paths. A new hub starts in `default-deny`; a hub that ran before the mode existed
keeps `default-allow`. The mode is stored in `data/hub.json` ([Data folder](data.md)).

A call to a service path is allowed, in this order:

1. when the caller is an owner;
2. never while the hub is locked down (below);
3. when a grant names the path for the caller's key, device, one of its groups, or everyone;
4. in `default-deny`, only when the service that provides the path marked it `public`;
5. in `default-allow`, unless the path has a permission name (a service declared `permissions` for it, or it is one
   of the hub's protected paths), which restricts it to grants.

`hub/api` and `hub/api/list` list only the paths the caller may call.

Built-in `hub/*` paths don't follow the mode: each has an access class (public, auth, reporter, grant, owner). The
table is protocol section 7. Paths the hub doesn't list there are owner-only. `network/*` paths check their callers
themselves ([Hub Network](network.md)).

Owners read and change the mode with:

- `hub/security/mode` (stream) → `{ mode, requireV1, v0Until? }`
- `hub/security/mode/set` `{ mode?, requireV1? }`. Setting it also ends a lockdown.

Local mode runs `default-allow` without storing it ([Running](running.md#local-mode)).

## Grants

A grant gives a subject access to an object:

- subject: `{ key }`, `{ device }`, `{ group }` or `{ everyone: true }`;
- object: `{ path }` (one path), `{ prefix }` (every path starting with it) or `{ share }` (a Hub Network share).

Owners manage them with `hub/grants` (stream), `hub/grant/add { subject, object }`, `hub/grant/remove { id }` and
`hub/grant/link { id, linked }` (a device's own grant that passes to its linked children, protocol section 14).
Grants are stored in `data/grants.json` and checked against what the caller is at call time; a revoked device or key
loses its grants.

A grant need not name an API. A service can define permissions of its own and ask the hub about them:
`hub/grant/check { path, caller }` → `{ allowed }`, where `caller` is the `context.hub.caller` of the request it is
handling. `allowed` is true for owners and for callers a grant names the path for, and false while the hub is locked
down. A service may only ask about paths under the first segment of a path it registered (`posts/moderate` for a
provider of `posts/*`); owners may ask about any path. The SDK side is
[hub-service's service features](https://github.com/v57/hub-service/blob/main/docs/service-features.md).

The older per-key APIs still work on top of grants: `hub/call/update { key, allow, revoke }` adds or removes path
grants for a key, `hub/call/allowed` (body: the key) lists them.

## Groups

A group has an id (its name), may be a person (`person: true`), holds members (`key:<SPKI>` or `device:<id>`) and is
the subject of grants. A member may be in any number of groups.

| Path | |
|---|---|
| `hub/group/create` | A name, or `{ name, person? }` → the group id |
| `hub/group/rename` | `{ group, name }` |
| `hub/group/remove` | The group id |
| `hub/group/update` | `{ group, add?, remove? }` or `{ group, set }`: the group's path grants |
| `hub/group/update/users` | `{ group, add?, remove? }`: members, as plain SPKIs or `device:<id>` |
| `hub/groups` (stream) | Every group with its kind, members and paths |
| `hub/group/list`, `hub/group/users`, `hub/group/names` (streams) | Older views: group → paths, members, permission names of paths |

All are owner-only.

## Hosting

Registering a path (`hub/service/update`) is public, but the hub routes calls to a provider only once its key may
host the path:

- owners may host any path, and the launcher key may host `launcher/*`;
- other keys need an owner's approval. Until then the hub keeps the provider disabled and lists the request in
  `hub/host/pending` (stream, `key → paths`);
- an owner approves or withdraws with `hub/host/update { key, allow?, revoke? }`; `hub/host/allowed` (body: the key)
  lists what a key may host. Approvals are stored in `data/services.json`;
- nobody may host `hub/*`.

## Whitelist

The whitelist turns a hub private to listed keys. `hub/whitelist { enabled?, add?, remove?, allowsCurrent? }`
(owner-only) changes it; `allowsCurrent: true` adds the keys connected right now. While it's enabled:

- a keyed connection whose key isn't listed and isn't an owner's is refused (`hub is not available`), and turning it
  on closes such connections and anonymous ones;
- an anonymous connection may call `hub/info` only, which is how a known client gets its challenge.

`hub/whitelist/status` streams `{ enabled, users }`.

## Lockdown

A store that fails to load could grant less or more than it should, so a corrupt `hub.json`, `paths.json`,
`whitelist.json`, `group-members.json`, `grants.json` or `devices.json` locks the hub down: only owners may call
service paths, the effective mode is `default-deny` (and is stored), and grant-class built-ins need an owner. An owner
ends it by setting the mode. See [Data folder](data.md#writes-and-corrupt-files).

## Tokens

Clients authenticate with v1 tokens bound to the hub's key and a one-time challenge from `hub/info` (protocol section
2). A token lives at most a minute, with 30 seconds of clock skew allowed.

v0 tokens (no challenge, sent by the Hub 1.0 app) are still taken during a transition, except:

- from a key that has used v1 on this hub and that the hub knows (`data/v1-keys.json`);
- after an owner refused them (`hub/security/mode/set { requireV1: true }`);
- after the transition end stored as `security.v0Until` in `hub.json`. The server ships with no end set.

## Devices

Devices enrol by connecting with a certificate; an owner approves them after comparing a safety code. Approval,
renaming, removal, revocation, the member directory and child devices are protocol sections 6, 8, 13 and 14. What
hub-server adds:

- the hub's own device (from the device key file) is approved at start, and the launcher key's device when it
  connects;
- an owner key connecting with a certificate, and a successful `hub/pair`, approve that device at once;
- revoked devices and keys are kept as tombstones in `data/devices.json`, so a lost file locks the hub down instead
  of letting them back in.
