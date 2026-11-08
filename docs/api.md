# APIs

Every path the hub serves itself starts with `hub/` (or `network/` for the Hub Network). Everything else is a service
path: the hub forwards it to a connection that registered it. Calls are channel posts (one answer) or streams (values
until the end).

The protocol's API table (protocol section 6) covers `hub/info`, devices, grants, the security mode, `hub/api/list`,
`hub/api/services` and `hub/grant/check`, with their types; access classes are in section 7. This page covers the rest
and how the hub routes. For writing services and clients, use the SDKs:
[hub-service](https://github.com/v57/hub-service) (TypeScript) and [HubService](https://github.com/v57/HubService)
(Swift).

## Registering a service

A connection provides paths with `hub/service/update` (public). The body may carry:

| Field | |
|---|---|
| `services` | `ServiceHeader[]`: the connection's full list. Paths not in it any more are removed |
| `add`, `remove` | Path lists to add or remove, without headers |
| `apps`, `addApps`, `removeApps` | App headers `{ type: "app", name, path }` the connection offers, shown in `hub/status/badges` |
| `reporter` | `true`: this connection wants to be its device's reporter (protocol section 5) |
| `draining` | `true` or `false`, below |

A `ServiceHeader`:

```ts
{
  path: string
  public?: boolean          // callable by anyone in default-deny
  limit?: number            // most calls and streams this provider runs at once, 0 for no limit
  permissions?: { group?: string; name: string }  // a permission name for the path, below
  kind?: 'post' | 'stream'  // which handler the description fields describe
  title?: string; description?: string; inputSchema?: object; outputSchema?: object; annotations?: object
}
```

- `permissions` gives the path a name, `"<group>: <name>"`, with `group` defaulting to the path's first segment. Owners
  see it in `hub/group/names`, and in `default-allow` a named path needs a grant ([Security](security.md#modes)).
- The provider takes calls only once its key may host the path ([Security](security.md#hosting)).
- Everything a connection registered goes when it disconnects. Streams it was serving fail with
  `service disconnected` (code `unavailable`), so callers can subscribe again.

## Routing a call

For a call to a service path the hub:

1. finds the path, else fails with `api not found` (`not_found`);
2. checks the caller ([Security](security.md#modes)), else `permissions required` (`forbidden`);
3. picks a provider: the one `context.service` (connection id or service key) or `context.device` (device id) names,
   else the next one by the path's load balancer;
4. without a free provider, waits up to 30 seconds for one, oldest call first, then fails with `api not available`
   (`unavailable`);
5. forwards the call with the caller in `context.hub` (protocol section 4). Cancelling the call or leaving the stream
   cancels it at the provider.

A provider's own error passes back with its `code` and `info`.

### Load balancers

| Name | |
|---|---|
| `counter` | The default. The next provider in the list, skipping ones at their `limit` |
| `random` | A random provider; ignores `limit` |
| `first` | The first provider with no post call running and not at its `limit` |
| `available` | Like `counter`, but only a provider with no post call running |

Owners pick one per path with `hub/balancer/set { path, type }`; it is stored in `data/hub.json`. `hub/balancer/limit
{ limit }` caps how many calls may wait per path (0, the default, for no cap): when more wait, the oldest fail with
`api not available`.

### Draining

`hub/service/update { draining: true }` stops the connection's paths from taking new calls while its running calls and
streams finish: send it when a service shuts down or isn't ready. `draining: false` undoes it. Paths registered
meanwhile start drained. A path whose last provider drains leaves `hub/api`, and calls to it wait for another provider
as above, so a restarted service picks them up.

### Errors

Errors keep the strings older clients compare and carry a code (channel wire v2, protocol section 11):

| Message | Code |
|---|---|
| `unauthorized` | `unauthorized` |
| `permissions required` | `forbidden` |
| `api not found` | `not_found` |
| `api not available` | `unavailable` |

Connection-time errors (`unsupported version`, `invalid signature`, `invalid nonce`, `authorization expired`,
`key revoked`, `hub is not available`) refuse the connection.

## Built-in paths

Access: **public** anyone, **auth** any keyed caller, **grant** owners, approved devices or a grant, **owner** owners.

### Hub and connections

| Path | Kind | Access | Body → result |
|---|---|---|---|
| `hub/info` | post | public | `{ nonce? }` → `{ key, protocol, pro, mode, challenge, proof? }` (protocol section 2) |
| `hub/header` | stream | public | → `{ name }`, the hub's display name |
| `hub/header/set` | post | owner | `{ name }` → `{ name }`; the name is trimmed, 1 to 128 characters |
| `hub/key` | post | owner | → the hub's SPKI |
| `hub/status` | stream | public | → `{ requests, services: ServicesStatus[], pro }` |
| `hub/status/badges` | stream | public | → `{ connections, services, security, apps }`: counts, pending hosting requests, app headers |
| `hub/connections` | stream | owner | → `{ id, key?, name?, icon?, services, apps, group?, device?, instance? }[]` |
| `hub/profile/update` | post | auth | `{ name?, icon? }`: a label for this connection, never a device's name (protocol section 13) |

`ServicesStatus` is `{ name, requests, services, disabled, balancer, pending, running, draining? }` per path:
providers taking calls, providers waiting for hosting approval, the balancer, waiting calls and running calls.

### Paths and descriptions

| Path | Kind | Access | Body → result |
|---|---|---|---|
| `hub/api` | post, stream | public | → the paths the caller may call |
| `hub/api/list` | post, stream | public | → `ApiDescription[]` for those paths, below |
| `hub/api/services` | stream | auth | a path → its providers (protocol section 6) |
| `hub/service/update` | post | public | above |

### Owners and permissions

`hub/pair`, `hub/pair/new`: [Running](running.md#pairing-the-first-owner). `hub/security/mode*`, `hub/grant*`,
`hub/group*`, `hub/groups`, `hub/host/*`, `hub/call/*`, `hub/whitelist*`: [Security](security.md).
`hub/merge/*`, `hub/proxy*`: [Running](running.md#merging-and-proxies). `hub/balancer/*`: above.

### Devices

`hub/devices`, `hub/devices/pending`, `hub/devices/data` and `hub/device/*`: protocol sections 6, 8, 13 and 14.

### Hub Network

`hub/net/*` and `network/*`: [Hub Network](network.md).

## API descriptions

Services may describe each path the way MCP describes tools: a title, a description, JSON schemas for the body and the
result, and hints. They send them in their `ServiceHeader`s, one header per kind for a path served both ways; the SDKs
do this from the handler's settings ([hub-service's API descriptions](https://github.com/v57/hub-service/blob/main/docs/api-descriptions.md)).
The wire rules are protocol section 15.

What the hub keeps, per connection, path and kind:

- `title` up to 128 characters and `description` up to 4096;
- `inputSchema` and `outputSchema` when they are JSON objects of at most 64 KiB serialized;
- `annotations`: the booleans `readOnlyHint`, `destructiveHint`, `idempotentHint` and `openWorldHint`.

Anything malformed or too large is left out; the update still succeeds. A `services` update replaces the connection's
descriptions; `add` changes none. They go when the connection does.

`hub/api/list` (post, or a stream that sends a new list when `hub/api` or a description changes) answers, for the
paths `hub/api` gives the same caller, sorted by path and then kind:

```ts
type ApiDescription = {
  path: string
  kind?: 'post' | 'stream'
  title?: string; description?: string
  inputSchema?: object; outputSchema?: object
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean }
}
```

- A path has one entry per kind a header named, or a bare `{ path }` when none did.
- Only providers the hub routes calls to count: approved for hosting, draining ones included. A key waiting for
  approval describes nothing. Among them, the first provider that described a path and kind wins.
- Built-in paths are listed as `{ path, kind }`, one entry per kind the hub serves.
