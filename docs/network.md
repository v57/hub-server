# Hub Network

The Hub Network is a WireGuard network between the devices of a hub. hub-server runs its control plane: it admits
agents, hands out overlay addresses, keeps shares and their policies, and signs the grants agents need to connect to
each other. The data plane is elsewhere: the `hub-net` agent on each machine (and the Hub app's packet tunnel on
Apple devices) and a coordinator, `hub-net-node`, that relays and introduces them.

The wire contract is protocol section 10 and, for agents and the coordinator,
[hub-net-node's PROTOCOL.md](https://github.com/v57/hub-net-node/blob/main/PROTOCOL.md). This page lists what the hub
serves and how to configure it. The code is `src/network/`.

## What the hub serves

| Area | Paths |
|---|---|
| Joining | `hub/net/bind` (auth): an agent binds as `machine` (proved by this machine's agent socket), `apple-app` (the Hub app) or `join` (a join admission an inviter's agent signed). Members are keyed by device, one endpoint per device; a bind also approves the device when it is allowed to |
| Coordinator | `hub/net/node` (stream, auth): the coordinator agents use; `hub/net/node/set` (owners): an address, or `null` for the default |
| Agents on the hub | `hub/net/list` (stream, owners): connections that provide `net/invite`, with their key and address; `hub/net/local-agent` (stream, owners) and `hub/net/local-agent/rebind` (owners): this machine's agent binding |
| Apple app agent | `hub/net/apple-agent/bind`, `/renew`, `/unbind` (owners) |
| Members and links | `network/agents/list`, `network/links`, `network/devices/revoked`, `network/status/agents`, `network/status/connections`, `network/diagnostics` |
| Shares | `network/shares/replace`, `network/shares/published`, `network/resource/update`, `network/resource/revoke`, `network/resource/list`, `network/resource/generations`, `network/providers/list` |
| Connections | `network/connection/grant`: a hub-signed grant for one connection to a share |
| Gateways | `network/gateway/advertise`, `/remove`, `/list`, `/grant`, `/revocations`, `/diagnostics`: a device sharing its internet connection |
| Tests | `hub/net/test/complete` and `hub/net/test/results` (owners) |

`network/*` paths check their callers themselves (protocol section 7): owners, the agent profile of the caller, or a
grant on a share. Who may open a share is a grant with a `{ share }` object ([Security](security.md#grants)).

Devices and the network meet in a few places: `hub/devices` shows each device's `network` state and `overlay`
address, removing or revoking a device removes its member and frees its addresses, and its WireGuard keys appear in
`network/devices/revoked`.

## Settings

| Setting | Where |
|---|---|
| Coordinator | `hub/net/node/set`, stored in `data/hub-net-node.json`. Without one the hub uses the coordinator v57 runs, `wss://v57.dev:1964` (`defaultHubNetNode` in `src/network/node-store.ts`) |
| Agent socket | `HUB_NET_AGENT_SOCKET`; default `/var/run/hub-net/agent.sock` on macOS, `/run/hub-net/agent.sock` elsewhere. A `machine` bind is proved over it |
| Apple app agent routes | `HUB_NET_APPLE_AGENT_ENABLED=false` (or `0`, `off`) leaves them out; `HUB_NET_APPLE_AGENT_PROTOCOL_VERSION` must equal `1` when set |
| State | `data/network.json` (members, allocations, shares, generations, the presence secret) and `data/local-agent.json` |

The overlay ranges, address release after a member leaves, share authorities and device names are protocol section
10.
