## Context

`hub-net` currently constructs one `hub-service-go.Service`, profile, WireGuard
interface, DNS resolver, node configuration, and enforcement manager at process
start. Frozen Hub overlay ranges can overlap because each Hub allocates within
its own network. Existing design reserves future gateway capability but forbids
full-tunnel routing.

This change turns process into local supervisor. Each joined Hub becomes an
isolated session with its own trust root and networking state. Installation no
longer implies membership: daemon starts local command server and waits.

## Goals / Non-Goals

**Goals:**

- Join private Hub without public hub-pro endpoint.
- Run several Hub sessions concurrently despite overlapping canonical ranges.
- Keep identities, keys, node connections, DNS, routes, publications, and
  authorization isolated by Hub.
- Make join transactional and one-time code consumption race-safe.
- Provide stable human-friendly local Hub aliases.
- Let explicitly enabled peers provide internet egress to Hub App.
- Keep rendezvous node outside application traffic path.

**Non-Goals:**

- Automatically merge identities, shares, permissions, or DNS across Hubs.
- Automatically enable gateway serving, choose an exit, or install default route.
- Let Go `hub-net` consume a full-tunnel exit in this change.
- Use `hub-net-node` as relay or internet gateway.
- Provide subnet routing or public ingress.

## Decisions

### 1. Hub header is persistent extensible metadata

hub-pro stores:

```ts
interface HubHeader {
  name: string
}
```

First initialization uses OS hostname. Empty or whitespace-only updates fail;
name is trimmed and bounded to 128 Unicode scalar values. `hub/header` is
publicly readable and streams current value plus later changes.
`hub/header/set` requires Hub owner permission and atomically persists before
publishing.

Public read intentionally exposes display name. It exposes no membership,
services, keys, or network topology.

### 2. Local agent binding is explicit

hub-pro accepts local-agent registration only through authenticated local IPC
proof tied to machine installation. Registration binds active `key`,
profile key, and session connection to local role. Disconnect marks binding
unavailable; reconnect with same proof restores it. A second distinct agent
cannot replace binding without owner-authorized rebind.

`hub/net/share` fails `local_agent_unavailable` unless bound agent is connected,
registered, and capable of bootstrap.

### 3. Invitation is compact, signed, and single-use

Canonical link:

```text
hub://net/join/<base64url>
```

CLI and App accept canonical URL or bare base64url. Encoding uses unpadded
base64url over canonical versioned binary/JSON envelope. Decoders reject
padding, non-canonical re-encoding, unknown major version, duplicate fields,
malformed URLs, invalid signature, future issuance beyond clock skew, and
expired values.

Version 1 signed envelope contains only bootstrap-critical fields:

- version and signature-domain identifier
- random 256-bit token ID
- issued-at and expires-at (exactly ten minutes)
- authoritative Hub public key
- inviting local-agent bootstrap key/address identifier
- hub-pro canonical overlay host/IP needed after tunnel establishment
- optional rendezvous node URL
- Hub signature

Default node `hub.v57.dev/node` is omitted and restored by decoder. Anything
authenticated and safely learned after bootstrap, including Hub name, is
excluded.

hub-pro stores SHA-256 digest of token ID, expiry, state, and bound local-agent
key. Raw code is never stored or logged. States are `issued`, `claiming`,
`consumed`, and `expired`. Expired records may be deleted after bounded audit
retention.

### 4. Consumption is transactional

Joiner first presents invitation to node and inviting local agent. Those
components validate Hub signature, expiry, audience, and their scoped
authorization without gaining general Hub rights.

hub-pro atomically changes `issued` to `claiming` for one join transaction.
Concurrent claims lose with `invite_already_claimed`. Claim has short bounded
lease. Failures before persistent membership commit return it to `issued` when
lease expires and code lifetime remains. Successful profile enrollment commits
membership and `consumed` together. Consumed invitation always rejects replay.

Temporary scopes permit only:

- node: open bounded bootstrap rendezvous session for named token and agents
- inviting agent: establish bootstrap peer and route only hub-pro bootstrap
  destination
- joiner: establish bootstrap peer and call enrollment plus public
  `hub/header`
- hub-pro: enroll one new network profile

No scope permits arbitrary RPC, share discovery, share access, gateway use,
policy mutation, or further invitations.

### 5. Per-Hub session owns all mutable state

State root contains versioned index plus one directory per immutable local
membership ID. Each record stores remote Hub key/network ID, local alias,
Hub address, node URL, translated ranges, interface name, service/profile
identity, WireGuard key, publications, gateway-serving choice, and last header.
Private keys remain separate `0600` files. Index updates use write-fsync-rename.

Daemon starts local control IPC, loads records, and starts each valid session
independently. One corrupt or unavailable Hub reports error without blocking
others. Reconnect refreshes `hub/header` by reading first stream value and
cancelling stream; it updates stored display header but never changes local
alias automatically.

Node client pools are keyed by normalized `(hub membership ID, node URL)`.
Sessions never share tickets, trust, candidate state, or peer maps even when
node URL matches.

### 6. Join uses staged state and atomic commit

Join stages keys and networking in private temporary membership directory:

1. Parse and validate code locally.
2. Connect to node and claim bootstrap session.
3. Authorize with inviting hub-net and establish temporary WireGuard peer.
4. Reach hub-pro only at signed overlay destination.
5. Claim invitation and enroll new per-Hub profile.
6. Read one `hub/header` value, cancel stream, derive unused local alias.
7. Allocate translated ranges/interface, write complete record, atomically add
   index entry, acknowledge invitation consumption.
8. Replace temporary route with persistent session and print result.

Failure before commit tears down peer, routes, node session, staged files, and
claim. Failure after Hub membership commit retries local commit idempotently
using transaction ID; it never creates duplicate membership.

### 7. Aliases are local and collision-safe

Normalize header name by trimming, lowercasing for collision comparison, and
replacing characters invalid for local DNS/CLI with `-`. Preserve readable
display form separately. Empty normalized name becomes `hub`.

Candidate generation treats final `-<positive integer>` as sequence notation.
First candidate uses normalized name. On collision, remove numeric suffix and
choose first free base sequence starting at `2`. Thus `hub` becomes `hub`,
`hub-2`, `hub-3`; joining header `hub-1` produces `hub-1`, then `hub-2`,
then `hub-3`. Alias never changes unless membership is removed and rejoined.

CLI resolves exact alias only. `list` prints alias, remote header, status,
virtual host/IP, and node without secrets.

### 8. Overlapping ranges use per-Hub translation

Each session creates distinct WireGuard interface and retains Hub canonical
addresses inside session control logic. Local applications use deterministic,
device-local translated IPv4 and IPv6 ranges allocated from platform-reserved
Hub Network translation pools. Allocation persists and probes all active routes
before installation.

Destination NAT maps translated session addresses to canonical Hub addresses
on egress; reverse translation restores translated sources on ingress. Policy
routing binds translated ranges to session interface. Peer grants and
WireGuard `AllowedIPs` continue using canonical addresses; translation does not
alter signed fields.

Allocator chooses first conflict-free slot derived from membership ID, then
linear probes. Restart reuses persisted slot. Exhaustion or live route conflict
fails only affected session; it never steals another session range or installs
broader route.

Each Hub receives separate reserved-suffix DNS view. Local virtual hostname
includes local alias namespace and resolves only to translated IP. Unknown
names never fall through to public DNS. `join` reports this host and translated
IP.

### 9. CLI mutates daemon through local IPC

`hub-net` without subcommand runs daemon. Subcommands connect to secured local
IPC; they do not start another networking process.

- `join <code-or-url>` performs transaction and prints exactly three lines.
- `leave <hubname>` removes one membership after stopping its session.
- `list` reports all memberships, including disconnected/error states.
- `open <port> <hubname>` persists both TCP and UDP loopback publications.
- `close <port> <hubname>` removes both protocols and revokes live grants.
- `vpn allow <hubname>` enables gateway serving for that Hub.
- `vpn remove <hubname>` revokes advertisement and active gateway sessions.
- `removeAll` removes every joined-Hub record.

Port must be integer 1...65535. Repeating desired mutation is idempotent.
Publication uses deterministic stable share names `port-<port>-tcp` and
`port-<port>-udp`, targets `127.0.0.1:<port>` and `[::1]:<port>` when listener
family exists, and republishes after reconnect. Failure to publish one protocol
leaves command failed and rolls both back.

`leave` and `removeAll` stop connections, routes, DNS, firewall/NAT, node
sessions, publications, and delete per-Hub keys. Installation, daemon package,
global settings, and ordinary logs remain.

### 10. Gateway is peer role, not node role

Any `hub-net` or Hub App profile may advertise `internet-gateway-v1` after
local user enables serving for specific Hub. Disabled is default. Advertisement
includes IPv4/IPv6 availability, DNS capability, metered/status metadata, and
current reachability. It grants no access by itself.

hub-pro issues short-lived gateway grant binding Hub, client profile, gateway
profile, WireGuard keys, default-route capability, DNS, issue/expiry, and
revocation generation. Both peers validate it. Gateway permits only enrolled
profiles authorized by current grant.

Serving agent enables IP forwarding and stateful NAT only for gateway tunnel
interface/profile. Firewall blocks access to gateway's LAN, loopback, management
ports, and other Hub sessions unless separately granted. Revocation removes
advertisement, grants, forwarding state, NAT, and tracked flows immediately.

`hub-net-node` coordinates candidates only. It neither advertises gateway role
nor receives forwarded IP packets.

### 11. Only Hub App consumes full tunnel initially

Hub App lists reachable, enabled gateway peers; selection is always explicit.
Activation obtains grant, verifies peer, then installs IPv4 `0.0.0.0/0`, IPv6
`::/0`, and DNS through packet tunnel. Control-plane routes needed to maintain
Hub/node tunnel remain pinned outside captured default route as required by OS.

Kill switch becomes active before default routes. If handshake, grant renewal,
DNS, or gateway fails, packet tunnel blocks IPv4, IPv6, and DNS rather than
falling back. User disabling exit removes defaults and kill switch atomically.
No gateway is selected automatically after restart; App may remember preference
but requires explicit VPN activation.

### 12. Migration preserves old single-Hub identity

On first multi-Hub start, old singleton config converts to one session using
existing profile identity, WireGuard key, Hub address, interface binding, and
publications. Migration writes new session before marking old layout migrated.
Rollback can read untouched backup marker; no key rotates. Gateway stays off.

## Trust Boundaries

- Hub key authenticates invitation and remains authoritative for enrollment,
  permissions, grants, and revocation within that Hub.
- Invitation bearer can enroll exactly one profile before expiry; code must be
  treated as secret.
- hub-net-node learns bootstrap timing, Hub key, token identifier, and endpoint
  candidates, but no Hub credentials or application payload.
- Inviting hub-net routes bootstrap traffic only to signed hub-pro destination.
- Per-Hub identities prevent cross-Hub correlation by shared profile keys.
- Local CLI IPC relies on platform peer credentials and group/entitlement access.
- Gateway peer sees destination metadata and internet traffic not protected by
  end-to-end application encryption. UI must disclose this before selection.

## Failure Behavior

- Missing local agent: invitation issuance fails without creating token.
- Expired/tampered/replayed code: fail before persistent state or general route.
- Node or direct path unavailable: bounded failure; no relay fallback.
- Hub unreachable after bootstrap: tear down staged state and release claim.
- Alias/range exhaustion: enrollment transaction remains recoverable but no
  partially advertised local session.
- One Hub reconnect failure: other Hub sessions continue.
- Gateway loss: kill switch blocks; no local internet fallback.
- Cleanup failure: membership enters `removing`, retries on daemon restart, and
  remains unusable until cleanup completes.

## Cross-Project Ownership

- `hub-pro`: header, local binding, invite issuance/claim/consume, membership,
  gateway discovery/grants/revocation.
- shared protocol package: invitation/bootstrap/gateway wire contracts.
- `hub-net`: session supervisor, CLI IPC, join transaction, translation, DNS,
  publications, gateway serving.
- `hub-net-node`: bounded bootstrap rendezvous only.
- Hub App: user flows, deep-link handling, Apple profiles, gateway server
  controls, full-tunnel client and kill switch.
- SDKs: matching public models and cancellation semantics where needed.

## Migration / Rollout

1. Ship protocol fixtures and hub-pro header/invitation APIs disabled by feature
   gate.
2. Ship hub-net state migration and multi-session daemon without join UI.
3. Enable invite bootstrap in test Hubs and validate concurrent/replay behavior.
4. Ship Hub App local sharing and join.
5. Ship gateway serving disabled; validate NAT/firewall containment.
6. Ship Hub App full-tunnel selection behind explicit experimental setting.
7. Remove gates after cross-platform, privileged, and adversarial release gates.

Rollback disables invitation creation and gateway advertisements first. Existing
per-Hub sessions continue ordinary overlay access. Removing full-tunnel defaults
and kill switch restores ordinary network before downgrading App.
