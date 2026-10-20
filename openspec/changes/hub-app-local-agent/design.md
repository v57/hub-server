## Context

Hub App currently registers an app-scoped network profile and installs a
WireGuardKit packet tunnel. hub-pro independently tracks one machine-local
`hub-net` binding proven through a Unix socket. Invitation issuance consults
only that binding, so an active Apple tunnel cannot invite peers. Marking the
App as available without implementing bootstrap would issue codes whose
inviting peer never joins the rendezvous session.

The change crosses hub-pro, Hub App, PacketTunnelExtension, shared wire models,
and hub-net-node. Private Apple identity and WireGuard key material remain in
the existing Keychain access group. The packet extension remains the only Apple
component allowed to mutate tunnel peers and routes.

## Goals / Non-Goals

**Goals:**

- Make an active Hub App tunnel a complete invitation-capable local agent.
- Preserve existing `hub-net` Unix-socket proof and binding behavior.
- Bind app-agent availability to authenticated owner connection, registered
  profile, tunnel instance, and short-lived readiness lease.
- Bootstrap joiners through direct temporary WireGuard paths and remove all
  temporary state deterministically.
- Keep status and Invite Code UI consistent with actual extension readiness.
- Maintain Bun, Go, and Swift wire compatibility with shared fixtures.

**Non-Goals:**

- Running or embedding Go `hub-net` inside Hub App.
- Relaying Hub RPC, enrollment, or application traffic through hub-net-node.
- Enabling gateway serving, full-tunnel routing, subnet routing, or ordinary
  resource access as a side effect of Share Network.
- Replacing the existing machine-local `hub-net` role on Linux.
- Supporting unattended invitations while Hub App or its packet tunnel is not
  running.

## Decisions

### 1. Model local agents as typed, connection-bound bindings

hub-pro stores local-agent bindings with kind `machine` or `apple-app`.
Machine bindings continue to require signed Unix-socket proof. Apple bindings
use a new owner-only control path and require:

- authenticated sender key used as registered profile identity;
- WireGuard key equal to current registered profile;
- opaque tunnel-instance ID generated for each activation;
- signed readiness assertion produced with the App profile identity;
- `invitation-bootstrap-v1` capability; and
- renewable bounded lease.

Only one binding is selected for an invitation. A ready machine binding wins;
otherwise a ready Apple binding may be selected. Invitations persist selected
kind, agent key, tunnel instance, and lease generation for audit and revocation.

Alternative: reuse `network/agent/register` and pretend the App passed local
proof. Rejected because it erases the machine-local trust boundary.

### 2. App coordinates control; extension owns bootstrap networking

Hub App sends versioned provider messages to start, refresh, and stop invitation
readiness. PacketTunnelExtension returns a signed readiness assertion containing
Hub network ID, profile key, WireGuard public key, tunnel-instance ID,
capabilities, issue time, and expiry. Hub App forwards this assertion to
hub-pro and renews it before expiry.

For each issued invitation, hub-pro sends a bounded bootstrap assignment to the
selected App connection. Hub App forwards it to PacketTunnelExtension. The
extension connects to the signed node URL, authenticates the invitation-bound
session, exchanges candidates, and temporarily installs only the joiner's
WireGuard key and bootstrap overlay routes.

Alternative: implement rendezvous in ordinary Hub App process. Rejected because
peer and route state would cross the NetworkExtension ownership boundary.

### 3. Readiness uses leases, not optimistic process state

Apple readiness leases last at most 30 seconds and are renewed while
`NEVPNStatus.connected` and provider health checks succeed. Disconnect,
sleep/wake failure, profile replacement, connection loss, missed renewal, or
explicit Share Network disable makes the binding unavailable. hub-pro rejects
new invitation issuance after lease expiry and cancels unclaimed assignments.

Alternative: persist Apple binding as durable availability. Rejected because
macOS may stop the extension independently of Hub App.

### 4. Bootstrap authorization stays invitation-scoped

Node session and temporary peer are keyed by invitation token digest,
tunnel-instance ID, transaction ID, and selected inviting-agent key. Allowed
routes contain only signed joiner and hub-pro bootstrap destinations. The
extension never installs default routes or exposes DNS/resource views from an
invitation. State expires at invitation expiry and is removed immediately after
enrollment, cancellation, tunnel stop, or handshake timeout.

hub-net-node remains signaling-only. Candidate exchange leads to direct
joiner-to-App WireGuard traffic. Failure to establish direct transport fails
the join; no relay fallback exists.

### 5. Use one versioned protocol across Bun, Go, and Swift

Shared contracts add Apple binding/readiness, assignment, status, cancellation,
and provider-message envelopes. Golden JSON fixtures and signature-input
vectors are consumed by hub-pro, hub-net-node, Hub App, and
PacketTunnelExtension tests. Unknown major versions fail closed; compatible
optional fields may be ignored.

### 6. Status reports capability source and real readiness

`hub/net/local-agent` retains existing availability fields and adds optional
binding kind and tunnel-instance metadata. Old clients ignore new fields.
Hub App shows `Available (This Mac)` only after hub-pro observes a valid lease;
an active tunnel with failed readiness shows a specific bootstrap error and
disables Invite Code.

## Trust Boundaries

- hub-pro owns owner authorization, agent selection, invitation issuance,
  transaction state, leases, and audit records.
- Hub App owns authenticated Channel control and user-visible state, but cannot
  claim readiness without a signed extension assertion.
- PacketTunnelExtension owns Apple private network state and accepts only
  assignments matching its active profile and tunnel instance.
- macOS Keychain protects App profile and WireGuard keys; raw private keys never
  cross Channel or provider messages.
- hub-net-node validates invitation-scoped authorization and exchanges
  candidates only. It is not trusted with plaintext application traffic.
- Joiner remains untrusted until signed invitation validation and enrollment
  complete.

## Failure Behavior

- Readiness assertion invalid or stale: reject bind; store no availability.
- Tunnel stops or lease expires: mark unavailable and cancel assignments.
- App connection drops: remove its connection-bound binding immediately.
- Node unreachable or no direct candidate: fail within invitation timeout.
- Temporary peer installation fails: report bounded error and remove partial
  peer/routes.
- Hub claim or enrollment fails: release claim when permitted and tear down
  bootstrap state.
- App restarts with tunnel connected: create new tunnel-instance generation,
  reassert readiness, and never resume stale assignments.

## Cross-Project Ownership

- `hub-pro`: binding registry, APIs/streams, lease expiry, selection, assignment,
  cancellation, tests.
- Hub App: activation coordinator, provider messaging, lease renewal, status UI,
  sleep/wake and reconnect handling.
- PacketTunnelExtension: readiness signing, node client, temporary peer/routes,
  bootstrap health, cleanup.
- `hub-net-node`: Apple inviting-peer compatibility and direct-only session
  validation.
- shared protocol fixtures: canonical models and signature vectors consumed by
  Bun, Go, and Swift.

## Risks / Trade-offs

- [macOS suspends App while extension runs] -> Extension assertion is bounded;
  missed App renewal disables new invitations without tearing down membership.
- [Provider messages are delayed or duplicated] -> Commands carry tunnel
  instance and monotonic generation; handling is idempotent.
- [Two local-agent implementations are ready] -> Deterministic selection and
  invitation-pinned binding prevent mid-transaction switching.
- [Temporary routes widen access] -> Install exact signed `/32` and `/128`
  bootstrap routes only; verify effective configuration before readiness.
- [Node protocol divergence] -> Pin shared fixtures and cross-language
  conformance tests before enabling API advertisement.
- [App update leaves old extension running] -> Protocol-version mismatch fails
  readiness and UI requests profile restart.

## Migration Plan

1. Land additive shared protocol models and fixtures.
2. Add hub-pro Apple binding APIs behind capability advertisement; existing
   machine bindings remain unchanged.
3. Add hub-net-node Apple inviting-peer compatibility without enabling relay.
4. Ship PacketTunnelExtension bootstrap implementation and focused live tests.
5. Enable Hub App readiness registration only when extension reports compatible
   protocol version.
6. Enable Invite Code from Apple binding after end-to-end direct bootstrap
   acceptance passes.

Rollback disables Apple binding API advertisement and lease renewal. Existing
App VPN membership, machine `hub-net` binding, invitations, and gateway behavior
remain compatible; all Apple leases naturally expire within 30 seconds.

## Open Questions

- Resolved HN-872: readiness assertions use the Hub Ed25519 identity stored in
  the Keychain access group shared by the containing App and
  PacketTunnelExtension. The assertion omits the key; hub-pro verifies it with
  the authenticated sender key. WireGuard retains its protocol-specific key.
- Whether hub-pro pushes bootstrap assignments over Channel or Hub App polls a
  connection-bound stream; both must preserve cancellation and backpressure.
- Exact macOS sleep grace period before tunnel instance must rotate.
