## 1. Shared Protocol and Fixtures

- [x] 1.1 HN-800 `[hub-net protocol]` Define versioned invitation envelope,
  canonical base64url/deep-link encoding, signature domain, default-node elision,
  bootstrap scopes, error codes, and golden cross-language fixtures.
- [x] 1.2 HN-801 `[hub-net protocol]` Define gateway capability, status, grant,
  revocation, and diagnostics models with Go/TypeScript/Swift fixtures.
- [x] 1.3 HN-802 `[hub-pro]` Add adversarial fixture tests for malformed,
  non-canonical, expired, tampered, wrong-audience, and replayed invitations.

## 2. Hub Header and Local Agent

- [x] 2.1 HN-810 `[hub-pro]` Add persisted `HubHeader`, hostname initialization,
  atomic update, validation, migration, and restart tests.
- [x] 2.2 HN-811 `[hub-pro]` Implement public `hub/header` stream and owner-only
  `hub/header/set`, including permission and subscription tests.
- [x] 2.3 HN-812 `[hub-pro]` Implement explicit machine-local hub-net binding,
  authenticated local proof, reconnect lifecycle, rebind authorization, and
  unavailable diagnostics.
- [x] 2.4 HN-813 `[hub-net]` Implement local-agent binding proof and bootstrap
  capability registration without relying on Launcher.

## 3. Invitations and Bootstrap

- [x] 3.1 HN-820 `[hub-pro]` Implement owner-only `hub/net/share`, ten-minute
  signed invitation issuance, token-digest persistence, expiry cleanup, and
  default/custom node encoding.
- [x] 3.2 HN-821 `[hub-pro]` Implement atomic claim lease, idempotent enrollment
  transaction, consume/release rules, concurrent redemption tests, and raw-code
  log redaction.
- [x] 3.3 HN-822 `[hub-net-node]` Add bounded invitation bootstrap sessions,
  scoped validation, candidate exchange, abuse controls, expiry/replay tests,
  and packet-capture no-relay gate.
- [x] 3.4 HN-823 `[hub-net]` Implement invitation parser and staged join flow:
  node rendezvous, inviting-agent authorization, temporary WireGuard peer,
  private hub-pro enrollment, one-value header read, rollback, and recovery.
  Completed 2026-07-29: added strict pre-network canonical invitation decoding
  for bare codes and `hub://net/join` links, default/custom node handling,
  duplicate/unknown-field rejection, exact scope/time/address validation,
  Ed25519 Hub verification, and shared `hub-pro` golden-fixture conformance.
  Added bounded dependency-injected join orchestration for rendezvous,
  least-route temporary tunnel, claim, idempotent enrollment, one-header read,
  atomic commit, peer/tunnel cleanup, and no-relay timeout. Added durable private
  staged storage with `0600` fsync-and-rename writes, stable identity reuse,
  recorded remote enrollment, atomic versioned membership index, deterministic
  alias allocation, pre-enrollment rollback, and post-enrollment restart
  recovery without duplicate membership. Local-agent binding proof now binds
  agent/profile/Hub connection/nonce and advertises invitation bootstrap over
  peer-credential-protected Unix IPC; IPC starts before Hub registration to
  remove binding race. Parser, transaction-boundary, interrupted-commit,
  binding endpoint, full race, and vet suites pass on Darwin.
- [x] 3.5 HN-824 `[hub-net]` Add two-agent bootstrap acceptance for success,
  tampering, expiry, concurrent use, retryable failure, no direct path, node
  restart, and interruption at every transaction boundary.
  Completed 2026-07-29: added deterministic two-agent acceptance around the
  production staged join orchestrator with a shared single-use invitation Hub,
  independent private agent stores, bounded direct-only rendezvous, and
  restartable node. Acceptance proves successful enrollment, pre-network
  tamper/expiry rejection, exactly one concurrent redemption, retry after
  released pre-enrollment failure, bounded no-relay failure, node-restart
  recovery, and crash/retry at stage, rendezvous, tunnel, claim, enrollment,
  durable enrollment record, header, local commit, tunnel replacement, and
  rendezvous cleanup boundaries. Every recovery ends with exactly one local
  membership and one remote enrollment. Full Darwin race, vet, and build gates
  pass.

## 4. Multi-Hub Agent

- [x] 4.1 HN-830 `[hub-net]` Replace singleton Agent with disconnected-by-default
  supervisor and independent per-Hub sessions; isolate services, identities,
  WireGuard keys, node pools, grants, DNS, enforcement, and lifecycle.
  Completed 2026-07-29: added a process-level `Daemon` and concurrency-safe
  supervisor above the existing single-Hub `Agent` session implementation.
  Fresh daemon startup constructs no session and opens no Hub, node, or
  WireGuard connection. Each persisted membership is validated and receives a
  fresh session factory invocation with separate state/key paths, interface,
  cancellation, lifecycle, and status. Membership IDs and aliases are unique;
  idempotent adds are supported; one session failure is retained as a scoped
  diagnostic without cancelling siblings, even when sessions use the same
  rendezvous node. Removal and shutdown stop only their intended session.
  Race tests cover disconnected startup, mutable-state separation, shared-node
  isolation, sibling survival, alias/config conflicts, idempotency, and scoped
  removal. Full Go race and vet suites pass.
- [x] 4.2 HN-831 `[hub-net]` Add versioned atomic membership storage, staged
  directories, corruption isolation, restart recovery, and singleton migration
  preserving old keys/publications.
  Completed 2026-07-29: added private versioned membership index plus hashed
  per-membership directories, atomic fsync/rename record and index writes,
  recoverable staged commits, deterministic restart loading, and scoped
  diagnostics that isolate corrupt records or failed sessions while healthy
  siblings start. Added released-singleton migration that copies profile
  identity, WireGuard key, Hub binding, and publications byte-for-byte before
  publishing migration marker; legacy files remain untouched for rollback and
  gateway serving stays disabled. Full Go race and vet suites pass.
- [x] 4.3 HN-832 `[hub-net]` Implement stable alias normalization/collision
  sequence, persisted remote header refresh, exact alias lookup, and list models.
  Completed 2026-07-29: centralized deterministic DNS/CLI-safe alias
  normalization and trailing-positive-integer collision sequencing, including
  duplicate `hub-1` progression. Added exact case-sensitive alias lookup,
  atomic persisted remote-header refresh that never mutates local alias,
  reconnect callback support after session activation, and secret-free sorted
  daemon list models with header, status, translated IPs, node, and scoped
  diagnostics. Full Go race and vet suites pass.
- [x] 4.4 HN-833 `[hub-net]` Implement per-Hub interface allocation, translated
  IPv4/IPv6 pools, policy routing, reversible NAT, conflict probing, deterministic
  restart, and cleanup.
  Completed 2026-07-29: added stable hash-derived Linux-safe interface names
  and persistent membership-derived translation allocation from paired
  canonical-sized IPv4/IPv6 pools. Allocation reuses conflict-free persisted
  ranges, linearly probes live routes and sibling claims, and fails only the
  affected session on persisted conflict or exhaustion. Multi-Hub daemon
  reserves and atomically persists ranges during restore, installs networking
  only after successful WireGuard interface activation, repairs it on
  reconnect/restart, and removes exact session state on leave/shutdown.
  Linux backend installs unique translated main routes plus marked per-Hub
  canonical/translated policy tables, saves/restores conntrack marks across
  complete flows, and atomically rebuilds one owned nftables table with
  reversible IPv4/IPv6 prefix DNAT and interface-bound masquerade. Scoped
  reverse-path-filter changes are reference-counted and restored after final
  cleanup. Privileged Ubuntu namespace acceptance proves two simultaneous Hubs
  with identical canonical IPv4/IPv6 peer addresses reach distinct translated
  TCP services, deterministic reinstall preserves both families, removing one
  leaves its sibling live, and final routes/rules/nftables/sysctl state is
  clean. Darwin and Ubuntu amd64 race, vet, and build gates pass.
- [x] 4.5 HN-834 `[hub-net]` Implement alias-qualified isolated DNS views,
  translated results, no-public-fallback behavior, and duplicate-share tests.
  Completed 2026-07-29: added atomic per-Hub DNS view registry behind one
  reserved-suffix resolver. Canonical resource authorities gain stable local
  alias namespace before `hub.invalid`; canonical IPv4/IPv6 host bits map into
  each membership's persisted translated prefixes. View replace/removal cannot
  mutate siblings, invalid aliases and non-overlay addresses fail before state
  change, unqualified/unknown reserved names remain authoritative NXDOMAIN with
  no upstream fallback, and duplicate-share tests prove two Hubs resolve same
  canonical authority to distinct translated IPv4/IPv6 answers. Full Go race
  and vet suites pass.
- [x] 4.6 HN-835 `[hub-net]` Implement secured daemon command IPC and CLI
  `join`, `leave`, `list`, `removeAll`, exact join output, idempotency, and
  concurrent command serialization.
  Completed 2026-07-29: replaced singleton command startup with a
  disconnected multi-Hub daemon whose CLI subcommands communicate only over a
  private `0600` Unix management socket. Added bounded strict JSON commands,
  exact three-line join output, secret-free status listing, exact-alias leave,
  idempotent leave/removeAll, and one serialized mutation boundary for
  concurrent clients. Staged invitation joins now bridge into atomic
  membership commit and live-session activation with stable token transaction
  identity; retries reuse committed membership state. Removal first publishes
  a durable `removing` tombstone, then deletes private identity/key/session
  state, and startup finishes interrupted cleanup before loading healthy
  siblings. Tests cover socket mode, oversized requests, exact output,
  concurrent serialization, repeated leave, and crash-resumed cleanup. Real
  binary smoke covers fresh disconnected startup, list, repeated removeAll,
  SIGTERM, and socket teardown. Full Darwin race, vet, build, and diff checks
  pass.
- [x] 4.7 HN-836 `[hub-net]` Implement persistent atomic TCP+UDP `open`/`close`,
  deterministic share names, reconnect republish, grant revocation, partial
  failure rollback, and port validation.
  Completed 2026-07-30: added serialized daemon IPC and CLI commands using the
  specified `open <port> <hubname>` / `close <port> <hubname>` shape with strict
  1...65535 validation and idempotent desired-state mutations. Each open
  atomically persists and publishes stable `port-<port>-tcp` and
  `port-<port>-udp` loopback shares; each close atomically removes both through
  Hub share replacement, causing live grant-generation revocation. Per-Hub
  `0600` fsync/rename publication state is loaded before session start and
  automatically republished by hub-service-go on every reconnect. Multi-step
  failures restore prior disk state and compensate already-applied live
  changes; tests prove UDP-after-TCP failure leaves neither share. Full Darwin
  race, vet, and build gates pass.
- [x] 4.8 HN-837 `[hub-net]` Add privileged Linux multi-Hub acceptance with
  overlapping canonical ranges, translated traffic, isolated DNS/node state,
  process/machine restart, independent leave, interrupted cleanup, and removeAll.
  Completed 2026-07-30: added one guarded root-only Ubuntu acceptance command
  combining race-enabled session/node isolation, alias-qualified DNS,
  persistent restart recovery, serialized independent leave/removeAll, and
  crash-resumed cleanup with real namespace traffic. The data-plane portion
  runs inside a clean parent network namespace so host Tailscale routes and
  anti-spoof rules cannot capture the intentionally overlapping
  `100.96.0.0/11` canonical test range. Two child Hubs expose identical
  canonical IPv4/IPv6 peers through distinct translated ranges; real TCP
  traffic proves policy-route, conntrack-mark, and nftables prefix-NAT
  isolation. Deterministic reinstall repairs interrupted process/machine
  state, removing one Hub leaves its sibling live, and final teardown removes
  owned routes, rules, nftables, namespaces, and reverse-path-filter changes.
  Ubuntu amd64 acceptance, full Darwin tests, race tests, vet, and build pass.

## 5. Gateway Control Plane and Provider

- [x] 5.1 HN-840 `[hub-pro]` Add permission-filtered gateway advertisement,
  discovery/status streams, purpose-separated grants, expiry, generation
  revocation, and cross-Hub rejection.
  Completed 2026-07-30: added authenticated `internet-gateway-v1`
  advertisement/removal tied to live registered profiles, permission-filtered
  discovery, revocation, and diagnostic streams, and disconnect-triggered
  removal. Gateway grants use a distinct signature domain and bind the Hub,
  client/gateway profiles, both WireGuard keys, requested IPv4/IPv6/DNS
  capabilities, five-minute expiry, and current provider generation. Disable
  and disconnect increment generation, publish scoped revocation, reject
  renewal, and invalidate older grants. Adversarial tests cover anonymous and
  spoofed discovery/advertisement, unavailable capabilities, cross-profile and
  cross-Hub mutation, signatures, expiry generation, and disconnect cleanup.
  Full hub-pro test suite passes.
- [x] 5.2 HN-841 `[hub-net]` Implement disabled-by-default per-Hub
  `vpn allow/remove`, capability advertisement, forwarding/NAT lifecycle,
  protected-prefix firewall, flow termination, and restart behavior.
  Completed 2026-07-30: wired explicit `vpn allow <hubname>` and
  `vpn remove <hubname>` through serialized daemon IPC, atomic membership
  persistence, live per-session mutation, idempotency, rollback, list state,
  and restart restore. New memberships and singleton migrations remain
  disabled. Enabled sessions install an isolated interface-bound Linux
  nftables forward/NAT table, drop loopback/private/link-local/multicast and
  management destinations before allowing enrolled overlay sources, enable
  IPv4/IPv6 forwarding through a sibling-safe reference count, advertise
  `internet-gateway-v1` only after local setup, and republish after reconnect.
  Disable removes advertisement, exact owned firewall/NAT state, conntrack
  flows, and restores forwarding after the final gateway stops. Memory and
  Linux rule tests cover lifecycle, protected prefixes, persistent command
  idempotency, and flow teardown. Full Darwin race/vet/build and Ubuntu amd64
  focused race/vet/build gates pass.
- [x] 5.3 HN-842 `[Hub App]` Implement equivalent disabled-by-default gateway
  serving in packet-tunnel target with UI toggle and status.
  Completed 2026-07-30: added explicit persisted gateway-serving intent,
  disabled by default, with separate HubNetworkView toggle, live status, and
  bounded error presentation. Enable restarts the packet tunnel, waits for a
  connected provider, requires an extension-owned runtime acknowledgement, and
  only then advertises IPv4/IPv6/DNS gateway capability. Missing profiles,
  disconnected tunnels, startup timeouts, and provider-message failures fail
  closed and restore the previous profile/tunnel state. Disable removes Hub
  advertisement before stopping extension serving. Packet-tunnel lifecycle
  publishes disabled/enabling/available/unavailable status and clears serving
  state during teardown. Focused profile, status, and reserved-DNS unit tests
  pass; unsigned macOS Hub plus embedded extension build passes.
- [x] 5.4 HN-843 `[hub-net]` Add privileged IPv4/IPv6 gateway tests proving
  internet egress, DNS, LAN/loopback/management/other-Hub isolation, revocation,
  and no packets through hub-net-node.
  Completed 2026-07-30: added root-gated Linux namespace acceptance with
  separate client, internet/DNS, rendezvous-node, LAN, management, and
  other-Hub endpoints. Real nftables, forwarding, NAT44/NAT66, conntrack, and
  sysctl lifecycle prove IPv4/IPv6 egress and DNS with WAN-source
  masquerading; protected probes cover loopback, private/ULA, management-port,
  other-Hub, and node destinations. Node interface counters remain unchanged
  during application egress. Disable removes the owned table, restores
  forwarding, flushes tracked source flows, and immediately stops both
  families. Acceptance exposed and fixed two containment gaps: local
  destinations require an interface-scoped input chain, and IPv6 clients need
  narrowly allowed neighbor solicitation/advertisement before multicast drops.
  Ubuntu amd64 privileged acceptance plus full race, vet, and build gates pass;
  Darwin full test and vet gates pass.

## 6. Hub App

- [x] 6.1 HN-850 `[Hub App]` Add `Share Network` toggle to HubNetworkView,
  VPN-profile installation/consent, local Hub activation, deactivation, and
  state/error presentation.
  Completed 2026-07-30: HubNetworkView now exposes independent Share Network
  membership control with explicit installing, activating, active,
  deactivating, inactive, and unavailable states plus bounded inline errors.
  Enable registers the authenticated Hub App profile with its Keychain-backed
  WireGuard public key, validates Hub-assigned IPv4/IPv6 overlay addresses,
  atomically installs the NetworkExtension profile through normal macOS VPN
  consent, and waits for live tunnel activation. Membership-only packet
  tunnels now support a zero-peer WireGuard interface and overlay-only DNS and
  routes; no gateway, forwarding, NAT, or default route is enabled. Disable
  stops the tunnel without removing persisted profile, Hub, or agent state.
  App and packet-extension builds pass; focused PacketTunnelController tests
  cover profile persistence and complete UI state mapping.
- [x] 6.2 HN-851 `[Hub App]` Add owner-only Invite Code button, local-agent
  availability state, `hub/net/share` call, canonical link clipboard copy,
  expiry confirmation, and error handling.
  Completed 2026-07-30: HubNetworkView now subscribes to owner-filtered
  `hub/net/local-agent` state and exposes invitation creation only when
  `hub/net/share` permission and a connected bootstrap-capable local agent are
  both present. Creating an invitation calls `hub/net/share`, validates the
  returned canonical `hub://net/join/` link and future expiry, copies it to the
  system clipboard, and displays bounded expiry confirmation or error state.
  Focused model tests cover availability gating and wire-response decoding;
  unsigned Hub plus embedded packet-extension build and tests pass.
- [x] 6.3 HN-852 `[Hub App]` Register `hub://net/join` deep link and add Home
  code field/Join button using shared validation and transactional join.
  Completed 2026-07-30: registered the `hub` URL scheme and routed cold-launch
  and active-app `hub://net/join/` links into a Home invitation field without
  accepting unrelated Hub links. The Home card accepts canonical links or bare
  codes, validates them with HubService's shared strict signature/time/scope
  parser, exposes bounded validation and join errors, and disables duplicate
  submissions. Validated canonical links are passed as arguments (never
  through a shell) to the installed local `hub-net join` client, whose daemon
  owns staged identity, rendezvous, enrollment, atomic membership commit,
  rollback, and retry recovery. The App accepts only the daemon's exact
  three-line secret-free result. Focused router/result tests and unsigned App
  build pass.
- [x] 6.4 HN-853 `[Hub App]` Add reachable gateway list and explicit selection;
  obtain/renew grant and install IPv4, IPv6, DNS defaults while retaining
  required control-plane routes.
  Completed 2026-07-30: extended authenticated gateway advertisement/status
  with direct transport endpoint metadata across TypeScript, Go, and Swift
  contracts and producers; endpoint remains an untrusted routing hint while
  Hub-signed grants bind Hub, client/gateway profiles, WireGuard keys,
  capabilities, generation, and lifetime. Hub App lists only available
  gateway capabilities whose profile/agent/WireGuard identity exactly matches
  a registered visible agent, requires explicit Use selection, requests and
  validates a purpose-separated five-minute grant, and renews it every four
  minutes. Selection atomically replaces and starts the packet-tunnel profile
  with IPv4/IPv6 WireGuard default allowed IPs, OS default routes, and
  full-domain DNS through the gateway. Hub and peer hostnames resolve before
  default-route installation and their IPv4/IPv6 host routes remain excluded
  for control-plane continuity. Renewal failure stops the tunnel instead of
  leaving an expired exit active. Focused App/profile/DNS tests, unsigned Hub
  plus embedded extension build, full hub-pro and hub-service suites,
  HubService contract tests, and Go hub-net/hub-service-go test and vet gates
  pass.
- [x] 6.5 HN-854 `[Hub App]` Implement kill switch before default-route install,
  block on gateway/handshake/grant/DNS failure, atomic user disable, and
  crash/restart recovery.
  Completed 2026-07-30: packet extension decodes persisted exit intent and
  installs IPv4/IPv6 default capture plus full-domain gateway DNS before grant
  validation or WireGuard startup, so startup, validation, backend, settings,
  or DNS-configuration failure stays blocked instead of falling back. The
  WireGuard interface repeats gateway DNS during backend setup to avoid a
  settings-replacement leak window. Extension health checks require a recent
  authenticated handshake every fifteen seconds and enforce signed grant
  expiry; either failure stops WireGuard while retaining blocking routes and
  DNS. App renewal failure also stops the tunnel. Explicit Disable cancels
  renewal and replaces full-tunnel state with the persisted overlay-only
  profile through one serialized tunnel replacement. Persisted full-tunnel
  intent restores blocking settings before validation after extension crash or
  restart, including when the stored grant has expired. Focused profile and DNS
  tests plus unsigned Hub and embedded extension build pass.
- [x] 6.6 HN-855 `[Hub App]` Add signed-device integration tests for profile
  install, local join, clipboard/deep link, multiple overlapping Hubs, gateway
  serving, full tunnel, DNS, kill switch, revocation, and teardown.
  Completed 2026-07-30: added signed-containing-app tests that verify Hub and
  its embedded packet-tunnel extension share the provisioned development team,
  exercise canonical invitation clipboard/deep-link delivery, and provide an
  opt-in real Network Extension preference install/remove gate with explicit
  fixture inputs. Fixed simulator-only screenshot capture to skip on physical
  macOS so signed-host suites run deterministically. On the provisioned Mac,
  the signed app launched its production embedded extension and passed live
  remote WireGuard acceptance: real profile install/consent, reserved-suffix
  DNS, overlay S3 download, JPEG upload/read-back, and final profile teardown.
  Full signed App tests cover local join response/capability checks,
  gateway-serving intent/status, gateway selection binding, full-tunnel
  profile constraints, DNS fail-closed behavior, and kill-switch state. The
  complementary privileged Ubuntu gate passed simultaneous overlapping
  IPv4/IPv6 Hubs, isolated DNS, gateway forwarding/NAT, protected-prefix
  containment, immediate revocation, and clean teardown.

## 7. Conformance, Migration, and Release

- [x] 7.1 HN-860 `[hub-service-go]` Add matching HubHeader/invitation/gateway
  models and one-value stream cancellation helpers required by hub-net.
  Completed 2026-07-30: added Go wire models for public Hub headers, complete
  invitation bootstrap scopes and signed envelopes, and gateway capability,
  status, grant, revocation, and diagnostics. Canonical invitation plus shared
  gateway/rendezvous/grant/share fixtures pass exact JSON round trips.
  `Service.OneValue` and generic `OneValueTyped` read one snapshot value and
  always return the underlying Channel iterator, including error/cancellation
  paths. Race tests verify typed header reads leave no retained stream; full
  Go race and vet suites pass.
- [x] 7.2 HN-861 `[HubService]` Add matching Swift models and shared invitation
  parser used by App and packet-tunnel extension.
  Completed 2026-07-30: added public Swift HubHeader, invitation, bootstrap
  scope, gateway capability/status/grant/revocation/diagnostic models matching
  shared Go fixtures. Added one strict shared invitation parser for bare codes
  and `hub://net/join/` links with bounded canonical base64url and canonical
  JSON enforcement, duplicate/unknown-field rejection, exact scope and
  ten-minute lifetime validation, default/custom node normalization, IP
  validation, Ed25519 SPKI parsing, purpose-framed signature verification, and
  stable error codes. Shared golden fixture and adversarial parser tests pass;
  full Swift package test suite passes.
- [x] 7.3 HN-862 `[hub-service]` Add matching TypeScript public models and
  cross-language fixture conformance.
  Completed 2026-07-30: exported TypeScript HubHeader, invitation scope and
  signed-envelope, gateway capability/status/grant/revocation/diagnostic, and
  bounded diagnostic-value models matching released Go and Swift wire names.
  Shared invitation and gateway fixtures now compile against those public
  types and pass semantic plus lossless JSON round trips alongside existing
  share replacement conformance. Full Bun test suite (39 tests) and TypeScript
  no-emit check pass.
- [x] 7.4 HN-863 `[hub-pro]` Run adversarial authorization suite: forged local
  binding, invite substitution/replay/race, scope escalation, transaction
  interruption, gateway grant substitution, and immediate revocation.
  Completed 2026-07-30: expanded local-binding adversarial coverage across
  profile, connection, nonce, agent key, capability, signature, and expiry
  substitutions. Expanded gateway-grant mutation coverage across Hub, client,
  gateway, WireGuard keys, capability, and generation bindings. Added
  interrupted temporary invitation-write restart coverage proving last atomic
  state survives and the transaction resumes durably. Existing canonical
  invitation tests reject malformed encoding, duplicate/unknown fields,
  altered scope, time, audience, signature, and replay; durable claim tests
  prove one winner under concurrent redemption and idempotent consumption.
  Immediate resource and gateway disable/disconnect revocation invalidates old
  generations and rejects renewal. Focused adversarial gate passed 50 tests
  with 151 assertions; complete hub-pro suite passed 114 tests with 295
  assertions.
- [x] 7.5 HN-864 `[hub-net]` Run upgrade/downgrade acceptance from released
  singleton package, verify byte-identical key preservation and gateway-off
  default, and document recovery/reset.
  Completed 2026-07-30: extended the real Ubuntu package lifecycle gate to
  install the `0.1.0` singleton package, upgrade to the multi-Hub acceptance
  build, downgrade to `0.1.0`, upgrade again, and uninstall through Launcher's
  systemd driver while preserving inactive service state. SHA-256 manifests,
  static amd64 binary, modes, capabilities, and hardening passed. Profile
  identity and WireGuard key hashes remain byte-identical through both package
  directions and uninstall. Singleton migration copies identity, WireGuard,
  and publication bytes without touching legacy rollback files, publishes its
  marker last, is idempotent, and forces gateway serving off. Added recovery,
  rollback, and intentional destructive-reset documentation. Ubuntu package
  acceptance and focused migration test pass.
- [x] 7.6 HN-865 `[hub-pro]` Run complete release scenario: two Hubs with
  overlapping ranges, CLI and App joins, TCP+UDP persistence, node reconnect,
  invitation replay defense, peer gateway egress, kill switch, revocation,
  leave/removeAll, and proof node carries coordination only.
  Completed 2026-07-30: added one cross-platform guarded release command. Its
  signed-macOS half validates matching App/extension provisioning and runs the
  production embedded packet tunnel; live acceptance passed real profile
  install, reserved DNS, remote WireGuard S3 transfer, and teardown. Its
  Ubuntu half passed 50 adversarial authorization tests, two-agent invitation
  success/replay/race/restart/interruption recovery, serialized CLI
  open/close/leave/removeAll with TCP+UDP rollback, two simultaneous
  overlapping IPv4/IPv6 Hubs, isolated translated DNS/traffic, peer gateway
  IPv4/IPv6 egress and containment, immediate revocation, process/Hub/node
  reconnect, Launcher-supervised agent restart, S3/TCP/UDP persistence, and
  final cleanup. Packet capture proved direct WireGuard survived rendezvous
  restart while the node carried coordination only. Real package
  upgrade/downgrade also ran within the release gate.
