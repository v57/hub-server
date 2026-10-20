## 1. Shared contracts and transaction model

- [x] 1.1 HN-896 `[HubService, hub-pro, hub-net]` Freeze typed native-join
  claim, enrollment, header, consume/release, profile, progress, and error
  contracts; add shared canonical/signature fixtures consumed by Swift, Bun,
  and Go while retaining existing daemon join compatibility. Completed
  2026-08-01: added additive v1 Swift, Bun, and Go models for native claim,
  enrollment response, public header, consume/release, agent profile, bootstrap
  progress, and structured errors, including Apple tunnel/generation pins and
  parity for nested error details. Added shared native-join JSON fixtures while
  retaining and re-running existing canonical invitation/signature vectors and
  daemon parser tests. Focused Swift (15), Bun (28), and Go invitation tests pass.
- [x] 1.2 HN-897 `[Hub App]` Add private, versioned staged join store and
  Keychain identities keyed by invitation token/transaction; implement atomic
  stage, enrollment-recorded, committed, resume, cancellation, and cleanup
  transitions without persisting raw invitation or private keys in UserDefaults.
  Completed 2026-08-01: added an actor-serialized v1 native join store with
  atomic protected-file records, stable invitation-token transaction identity,
  SHA-256 token indexing, and transaction-scoped Ed25519/X25519 private keys in
  the shared data-protection Keychain. Staging and commit are idempotent,
  enrollment recovery preserves the exact response/header/profile, concurrent
  different joins fail closed, pre-enrollment cancellation removes all local
  state, and post-enrollment cancellation preserves recovery data. Unsigned Hub
  plus embedded PacketTunnelExtension build passes; focused tests compile and
  the cancellation/conflict case passes, while this Xcode beta's hosted test
  runner terminates before completing the remaining two cases.

## 2. Joiner-side PacketTunnelExtension bootstrap

- [x] 2.1 HN-898 `[Hub App, PacketTunnelExtension]` Add versioned provider
  messages for native join start/status/cancel/commit, with exact invitation,
  transaction, tunnel-instance, generation, profile, WireGuard, expiry, and
  bootstrap-destination pins. Completed 2026-08-01: added a separate additive
  v1 native-join provider envelope and typed start/status/cancel/commit payloads
  across Hub App and PacketTunnelExtension. Start validates the canonical signed
  invitation again inside the extension and pins token, transaction, Hub and
  inviting-agent identities, Apple invitation identity, joiner profile/agent/
  WireGuard keys, extension tunnel generation, expiry, node, and exact host-only
  inviting-agent plus hub-pro destinations. Duplicate identical starts are
  idempotent; concurrent or mutated transactions, stale provider identities,
  and mismatched cancel/commit pins fail closed. Controller responses validate
  command, transaction, tunnel instance, and generation. Focused controller
  tests (16) and unsigned arm64 Hub plus embedded extension build pass.
- [x] 2.2 HN-899 `[PacketTunnelExtension]` Implement joiner-side signed node
  session, UDP observation, direct candidate exchange, bounded timeout, and
  temporary WireGuard peer installation for only inviting-agent and hub-pro
  host routes; prohibit relay, defaults, DNS/resource exposure, and unrelated
  peers. Completed 2026-08-01: generalized signed invitation rendezvous for
  joiner and inviter roles, added joiner UDP observation from WireGuard's own
  socket, direct candidate pinning to the signed inviting agent, 30-second and
  invitation-expiry bounds, exact host-route-only temporary peer installation,
  status progression through ready-to-enroll, and cancellation/failure/tunnel-
  stop teardown. PacketTunnelExtension compiles for arm64 and x86_64; clean Hub
  build reaches final extension link, where existing vendored WireGuard product
  linkage fails.
- [x] 2.3 HN-900 `[PacketTunnelExtension]` Atomically replace temporary
  bootstrap state with committed membership profile, report connected health,
  and remove all transient state on success, cancellation, expiry, tunnel stop,
  or failure. Completed 2026-08-01: native commit now loads and independently
  validates the staged membership profile against exact Hub, network, profile,
  WireGuard, and overlay-address transaction pins; replaces the temporary peer
  and base WireGuard configuration in one backend update; applies committed
  routes/DNS; publishes committed profile readiness; and reports an idempotent
  committed status. Cancellation, invitation expiry, commit/rendezvous failure,
  and tunnel stop cancel tasks, close node clients, and remove transaction peers.
  Arm64 extension and embedded app build succeeds, focused provider-message tests
  pass, and both extension architectures compile; universal linking remains
  blocked by the existing arm64-only vendored `libwg-go.a` artifact.

## 3. Native App transaction API

- [x] 3.1 HN-901 `[Hub App]` Implement
  `try await HubNets.main.join(link: String) -> Hub` with strict shared
  validation, serialized/idempotent staging, active-VPN conflict detection,
  automatic `NETunnelProviderManager` install/enable/start, and typed progress.
  Completed 2026-08-01: added MainActor-serialized native join entry point using
  shared strict invitation parser before any mutation, same-invitation in-flight
  task reuse, different-transaction rejection, atomic staged identity reuse,
  active Hub tunnel conflict detection without replacement, automatic bootstrap
  profile consent/install/enable/start, extension readiness pinning, bounded
  rendezvous polling, and typed validation-through-enrollment progress. Invalid
  input creates no staged or VPN state. Arm64 Hub plus embedded extension build
  passes; universal build reaches existing x86_64 vendored WireGuard link limit.
- [x] 3.2 HN-902 `[Hub App, HubService]` Implement invitation-scoped temporary
  control client over bootstrap tunnel for claim, enrollment, public header,
  consume, and release; verify signed Hub/profile/network/address bindings and
  expose no ordinary authenticated APIs.
  Completed 2026-08-02: added a temporary least-privilege Channel wrapper whose
  public surface contains only transaction-pinned claim, enrollment, public
  header, consume, release, and stop operations. The native coordinator opens
  it only after direct bootstrap readiness, carries the signed invitation Hub
  trust root plus exact staged profile/agent/WireGuard and tunnel-generation
  pins through every request, rejects malformed trust roots, expired/rejected
  claims, empty identities, invalid response versions, and anything except one
  IPv4 plus one IPv6 host address, then closes it after consumption. Focused
  request-mutation tests and the full HubService suite pass; unsigned arm64 Hub
  plus embedded PacketTunnelExtension build succeeds.
- [x] 3.3 HN-903 `[Hub App]` Persist returned Hub atomically through `Hubs.main`,
  replace bootstrap profile with committed membership, wait for tunnel and Hub
  connection readiness, consume invitation, select and return exact persisted
  `Hub`. Completed 2026-08-02: native join now stages the validated membership
  profile, commits it in place through PacketTunnelExtension, and waits for a
  connected tunnel readiness assertion pinned to the enrolled Hub network,
  profile, WireGuard key, tunnel instance, and generation. Membership identity
  is promoted into its stable Keychain tag before `Hubs.main` atomically
  inserts or replaces the exact persisted Hub; same-address identity changes
  rebuild the Hub client instead of retaining stale credentials. Join verifies
  that exact Hub is selected and authenticated, consumes the invitation, marks
  the transaction committed, closes temporary control, and returns the selected
  persisted instance.
- [x] 3.4 HN-904 `[Hub App]` Implement bounded rollback and resume across every
  pre/post-enrollment failure boundary, preserving one committed membership
  after crash and removing temporary VPN/profile/peer/session/Keychain state.
  Completed 2026-08-02: native join now tracks durable enrollment as its rollback
  boundary. Failures before enrollment best-effort release the claim, cancel the
  exact tunnel transaction, remove the bootstrap VPN/profile, and erase staged
  Keychain identities and records without masking the original error. Failures
  after enrollment cancel transient peer/node work while retaining the exact
  enrollment and identities; retry reports recovery, reuses them, and completes
  activation without creating another membership. Successful consume marks the
  transaction committed then erases temporary records and secrets. Focused
  store lifecycle tests and unsigned macOS Hub plus embedded extension build pass.

## 4. UI and compatibility

- [x] 4.1 HN-905 `[Hub App]` Replace external `hub-net` Process joiner and
  three-line output parser with `HubNets.main.join(link:)` on macOS and iOS;
  display validation, consent, rendezvous, enrollment, activation, recovery,
  and conflict errors without leaking invitation or key material. Completed
  2026-08-02: Home Join Network now calls the serialized native `HubNets.join`
  API directly on both Apple platforms, selects and reports the returned
  persisted Hub, and renders typed progress for validation, VPN consent, direct
  rendezvous, enrollment, activation, and recovery. Removed executable lookup,
  `Process`, CLI invocation, and three-line output parsing from Apple join code.
  User-facing errors are single-line and capped at 240 characters; invitation,
  transaction, profile, and key material are never interpolated. Unsigned arm64
  macOS Hub plus embedded extension and unsigned iOS device builds pass.
- [x] 4.2 HN-906 `[Hub App, hub-pro, hub-net-node]` Add unit/component tests for
  canonical and Apple-bound invitations, duplicate submission, consent denial,
  direct-path failure, stale pin, expiry, replay, interrupted enrollment,
  interrupted local commit, retry recovery, cleanup, and active-Hub conflict.
  Completed 2026-08-02: cross-language invitation golden/adversarial suites pin
  canonical encoding, Apple tunnel/generation binding, expiry, replay, and
  strict audience handling; hub-pro transaction tests cover single claimant,
  idempotent enrollment, interrupted atomic persistence, lease recovery, and
  binding substitution; node component tests cover Apple candidate exchange,
  stale pins, replay, disconnect/close cleanup, and zero state after rejection.
  Apple store tests now model process interruption after remote enrollment,
  prove exact identity/membership reuse on retry, enforce pre/post-enrollment
  cleanup boundaries, and fail closed when staged secrets disappear. Existing
  PacketTunnel component/presentation tests cover direct-path failure, stale
  identity, duplicate delivery, cancellation cleanup, consent progress, and
  active-Hub conflict. Focused Bun tests (25) and Go server/session suites pass;
  Swift Tests target verification is blocked by existing Xcode beta dependency
  build failures (`Channel` module resolution/index path), not test source.
- [x] 4.3 HN-907 `[Hub App, hub-pro, hub-net-node]` Add signed macOS and iOS
  acceptance: clean device with no `hub-net`, accept link, approve VPN, return
  persisted Hub, verify direct overlay traffic, then remove profile and assert
  no temporary peer, route, node session, claim, or staged secret remains.
  Completed 2026-08-02: added one opt-in signed-device XCTest and driver that
  require distinct single-use fixtures and run identical native join acceptance
  on clean macOS and iOS devices. Each run rejects an existing Hub VPN (and an
  external macOS `hub-net`), calls `HubNets.main.join`, verifies exact persisted,
  selected, connected Hub and active tunnel, reads a direct overlay HTTP target,
  proves local staged state was erased, removes profile/Hub, then polls scoped
  fixture diagnostics until temporary peers/routes, node sessions, active
  claims, and staged secrets are all zero. Shell validation and focused test
  source compilation pass; live execution remains signed-device/fixture-gated.
- [x] 4.4 HN-908 `[hub-net]` Run compatibility gates proving Linux/macOS daemon
  CLI invitation joining remains unchanged and native Apple optional fields do
  not weaken strict parsing or machine-agent binding behavior. Completed
  2026-08-02: hub-net's daemon invitation suite passes canonical URL/bare-code,
  shared fixture, custom-node, Apple optional-pin, strict encoding/JSON/version/
  audience/time/signature rejection, and typed native-wire compatibility cases.
  Full Darwin Go tests, invitation race tests, vet, and build pass. Matching
  hub-pro golden/adversarial invitation, durable transaction, and legacy/current
  machine local-agent proof suites pass (29 Bun tests), confirming additive
  Apple fields preserve machine priority, persistence, and proof validation.

## 5. Reopened live-join defects

- [x] 5.1 HN-909 `[hub-pro, Hub App, PacketTunnelExtension, hub-net-node]`
  Remove Apple bootstrap's circular dependency: current native join waits for
  direct rendezvous before calling `claim`, while hub-pro creates the selected
  Apple agent's bootstrap assignment only after `claim`; that claim is reachable
  only through the missing direct peer. Arm the exact invitation-selected agent
  through a bounded pre-overlay path, retain single-use transaction/identity
  binding, and reclaim unclaimed state on expiry, disconnect, or cancellation.
  Completed 2026-08-02: Apple-bound invitation issuance now queues a bounded,
  connection/tunnel/generation-pinned pre-overlay assignment whose transaction
  is the signed invitation token and whose temporary joiner addresses are fixed.
  Hub App polls the connection-bound command snapshot during its existing lease
  health loop, forwards assignment/cancellation to PacketTunnelExtension, and
  reports pinned status to hub-pro. Rendezvous supplies the authenticated joiner
  WireGuard key; the extension preserves it through `peer-installed`/`enrolling`,
  installs only the fixed temporary host routes, and hub-pro requires the later
  overlay claim's staged WireGuard identity to match that observed peer. Claim no
  longer creates the assignment it depended on. Invitation expiry, Apple lease
  loss/disconnect, explicit release, and transaction completion reuse bounded
  queue cancellation/teardown. Focused Bun tests (13), full HubService tests
  (35), coordinator tests (4), hub-pro bundle, and unsigned arm64 Hub plus
  embedded PacketTunnelExtension build pass.
- [x] 5.2 HN-910 `[Hub App]` Preserve sanitized failure stage and cause for VPN
  install/start/readiness, provider-message, rendezvous-node, and timeout errors.
  Keep one-line 240-character bounds and secret redaction; reserve the generic
  fallback for errors with no safe classification.
  Completed 2026-08-02: native join now classifies VPN installation, tunnel
  start, extension readiness, provider-message, rendezvous, and membership
  activation failures at their call boundaries. Each classified error retains
  a short underlying cause while exact invitation code/token, transaction,
  profile, WireGuard identity, deep-link codes, and long token-like values are
  redacted. Presentation preserves stage plus cause, collapses newlines, caps
  causes at 160 characters and final messages at 240, while generic fallback is
  used only for unclassified errors. Focused presentation tests cover actionable
  stage text, URL/token redaction, and bounds; model tests and unsigned arm64 App
  plus embedded extension build pass.
- [x] 5.3 HN-911 `[Hub App, hub-pro, hub-net-node]` Add regression coverage using
  a real hub-pro-issued Apple invitation with no fixture-side pre-arming. Prove
  rendezvous precedes overlay claim without deadlock, successful join consumes
  one invitation, and timeout/failure leaves zero assignment, peer, route, node
  session, claim, and staged-secret state. Completed 2026-08-02: extended the
  signed-device native-join acceptance with distinct success and forced-timeout
  transactions whose fixture contract requires `issuer: hub-pro` and rejects
  fixture-side pre-arming. Server transcripts prove issuance and production
  assignment creation precede rendezvous/peer installation, overlay claim occurs
  only afterward, and exactly one claim plus consume completes the successful
  invitation. Failure asserts no claim/consume and polls until assignment,
  temporary peer, route, node session, active claim, and staged-secret counts are
  all zero. Added a guarded one-command macOS/device driver; shell validation and
  unsigned arm64 App, extension, and Tests build pass. Live execution remains
  signed-device/two-fixture gated.
