## MODIFIED Requirements

### Requirement: Hub App joins from code
Home SHALL accept a canonical `hub://net/join/<code>` link or bare base64url and
SHALL join natively through `try await HubNets.main.join(link: String) -> Hub` on
macOS and iOS. Successful join SHALL persist and return one `Hub`, install and
enable the embedded packet-tunnel VPN profile, activate membership, and select
the returned Hub. Apple joining MUST NOT require, install, or execute external
`hub-net` or another privileged helper.

#### Scenario: Clean Apple device joins
- **WHEN** user submits valid invitation on device with no Hub VPN profile and no hub-net executable
- **THEN** App requests VPN consent, completes direct enrollment, persists one Hub, starts its tunnel, and returns that Hub

#### Scenario: Invalid code submitted
- **WHEN** shared parser rejects input
- **THEN** App displays bounded error and creates no VPN, transaction, Hub, peer, route, or Keychain state

#### Scenario: Another Hub VPN is active
- **WHEN** native join would replace a different active Hub tunnel
- **THEN** App rejects with actionable conflict and does not stop or mutate active tunnel

#### Scenario: Native join fails before typed rendezvous status
- **WHEN** VPN installation, tunnel start/readiness, provider messaging, or node connection fails
- **THEN** App displays a bounded sanitized cause that distinguishes the failed stage and does not expose invitation or key material

### Requirement: Apple VPN implementation keeps extension boundary
Invitation bootstrap WireGuard peers/routes, committed membership networking,
overlay routing, DNS, gateway state, and kill switch SHALL remain in
PacketTunnelExtension. Hub App MAY coordinate transaction and control-plane
messages but MUST NOT configure WireGuard or packet routes directly.

#### Scenario: Native join establishes bootstrap transport
- **WHEN** Hub App starts validated invitation transaction
- **THEN** PacketTunnelExtension alone creates and later removes temporary peer and routes
