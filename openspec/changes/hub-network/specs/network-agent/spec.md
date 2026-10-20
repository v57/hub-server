## ADDED Requirements

### Requirement: One agent provides networking to ordinary applications
`hub-net` SHALL expose authorized Hub Network resources through OS TCP/UDP networking without requiring WireGuard embed in applications.

#### Scenario: Minecraft connects through Hub Network
- **WHEN** Minecraft client connects to authorized Hub Network hostname + port
- **THEN** OS routes TCP/UDP traffic through `hub-net`. No Minecraft-specific integration needed.

### Requirement: Agent proves local publication
`hub-net` SHALL expose platform-secured local IPC endpoint that verifies service identity proofs and issues short-lived share attestations only for valid local targets.

#### Scenario: Service launched outside Launcher
- **WHEN** manually launched service proves Hub key over local IPC and requests loopback port publication
- **THEN** agent attests share without Launcher involvement

#### Scenario: Remote target requested
- **WHEN** service asks agent to attest arbitrary non-local target
- **THEN** agent rejects unless subnet-routing capability explicitly permits

### Requirement: Agent enforces grants
Target agent MUST forward traffic only when unexpired Hub-signed grant matches caller, target, resource, protocol, address, port, and authorization generation.

#### Scenario: Caller scans unshared port
- **WHEN** connected peer sends traffic to port not covered by grant
- **THEN** target agent drops or rejects traffic

### Requirement: Agent manages peers on demand
`hub-net` SHALL add WireGuard peers when authorized connection established and remove idle peer and authorization state after configurable lifetimes.

#### Scenario: Peer becomes idle
- **WHEN** no authorized flow or renewal uses peer beyond idle lifetime
- **THEN** agent removes peer and firewall state

### Requirement: Agent exposes control and status APIs
`hub-net` SHALL connect as Hub service and expose permission-controlled APIs for profile state, peer state, share health, direct-connect diagnostics, and node configuration.

#### Scenario: Hub App inspects failed connection
- **WHEN** owner opens network diagnostics after direct establishment fails
- **THEN** app obtains bounded, non-secret failure reason through Hub APIs

### Requirement: Keys are separated and protected
`hub-net` MUST use separate Hub/profile identity and WireGuard keys, store private material using platform protection, and support rotation without changing stable share ownership.

#### Scenario: WireGuard key rotates
- **WHEN** agent rotates WireGuard key
- **THEN** Hub binds new key to same profile through new short-lived grant, old sessions expire

### Requirement: Unsupported platforms fail safely
If platform WireGuard interface, privilege, or routing capability unavailable, `hub-net` MUST report unavailable and MUST NOT advertise working routes.

#### Scenario: Missing network privilege
- **WHEN** agent starts without privilege required to create interface
- **THEN** reports configuration error, publishes no reachable profile