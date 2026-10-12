## ADDED Requirements

### Requirement: One agent provides networking to ordinary applications
`hub-net` SHALL expose authorized Hub Network resources through ordinary operating-system TCP and UDP networking without requiring applications to embed WireGuard.

#### Scenario: Minecraft connects through Hub Network
- **WHEN** a Minecraft client connects to an authorized Hub Network hostname and port
- **THEN** the operating system routes its TCP or UDP traffic through `hub-net` without Minecraft-specific integration

### Requirement: Agent proves local publication
`hub-net` SHALL expose a platform-secured local IPC endpoint that verifies service identity proofs and issues short-lived share attestations only for valid local targets.

#### Scenario: Service launched outside Launcher
- **WHEN** a manually launched service proves its Hub key over local IPC and requests publication of its loopback port
- **THEN** the agent can attest the share without Launcher involvement

#### Scenario: Remote target requested
- **WHEN** a service asks the agent to attest an arbitrary non-local target
- **THEN** the agent rejects the request unless an explicitly specified future subnet-routing capability permits it

### Requirement: Agent enforces grants
The target agent MUST forward traffic only when an unexpired Hub-signed grant matches the caller, target, resource, protocol, address, port, and authorization generation.

#### Scenario: Caller scans an unshared port
- **WHEN** an otherwise connected peer sends traffic to a target port not covered by its grant
- **THEN** the target agent drops or rejects the traffic

### Requirement: Agent manages peers on demand
`hub-net` SHALL add WireGuard peers when an authorized connection is established and remove idle peer and authorization state after configurable bounded lifetimes.

#### Scenario: Peer becomes idle
- **WHEN** no authorized flow or renewal uses a peer beyond the idle lifetime
- **THEN** the agent removes unnecessary peer and firewall state

### Requirement: Agent exposes control and status APIs
`hub-net` SHALL connect as a Hub service and expose permission-controlled APIs or streams for profile state, peer state, share health, direct-connect diagnostics, and node configuration.

#### Scenario: Hub App inspects failed connection
- **WHEN** an owner opens network diagnostics after direct establishment fails
- **THEN** the app can obtain a bounded, non-secret failure reason through Hub APIs

### Requirement: Keys are separated and protected
`hub-net` MUST use separate Hub/profile identity and WireGuard keys, store private material using platform-appropriate protection, and support rotation without changing stable share ownership.

#### Scenario: WireGuard key rotates
- **WHEN** an agent rotates its WireGuard key
- **THEN** Hub binds the new key to the same profile through a new short-lived grant and old sessions expire

### Requirement: Unsupported platforms fail safely
If the platform WireGuard interface, required privilege, or secure routing capability is unavailable, `hub-net` MUST report itself unavailable and MUST NOT advertise working routes.

#### Scenario: Missing network privilege
- **WHEN** the agent starts without the privilege required to create its interface
- **THEN** it reports a configuration error and publishes no reachable profile
