## ADDED Requirements

### Requirement: Active Apple tunnel can bind as local agent
Hub App SHALL bind its app-scoped profile as an `apple-app` local agent only
after PacketTunnelExtension confirms an active tunnel and
`invitation-bootstrap-v1` readiness. hub-pro SHALL bind the assertion to the
authenticated owner connection, registered profile, WireGuard key, Hub network,
and tunnel instance.

#### Scenario: Share Network becomes ready
- **WHEN** owner activates Share Network and compatible extension confirms bootstrap readiness
- **THEN** hub-pro reports an available `apple-app` local agent for that profile

#### Scenario: Unauthenticated client claims readiness
- **WHEN** client submits assertion not bound to its authenticated registered profile
- **THEN** hub-pro rejects it and local-agent status does not change

### Requirement: Apple availability is leased
Apple app-agent readiness SHALL expire after at most 30 seconds unless renewed
with a fresh extension assertion for same active tunnel instance.

#### Scenario: App stops renewing
- **WHEN** readiness lease expires
- **THEN** hub-pro marks Apple local agent unavailable and issues no new invitation against it

#### Scenario: Tunnel instance changes
- **WHEN** App restarts or replaces VPN profile
- **THEN** old instance assertions and bootstrap assignments are rejected

### Requirement: Extension owns temporary bootstrap networking
PacketTunnelExtension SHALL perform invitation rendezvous, install only exact
temporary bootstrap peers and routes, and remove them after completion,
cancellation, expiry, tunnel stop, or failure.

#### Scenario: Direct bootstrap succeeds
- **WHEN** node supplies authenticated joiner candidate and direct handshake completes
- **THEN** extension installs invitation-scoped peer and exact bootstrap routes until enrollment finishes

#### Scenario: Partial installation fails
- **WHEN** peer or route installation fails
- **THEN** extension removes all partial bootstrap state and reports failure

### Requirement: Apple app-agent grants no ambient capability
Activating Apple app-agent SHALL NOT enable gateway serving, default routes,
subnet routing, ordinary RPC, resource publication, or unrelated resource
access.

#### Scenario: Share Network activates app-agent
- **WHEN** no gateway or resource is explicitly selected
- **THEN** profile remains overlay-only and bootstrap state is absent outside active invitation transactions

