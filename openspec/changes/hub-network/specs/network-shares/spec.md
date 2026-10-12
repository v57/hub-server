## ADDED Requirements

### Requirement: Authenticated services can publish local ports
The Hub SHALL allow an authenticated service connection to register one or more named TCP or UDP shares without requiring the service to be launched by Hub Launcher.

#### Scenario: Manually launched service publishes a TCP port
- **WHEN** an authenticated manually launched service registers a valid TCP share and local-agent attestation
- **THEN** Hub records the share as owned by that service identity and makes it discoverable according to its network policy

#### Scenario: Unauthenticated connection attempts publication
- **WHEN** a connection without a verified service identity attempts to register a network share
- **THEN** Hub rejects the registration

### Requirement: Share registration is bound to a local agent
Every live share registration MUST contain an unexpired agent attestation binding the owner key, agent key, stable share name, protocol, and local target.

#### Scenario: Service claims an unrelated agent
- **WHEN** a service submits a share with a missing, expired, mismatched, or invalid agent attestation
- **THEN** Hub rejects the share and does not advertise it

### Requirement: Live providers and persistent policy have separate lifecycles
Hub SHALL remove a live share provider when its owning service connection disconnects while retaining the stable resource policy for later registrations of the same owner and share name.

#### Scenario: Publisher reconnects after restart
- **WHEN** a service disconnects and later republishes the same stable share name using the same service identity
- **THEN** Hub restores the existing network policy and registers the new live provider

### Requirement: Share updates are atomic
A service SHALL be able to replace its complete share set, and Hub MUST atomically add, update, and remove live registrations relative to the previous set for that connection.

#### Scenario: Dynamic local port changes
- **WHEN** a service republishes a stable share with a new locally attested port
- **THEN** new discovery results use the new provider target and the old target is no longer authorized

### Requirement: Discovery returns only usable shares
Hub SHALL return only live shares visible to the requesting network profile and SHALL include stable resource identity, protocol, address authority, and available provider information.

#### Scenario: No live provider exists
- **WHEN** a permitted resource has no connected provider
- **THEN** discovery reports it as unavailable or omits it from the usable result and no connection grant is issued

### Requirement: TCP and UDP are explicit
Each share MUST declare `tcp`, `udp`, or an explicitly versioned combined mode, and authorization MUST NOT imply access to an undeclared transport.

#### Scenario: UDP access requested for TCP-only share
- **WHEN** a caller requests a UDP grant for a TCP-only resource
- **THEN** Hub rejects the request
