## ADDED Requirements

### Requirement: Authenticated services can publish local ports
Hub MUST let authenticated services publish TCP/UDP shares without Hub Launcher.

#### Scenario: Manually launched service publishes a TCP port
- **WHEN** authenticated manual service registers valid TCP share + local-agent attestation
- **THEN** Hub records share owned by that identity, makes discoverable per network policy

#### Scenario: Unauthenticated connection attempts publication
- **WHEN** unverified connection attempts to register network share
- **THEN** Hub rejects

### Requirement: Share registration is bound to a local agent
Every live share MUST have an unexpired agent attestation binding owner key, agent key, stable share name, protocol, and local target.

#### Scenario: Service claims an unrelated agent
- **WHEN** service submits share with missing/expired/mismatched/invalid agent attestation
- **THEN** Hub rejects, does not advertise

### Requirement: Live providers and persistent policy have separate lifecycles
Hub MUST remove a live share provider when its owning service disconnects and MUST keep stable resource policy for same-name re-registration.

#### Scenario: Publisher reconnects after restart
- **WHEN** service disconnects then republishes same stable share name using same identity
- **THEN** Hub restores existing network policy, registers new live provider

### Requirement: Share updates are atomic
Service MUST be able to replace its entire share set; Hub MUST atomically add, update, and remove live registrations relative to the previous set.

#### Scenario: Dynamic local port changes
- **WHEN** service republishes stable share with new locally attested port
- **THEN** new discovery uses new provider target, old target unauthorized

### Requirement: Discovery returns only usable shares
Hub MUST return only live shares visible to the requesting network profile and MUST include stable resource identity, protocol, address authority, and available provider information.

#### Scenario: No live provider exists
- **WHEN** permitted resource has no connected provider
- **THEN** discovery reports unavailable or omits from usable results, no connection grant issued

### Requirement: TCP and UDP are explicit
Each share MUST declare `tcp`, `udp`, or a versioned combined mode; authorization MUST NOT imply undeclared transport access.

#### Scenario: UDP access requested for TCP-only share
- **WHEN** caller requests UDP grant for TCP-only resource
- **THEN** Hub rejects
