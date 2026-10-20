## ADDED Requirements

### Requirement: Overlay addresses are unique within a Hub network
Hub MUST keep a persistent network ID and MUST allocate non-conflicting overlay addresses to registered network profiles.

#### Scenario: Two agents join same Hub
- **WHEN** two network profiles register
- **THEN** Hub assign different overlay addresses within that Hub network

### Requirement: Names are stable and collision resistant
A stable resource MUST have canonical versioned authority derived from share identity, owner identity, and Hub network identity, not display names alone.

#### Scenario: Two services publish same display name
- **WHEN** different services publish shares named `s3`
- **THEN** canonical authorities stay distinct

### Requirement: Resolution private to active profile
`hub-net` MUST resolve the reserved Hub Network namespace only while the corresponding network profile is active and authorized.

#### Scenario: Agent stopped
- **WHEN** application resolve Hub Network authority after profile stops
- **THEN** authority not resolve to publicly routable fallback

### Requirement: Non-Hub DNS not captured unnecessarily
Local resolver MUST limit authoritative handling to the reserved Hub Network namespace and MUST preserve normal resolution for unrelated names.

#### Scenario: Public website lookup
- **WHEN** application resolve name outside Hub Network suffix
- **THEN** `hub-net` not synthesize overlay response

### Requirement: Provider selection precedes authorization
Hub MUST select a live provider for a stable resource before issuing a grant. Caller MAY request a specific advertised provider.

#### Scenario: Default selection among replicas
- **WHEN** several live providers implement one resource and caller not select
- **THEN** Hub choose available provider using defined network provider-selection policy

### Requirement: Overlay routes scoped
Initial `hub-net` profile route only allocated Hub Network prefixes. MUST NOT become default internet route.

#### Scenario: Ordinary internet request
- **WHEN** application access public internet address while initial profile active
- **THEN** request follow existing non-Hub default route
