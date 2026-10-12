## ADDED Requirements

### Requirement: Overlay addresses are unique within a Hub network
Hub SHALL maintain a persistent network identifier and allocate non-conflicting overlay addresses to registered network profiles.

#### Scenario: Two agents join the same Hub
- **WHEN** two distinct network profiles register
- **THEN** Hub assigns different overlay addresses within that Hub network

### Requirement: Names are stable and collision resistant
Every stable resource SHALL have a canonical versioned authority derived from its share identity, owner identity, and Hub network identity rather than display names alone.

#### Scenario: Two services publish the same display name
- **WHEN** different service identities publish shares named `s3`
- **THEN** their canonical authorities remain distinct

### Requirement: Resolution is private to an active profile
`hub-net` SHALL resolve the reserved Hub Network namespace only while the corresponding network profile is active and authorized.

#### Scenario: Agent is stopped
- **WHEN** an application resolves a Hub Network authority after its profile stops
- **THEN** the authority does not resolve to a publicly routable fallback

### Requirement: Non-Hub DNS is not captured unnecessarily
The local resolver MUST limit authoritative handling to the reserved Hub Network namespace and MUST preserve normal resolution for unrelated names.

#### Scenario: Public website lookup
- **WHEN** an application resolves a name outside the Hub Network suffix
- **THEN** `hub-net` does not synthesize an overlay response

### Requirement: Provider selection precedes authorization
Hub SHALL select a live provider for a stable resource before issuing a grant, and a caller MAY request a specific advertised provider.

#### Scenario: Default selection among replicas
- **WHEN** several live providers implement one resource and the caller does not select one
- **THEN** Hub chooses one available provider using the defined network provider-selection policy

### Requirement: Overlay routes are scoped
The initial `hub-net` profile SHALL route only allocated Hub Network prefixes and MUST NOT become a default internet route.

#### Scenario: Ordinary internet request
- **WHEN** an application accesses a public internet address while the initial profile is active
- **THEN** the request follows the existing non-Hub default route
