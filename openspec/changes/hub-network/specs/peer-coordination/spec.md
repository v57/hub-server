## ADDED Requirements

### Requirement: Node coordinates direct connections
`hub-net-node` SHALL exchange observed endpoints and candidate coordination messages needed for agents to establish direct WireGuard connectivity.

#### Scenario: Direct candidate succeeds
- **WHEN** caller and target agents have compatible reachable UDP candidates
- **THEN** they establish a WireGuard handshake and subsequent application packets travel directly between their endpoints

### Requirement: Initial node never carries application traffic
An initial-release node with only the `rendezvous` role MUST reject application payload forwarding and MUST NOT be configured as a WireGuard peer on the application data path.

#### Scenario: Direct establishment fails
- **WHEN** all candidate checks and WireGuard handshakes fail before timeout
- **THEN** the connection fails with a direct-connect error and no relay fallback is attempted

### Requirement: Rendezvous sessions require Hub tickets
The node SHALL accept an agent rendezvous session only with an unexpired, correctly signed Hub ticket bound to the agent identity, Hub network, protocol version, and session purpose.

#### Scenario: Replayed expired ticket
- **WHEN** an agent presents an expired rendezvous ticket
- **THEN** the node rejects the session

### Requirement: The node is not an authorization authority
Agents MUST validate Hub connection grants independently and MUST NOT treat candidate delivery by the node as permission to exchange application traffic.

#### Scenario: Node substitutes a target candidate
- **WHEN** a malicious or compromised node supplies a candidate not bound by the validated peer grant
- **THEN** the agent refuses to authorize that candidate as the target peer

### Requirement: Node roles are capability negotiated
The node protocol SHALL advertise versioned roles, with only `rendezvous` defined by this change, and agents MUST NOT assume unsupported roles.

#### Scenario: Future gateway role is advertised
- **WHEN** a future node advertises both `rendezvous` and `gateway` to an initial client
- **THEN** the initial client can use rendezvous compatibility but does not install a default route or send gateway traffic

### Requirement: Coordination metadata is bounded
The node MUST enforce message-size, session, and rate limits and SHOULD retain no endpoint metadata beyond the operational lifetime required for rendezvous and abuse protection.

#### Scenario: Client floods candidate messages
- **WHEN** a client exceeds the configured coordination rate or size limit
- **THEN** the node throttles or closes that session without affecting application traffic between established peers

### Requirement: Protocol incompatibility is explicit
Agents and nodes SHALL reject unsupported major rendezvous protocol versions with a diagnosable error.

#### Scenario: Major versions differ
- **WHEN** an agent connects using an unsupported major version
- **THEN** the node rejects negotiation and reports supported versions without attempting peer establishment
