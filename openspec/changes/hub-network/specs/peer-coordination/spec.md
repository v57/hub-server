## ADDED Requirements

### Requirement: Node coordinates direct connections
`hub-net-node` SHALL exchange observed endpoints and candidate coordination messages for agents to establish direct WireGuard connectivity.

#### Scenario: Direct candidate succeeds
- **WHEN** caller and target agents have compatible reachable UDP candidates
- **THEN** WireGuard handshake established, application packets travel directly between endpoints

### Requirement: Initial node never carries application traffic
Initial-release node with only `rendezvous` role MUST reject application payload forwarding and MUST NOT be configured as WireGuard peer on application data path.

#### Scenario: Direct establishment fails
- **WHEN** all candidate checks and WireGuard handshakes fail before timeout
- **THEN** connection fails with direct-connect error, no relay fallback attempted

### Requirement: Rendezvous sessions require Hub tickets
Node SHALL accept agent rendezvous session only with unexpired, correctly signed Hub ticket bound to agent identity, Hub network, protocol version, and session purpose.

#### Scenario: Replayed expired ticket
- **WHEN** agent presents expired rendezvous ticket
- **THEN** node rejects session

### Requirement: Rendezvous tickets are single-use
Node MUST atomically consume a valid `TicketID` on first successful session open and MUST reject every later use until that ticket expires. Signature, purpose, bindings, issue time, expiry, maximum lifetime, and clock skew MUST be validated before replay state is allocated. Reconnecting agent MUST obtain a fresh ticket.

#### Scenario: Two connections present same ticket concurrently
- **WHEN** two connections present same valid `TicketID` at same time
- **THEN** exactly one session opens and other receives replay rejection

#### Scenario: Invalid ticket attempts cache exhaustion
- **WHEN** client submits many invalid signatures or malformed tickets with unique identifiers
- **THEN** node rejects them without inserting identifiers into replay cache

#### Scenario: Consumed ticket expires
- **WHEN** consumed ticket reaches `ExpiresAt`
- **THEN** node may remove its identifier from bounded in-memory replay cache

#### Scenario: Single-node process restarts
- **WHEN** node uses documented in-memory replay mode and process restarts
- **THEN** replay memory resets and remaining exposure is bounded by ticket lifetime

#### Scenario: Strict or replicated deployment
- **WHEN** deployment requires replay rejection across restarts or runs multiple node replicas
- **THEN** replicas use shared replay state or route each ticket deterministically to one replay authority

### Requirement: Node is not authorization authority
Agents MUST validate Hub connection grants independently and MUST NOT treat candidate delivery by node as permission to exchange application traffic.

#### Scenario: Node substitutes target candidate
- **WHEN** malicious or compromised node supplies candidate not bound by validated peer grant
- **THEN** agent refuses to authorize candidate as target peer

### Requirement: Node roles are capability negotiated
Node protocol SHALL advertise versioned roles, with only `rendezvous` defined by this change; agents MUST NOT assume unsupported roles.

#### Scenario: Future gateway role is advertised
- **WHEN** future node advertises both `rendezvous` and `gateway` to initial client
- **THEN** initial client can use rendezvous compatibility but does not install default route or send gateway traffic

### Requirement: Coordination metadata is bounded
Node MUST enforce message-size, session, and rate limits; SHOULD retain no endpoint metadata beyond operational lifetime required for rendezvous and abuse protection.

#### Scenario: Client floods candidate messages
- **WHEN** client exceeds configured coordination rate or size limit
- **THEN** node throttles or closes session without affecting application traffic between established peers

#### Scenario: Malformed 64-bit WebSocket length
- **WHEN** unauthenticated client sends frame length larger than configured cap or platform allocation range
- **THEN** node closes connection without allocating declared length, panicking, or affecting other sessions

#### Scenario: Unmasked client frame
- **WHEN** client sends WebSocket frame without required client masking
- **THEN** node rejects frame as protocol violation before envelope processing

#### Scenario: Pre-auth connection exhaustion
- **WHEN** clients hold many incomplete HTTP upgrades or silent rendezvous connections
- **THEN** node applies global and per-source bounds plus deadlines so memory, descriptors, and goroutines remain within documented operating limits

### Requirement: Observed endpoints are delivered distinctly
Node MUST send peer-observed transport address and port as a typed field distinct from every client-declared candidate. Logging observed endpoint does not satisfy delivery.

#### Scenario: Peer is behind NAT
- **WHEN** node observes source mapping different from peer's declared host candidate
- **THEN** matched peer receives both observed mapping and declared candidates with unambiguous provenance

### Requirement: Public-node admission policy is explicit
Node documentation and configuration MUST state whether deployment trusts selected Hub keys or accepts tickets from arbitrary self-hosted Hubs. Self-contained signature proves ticket consistency but MUST NOT be represented as Sybil-resistant admission.

#### Scenario: Attacker rotates self-generated Hub and agent keys
- **WHEN** open public node accepts arbitrary self-contained Hub keys
- **THEN** global and source-based resource controls remain effective despite identity rotation

### Requirement: Protocol incompatibility is explicit
Agents and nodes SHALL reject unsupported major rendezvous protocol versions with diagnosable error.

#### Scenario: Major versions differ
- **WHEN** agent connects using unsupported major version
- **THEN** node rejects negotiation and reports supported versions without attempting peer establishment
