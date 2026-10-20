## MODIFIED Requirements

### Requirement: Node coordinates invitation bootstrap
hub-net-node SHALL accept valid invitation-scoped bootstrap sessions from
joiner and invitation-selected machine or Apple inviting agent, exchange
bounded endpoint candidates and observed endpoints, and SHALL NOT forward Hub
RPC, enrollment, DNS, or application packets.

#### Scenario: Joiner and Apple App rendezvous
- **WHEN** joiner and selected Apple app-agent present matching unexpired authorization
- **THEN** node exchanges coordination needed for direct temporary WireGuard peer

#### Scenario: Bootstrap direct path fails
- **WHEN** no candidate produces handshake before timeout
- **THEN** join fails explicitly without relay

#### Scenario: Unselected local agent joins session
- **WHEN** another ready agent presents same invitation but does not match pinned binding
- **THEN** node rejects it without disclosing peer candidates

### Requirement: Bootstrap node state is bounded and isolated
hub-net-node SHALL key Apple bootstrap state by invitation token digest,
inviting-agent key, tunnel instance, transaction, and expiry. State from one
invitation or tunnel generation MUST NOT mutate another.

#### Scenario: App tunnel restarts
- **WHEN** old tunnel instance attempts to resume bootstrap after new instance binds
- **THEN** node rejects stale instance and removes its session state

#### Scenario: Invitation expires
- **WHEN** invitation reaches expiry before direct handshake
- **THEN** node removes candidates and session authorization

