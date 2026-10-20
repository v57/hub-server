## MODIFIED Requirements

### Requirement: Node coordinates invitation bootstrap
hub-net-node SHALL accept valid invitation-scoped bootstrap sessions, exchange
bounded endpoint candidates and observed endpoints, and SHALL NOT forward Hub
RPC or application packets.

#### Scenario: Join peers rendezvous
- **WHEN** joiner and inviting agent present matching unexpired authorization
- **THEN** node exchanges coordination needed for direct temporary WireGuard peer

#### Scenario: Bootstrap direct path fails
- **WHEN** no candidate produces handshake before timeout
- **THEN** join fails explicitly without relay

### Requirement: Node state is scoped per Hub membership
hub-net SHALL key node connections, tickets, candidates, and replay state by
membership plus normalized node URL even when several Hubs use same node.

#### Scenario: Same node hosts two Hubs
- **WHEN** device joins both
- **THEN** ticket or peer event for one Hub cannot mutate other Hub session

### Requirement: Rendezvous node is never gateway
hub-net-node MUST NOT advertise internet gateway capability or receive
full-tunnel packets. Gateway is enrolled peer role.

#### Scenario: App selects exit
- **WHEN** Hub App establishes full-tunnel gateway
- **THEN** node may coordinate peer endpoints but packet path is App to peer directly
