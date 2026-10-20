## MODIFIED Requirements

### Requirement: Owners create bounded invitations
`hub/net/share` SHALL require owner authorization and one connected,
bootstrap-ready local agent. Eligible agents MAY be machine-local `hub-net`
proven through local IPC or active Apple app-agent proven through a leased
extension assertion. Invitation SHALL expire exactly ten minutes after issuance
and remain pinned to selected binding for its lifetime.

#### Scenario: Apple app-agent selected
- **WHEN** owner requests invitation with ready Apple binding and no ready machine binding
- **THEN** Hub issues invitation bound to Apple profile, tunnel instance, and agent address

#### Scenario: Local agent absent
- **WHEN** owner requests invitation without any ready local agent
- **THEN** request fails `local_agent_unavailable` and stores no token

#### Scenario: Binding disappears after issuance
- **WHEN** selected App tunnel disconnects before join completes
- **THEN** bootstrap fails closed and Hub does not switch invitation to another agent

### Requirement: Join is transactional
Join SHALL establish node-mediated direct peer with invitation-selected local
agent, reach signed hub-pro overlay destination through that peer, enroll one
profile, read one header, allocate local session, persist atomically, and
consume invitation with idempotent transaction ID. Machine and Apple inviting
agents SHALL provide behaviorally equivalent bootstrap results.

#### Scenario: Apple direct path succeeds
- **WHEN** joiner and selected Apple app-agent establish direct temporary WireGuard transport
- **THEN** join commits one membership and both sides remove invitation bootstrap state

#### Scenario: Direct path unavailable
- **WHEN** peer candidate checks fail
- **THEN** join fails in bounded time, creates no membership, and uses no relay

#### Scenario: Local commit interrupted
- **WHEN** process stops after remote enrollment but before local index commit
- **THEN** retry with same transaction recovers one membership, not duplicate

