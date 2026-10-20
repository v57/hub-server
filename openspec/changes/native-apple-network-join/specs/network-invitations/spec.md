## MODIFIED Requirements

### Requirement: Join is transactional
Apple native and daemon joins SHALL establish node-mediated direct peer with the
invitation-selected local agent, reach signed hub-pro bootstrap destination,
claim invitation, enroll one profile, read one public header, persist one local
membership, activate its platform tunnel, and consume invitation with stable
idempotent transaction ID. `HubNets.main.join(link:)` SHALL return only the
persisted connected `Hub` after committed membership profile is active.

#### Scenario: Native Apple join succeeds
- **WHEN** valid invitation has direct path and user grants VPN consent
- **THEN** one Hub and membership are committed, VPN is active, invitation is consumed, and temporary bootstrap state is removed

#### Scenario: Direct path unavailable
- **WHEN** peer candidate checks fail
- **THEN** join fails in bounded time, creates no Hub or membership, removes temporary VPN state, and uses no relay

#### Scenario: Apple inviting agent is armed before overlay access
- **WHEN** hub-pro issues an Apple-bound invitation and the joiner cannot yet route to `hubProHost`
- **THEN** the selected Apple agent can enter invitation rendezvous without waiting for an overlay claim, establish the direct bootstrap peer, and only then permit the transaction-pinned claim and enrollment

#### Scenario: Bootstrap has no circular claim dependency
- **WHEN** join uses a real hub-pro-issued Apple invitation without fixture-side peer pre-arming
- **THEN** rendezvous readiness does not depend on a claim that itself requires the rendezvous-created overlay route

#### Scenario: Local commit interrupted after enrollment
- **WHEN** App terminates after remote enrollment but before Hub/tunnel commit
- **THEN** retry with same invitation resumes staged transaction and returns same membership without duplicate enrollment

#### Scenario: User cancels before enrollment
- **WHEN** user cancels or VPN consent fails before remote enrollment commits
- **THEN** App releases claim and removes staged profile, Keychain identity, peer, route, and node state

### Requirement: Bootstrap authorization is least privilege
Native Apple join bootstrap SHALL authorize only node coordination, selected
inviting peer, enrollment, public Hub header, consume, and release for one
transaction. Temporary control client MUST NOT gain normal Hub, share, policy,
invitation, resource, or gateway permissions.

#### Scenario: Temporary client calls unrelated API
- **WHEN** native join bootstrap client calls API outside invitation transaction
- **THEN** hub-pro rejects regardless of invitation validity
