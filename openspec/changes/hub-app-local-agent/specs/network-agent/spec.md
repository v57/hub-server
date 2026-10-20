## ADDED Requirements

### Requirement: Local-agent implementations preserve distinct trust proofs
hub-pro SHALL support `machine` and `apple-app` local-agent kinds. Machine
registration MUST retain Unix-socket binding proof. Apple registration MUST
require owner authorization, authenticated registered profile binding, signed
extension readiness, and bounded lease. Proof from one kind MUST NOT satisfy
the other kind.

#### Scenario: App uses machine endpoint
- **WHEN** Hub App submits profile through machine-agent registration without Unix-socket proof
- **THEN** registration fails `local_agent_unavailable`

#### Scenario: Machine agent uses App endpoint
- **WHEN** non-owner daemon submits Apple readiness registration
- **THEN** registration fails `forbidden`

### Requirement: Invitation selection is deterministic
When several local-agent bindings are ready, hub-pro SHALL select by stable
documented priority and pin invitation to selected binding kind, agent key,
profile key, and generation.

#### Scenario: Machine and Apple agents are ready
- **WHEN** owner creates invitation
- **THEN** Hub selects machine binding first and records selection

#### Scenario: Selected binding disconnects
- **WHEN** pinned agent becomes unavailable during bootstrap
- **THEN** transaction fails without silently changing inviting agent

