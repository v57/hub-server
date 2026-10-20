## ADDED Requirements

### Requirement: Owners create bounded invitations
`hub/net/share` SHALL require owner authorization, connected explicitly bound
local hub-net, and SHALL create signed invitation expiring exactly ten minutes
after issuance.

#### Scenario: Local agent absent
- **WHEN** owner requests invitation without available local agent
- **THEN** request fails `local_agent_unavailable` and stores no token

#### Scenario: Non-owner requests invitation
- **WHEN** non-owner calls `hub/net/share`
- **THEN** Hub rejects without issuing token

### Requirement: Invitation has canonical compact encoding
Invitation SHALL use unpadded canonical base64url and canonical
`hub://net/join/<code>` link. Default node `hub.v57.dev/node` SHALL be omitted
from envelope and restored while decoding.

#### Scenario: Default node invitation encoded
- **WHEN** Hub uses default node
- **THEN** node field is absent and decoder resolves default URL

#### Scenario: Custom node invitation encoded
- **WHEN** Hub uses custom node
- **THEN** signed normalized node URL appears in envelope

#### Scenario: Bare code supplied
- **WHEN** CLI or App receives bare canonical base64url
- **THEN** it decodes same invitation as canonical deep link

### Requirement: Invitation validates before networking
Consumers MUST reject malformed URL, non-canonical base64url, unsupported major
version, duplicate/unknown critical fields, invalid signature, invalid times,
expired code, or inconsistent audience before persistent state or routes.

#### Scenario: Payload tampered
- **WHEN** attacker changes node or bootstrap destination
- **THEN** signature verification fails before connection

### Requirement: Invitation is single-use without raw-code storage
hub-pro SHALL store only token digest/ID metadata and SHALL atomically claim and
consume invitation. Concurrent or later replay MUST fail.

#### Scenario: Concurrent redemption
- **WHEN** two clients claim same issued code
- **THEN** one claim wins and other receives `invite_already_claimed`

#### Scenario: Successful join replayed
- **WHEN** consumed code is submitted again before expiry
- **THEN** Hub rejects `invite_consumed`

#### Scenario: Failed claim lease expires
- **WHEN** join fails before membership commit and code remains unexpired
- **THEN** Hub releases claim after bounded lease for retry

### Requirement: Bootstrap authorization is least privilege
Invitation SHALL independently scope node, inviting agent, joiner, and hub-pro
actions to one bootstrap/enrollment transaction and SHALL grant no ordinary RPC,
share, policy, invitation, or gateway access.

#### Scenario: Joiner calls unrelated API
- **WHEN** temporary bearer calls API outside enrollment or public header
- **THEN** Hub rejects regardless of invitation validity

### Requirement: Join is transactional
Join SHALL establish node-mediated peer, reach signed hub-pro overlay destination,
enroll one profile, read one header, allocate local session, persist atomically,
and consume invitation with idempotent transaction ID.

#### Scenario: Direct path unavailable
- **WHEN** peer candidate checks fail
- **THEN** join fails in bounded time, creates no membership, and uses no relay

#### Scenario: Local commit interrupted
- **WHEN** process stops after remote enrollment but before local index commit
- **THEN** retry with same transaction recovers one membership, not duplicate
