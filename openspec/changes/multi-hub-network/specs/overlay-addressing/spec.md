## MODIFIED Requirements

### Requirement: Per-Hub translated address spaces avoid overlap
hub-net SHALL give every Hub a separate interface and persistent conflict-free
local translated IPv4/IPv6 range. Policy routing and reversible translation
SHALL isolate canonical overlapping Hub addresses.

#### Scenario: Two Hubs allocate same canonical IP
- **WHEN** device joins both simultaneously
- **THEN** each gets distinct local virtual IP and traffic reaches correct Hub

#### Scenario: Device restarts
- **WHEN** persisted translated range remains conflict-free
- **THEN** session reuses same virtual IP and host

#### Scenario: Route conflict appears
- **WHEN** persisted range overlaps live non-Hub route
- **THEN** affected session fails closed without changing another session

### Requirement: Signed canonical addressing survives translation
Connection grants, WireGuard peers, and Hub authorization SHALL continue binding
canonical Hub addresses. Translation SHALL be local routing implementation and
MUST NOT rewrite signed grant fields.

#### Scenario: Grant verified after translation
- **WHEN** application connects to translated destination
- **THEN** agent maps it to canonical address only after validating matching grant

### Requirement: DNS is isolated by local Hub alias
Each Hub SHALL have separate reserved DNS view whose local names resolve only to
that session's translated addresses. Unknown names MUST NOT use public fallback.

#### Scenario: Same share name exists in two Hubs
- **WHEN** application resolves each alias-qualified virtual host
- **THEN** each resolves to corresponding translated session address

### Requirement: Hub aliases are deterministic and stable
Join SHALL derive readable local alias from header and allocate collision suffix.
Trailing positive numeric suffix SHALL be treated as sequence notation. Alias
SHALL persist independently of later remote header changes.

#### Scenario: Three Hubs named hub join
- **WHEN** aliases allocate in order
- **THEN** names are `hub`, `hub-2`, and `hub-3`

#### Scenario: Duplicate hub-1 joins
- **WHEN** existing aliases collide
- **THEN** names progress `hub-1`, `hub-2`, and `hub-3`
