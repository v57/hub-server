## ADDED Requirements

### Requirement: Go, Bun, Swift publication APIs equivalent
`hub-service-go`, `hub-service`, `HubService` MUST expose equivalent models and behavior for share name, protocol, local port, access policy, and stable identity.

#### Scenario: Cross-language publication equivalent
- **WHEN** equivalent Go, Bun, Swift services publish same share config
- **THEN** Hub receives protocol-compatible registration fields, same semantics

### Requirement: Go Hub service SDK first
`hub-service-go` MUST provide reusable Hub identity, auth, registration, request, streaming, reconnect, profile, API-setting, network-publication behavior before `hub-net` begins implementation.

#### Scenario: Go agent registers with Hub
- **WHEN** `hub-net` needs connect, advertise control APIs, or consume Hub APIs
- **THEN** uses released `hub-service-go` SDK, not private Hub client

### Requirement: Go SDK needs conformant Channel library
`hub-service-go` MUST depend on stabilized `channel-go` module passing supported-platform tests, race detection, TypeScript Channel interoperability tests.

#### Scenario: Channel wire behavior changes
- **WHEN** TypeScript fixture reveals incompatible Go behavior
- **THEN** incompatibility resolved or versioned before `hub-service-go` release

### Requirement: Service libraries: no embedded WireGuard
Go, Bun, Swift service libraries MUST use Hub registration, local-agent IPC for network publication. MUST NOT include WireGuard implementation.

#### Scenario: Service adds share
- **WHEN** application adopts network-share API
- **THEN** only separate agent or platform extension provides WireGuard packet processing

### Requirement: Local S3 uses actual selected port
`hub-s3-local` SHALL publish runtime-selected port, SHALL construct overlay-compatible S3 endpoints, presigned URLs using canonical share authority.

#### Scenario: Port 9000 unavailable
- **WHEN** local S3 starts on port 9001
- **THEN** share, overlay URLs target port 9001, not 9000

### Requirement: Remote S3: no implicit tunneling
`hub-s3` MUST preserve public provider endpoints (AWS, Wasabi) unless user explicitly configures local-published or gateway-backed endpoint.

#### Scenario: AWS public endpoint configured
- **WHEN** `hub-s3` uses normal AWS endpoint
- **THEN** generated URLs use that endpoint, no Hub Network required

### Requirement: Launcher integration optional
Hub Launcher SHALL install, configure, start, stop, update `hub-net`. Hub Network registration, authorization MUST work for manually installed agents, services.

#### Scenario: Agent installed manually
- **WHEN** `hub-net` installed, started without Launcher
- **THEN** can join Hub, same protocol behavior

### Requirement: Store exposes agent
Hub Store SHALL contain one-click install entry for `hub-net` using Launcher setup model. SHALL identify as server/network component.

#### Scenario: User installs from Store
- **WHEN** Launcher user selects Hub Network entry
- **THEN** Launcher receives valid `hub-net` install config

### Requirement: Hub App manages network resources
Hub App SHALL display live shares, owners, availability, access policies, agents, direct-connect diagnostics to users with Hub permissions.

#### Scenario: Non-owner opens network management
- **WHEN** user lacks network management permission
- **THEN** app hides mutation controls, Hub rejects mutations

### Requirement: Apple VPN code isolated
On Apple platforms supporting Hub Network profiles, packet-tunnel, WireGuard dependencies SHALL reside in dedicated extension or platform networking target, not each embedded Hub service.

#### Scenario: Built-in encoder uses overlay URL
- **WHEN** Hub Network profile active, encoder receives authorized S3 URL
- **THEN** existing URL loading APIs transfer object, no encoder-specific WireGuard code

### Requirement: Future gateway: opt-in, separate
Initial integration MUST NOT create default route through `hub-net-node`. Future gateway profile SHALL require separate capability, explicit user consent, node advertising `gateway` role.

#### Scenario: Rendezvous-only node selected
- **WHEN** user connects to node advertising only `rendezvous`
- **THEN** app offers no full-tunnel routing through that node

### Requirement: Go agent, node share protocol contracts
`hub-net`, `hub-net-node` SHALL be Go implementations. SHALL use shared versioned package for Hub Network grants, tickets, candidates, node capabilities, errors.

#### Scenario: Node protocol model changes
- **WHEN** rendezvous wire model changes compatibly
- **THEN** agent, node builds consume same model version, pass shared fixtures

### Requirement: Apple packet tunnel native
Apple app-scoped packet tunnel SHALL remain Swift/WireGuardKit. SHALL conform to same Hub Network wire contracts as Go agent.

#### Scenario: Apple profile requests connection
- **WHEN** Apple packet-tunnel profile requests authorized peer
- **THEN** validates, uses same versioned grant semantics as `hub-net`
