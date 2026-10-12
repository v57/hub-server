## ADDED Requirements

### Requirement: Go, Bun, and Swift publication APIs are equivalent
`hub-service-go`, `hub-service`, and `HubService` SHALL expose equivalent models and behavior for declaring share name, protocol, local port, access policy, and stable identity.

#### Scenario: Equivalent cross-language publication
- **WHEN** equivalent Go, Bun, and Swift services publish the same logical share configuration
- **THEN** Hub receives protocol-compatible registration fields with the same semantics

### Requirement: Go Hub service SDK is implemented first
`hub-service-go` MUST provide reusable Hub identity, authentication, registration, request, streaming, reconnect, profile, API-setting, and network-publication behavior before `hub-net` begins implementation.

#### Scenario: Go agent registers with Hub
- **WHEN** `hub-net` needs to connect, advertise control APIs, or consume Hub APIs
- **THEN** it uses the released `hub-service-go` SDK rather than a private agent-specific Hub client

### Requirement: Go SDK builds on a conformant Channel library
`hub-service-go` MUST depend on a stabilized `channel-go` module that passes supported-platform tests, race detection, and current TypeScript Channel interoperability tests.

#### Scenario: Channel wire behavior changes
- **WHEN** a TypeScript interoperability fixture reveals incompatible Go behavior
- **THEN** the incompatibility is resolved or explicitly versioned before `hub-service-go` is released

### Requirement: Service libraries do not embed WireGuard
The Go, Bun, and Swift service libraries MUST use Hub registration and local-agent IPC for network publication and MUST NOT include a WireGuard implementation.

#### Scenario: Service adds a share
- **WHEN** an application adopts the network-share API
- **THEN** only the separately installed agent or platform network extension provides WireGuard packet processing

### Requirement: Local S3 uses its actual selected port
`hub-s3-local` SHALL publish the port successfully selected at runtime and SHALL construct overlay-compatible S3 endpoints and presigned URLs using the canonical share authority.

#### Scenario: Port 9000 is unavailable
- **WHEN** local S3 starts on port 9001
- **THEN** its share and generated overlay URLs target port 9001 rather than assuming port 9000

### Requirement: Remote S3 is not tunneled implicitly
`hub-s3` MUST preserve ordinary public provider endpoints such as AWS or Wasabi unless the user explicitly configures a locally published or gateway-backed endpoint.

#### Scenario: AWS public endpoint configured
- **WHEN** `hub-s3` uses a normal AWS endpoint
- **THEN** generated URLs continue to use that provider endpoint and do not require Hub Network

### Requirement: Launcher integration is optional
Hub Launcher SHALL be able to install, configure, start, stop, and update `hub-net`, but Hub Network registration and authorization MUST continue to work for manually installed agents and services.

#### Scenario: Agent installed manually
- **WHEN** `hub-net` is installed and started without Launcher
- **THEN** it can join a Hub and provide the same protocol behavior

### Requirement: Store exposes the agent
Hub Store SHALL contain a one-click installation entry for `hub-net` using the Launcher setup model and SHALL identify it as a server/network component.

#### Scenario: User installs from Store
- **WHEN** a compatible Launcher user selects the Hub Network entry
- **THEN** Launcher receives a valid installation configuration for `hub-net`

### Requirement: Hub App manages network resources
Hub App SHALL display live shares, their owners, availability, access policies, agents, and direct-connect diagnostics to users with corresponding Hub permissions.

#### Scenario: Non-owner opens network management
- **WHEN** a user lacks network management permission
- **THEN** the app does not expose mutation controls and Hub independently rejects mutation attempts

### Requirement: Apple VPN code is isolated
On Apple platforms that support Hub Network profiles, packet-tunnel and WireGuard dependencies SHALL reside in a dedicated extension or platform networking target rather than each embedded Hub service.

#### Scenario: Built-in encoder uses overlay URL
- **WHEN** the app-scoped Hub Network profile is active and an encoder receives an authorized S3 URL
- **THEN** its existing URL loading APIs can transfer the object without encoder-specific WireGuard code

### Requirement: Future gateway behavior remains opt-in and separate
The initial integration MUST NOT create a default route through `hub-net-node`; a future gateway profile SHALL require a separately specified capability, explicit user consent, and a node advertising the `gateway` role.

#### Scenario: Rendezvous-only node selected
- **WHEN** a user connects to a node that advertises only `rendezvous`
- **THEN** the app offers no full-tunnel routing through that node

### Requirement: Go agent and node share protocol contracts
`hub-net` and `hub-net-node` SHALL be implemented in Go and SHALL use a shared versioned package for Hub Network grants, tickets, candidates, node capabilities, and errors.

#### Scenario: Node protocol model changes
- **WHEN** a rendezvous wire model changes compatibly
- **THEN** agent and node builds consume the same model version and pass shared fixtures

### Requirement: Apple packet tunnel remains native
The Apple app-scoped packet tunnel SHALL remain Swift/WireGuardKit and SHALL conform to the same Hub Network wire contracts as the Go agent.

#### Scenario: Apple profile requests a connection
- **WHEN** an Apple packet-tunnel profile requests an authorized peer
- **THEN** it validates and uses the same versioned grant semantics as `hub-net`
