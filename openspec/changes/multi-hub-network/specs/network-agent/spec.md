## MODIFIED Requirements

### Requirement: Agent manages multiple isolated Hubs
`hub-net` SHALL start with no Hub connection and dynamically supervise zero or
more persistent Hub sessions. Each session SHALL own separate service/profile
identity, WireGuard key, interface, node state, DNS, routing, enforcement, and
publications.

#### Scenario: Fresh daemon starts
- **WHEN** hub-net has no joined-Hub records
- **THEN** local command IPC starts and no Hub, node, or WireGuard connection opens

#### Scenario: One Hub fails
- **WHEN** one of several sessions cannot reconnect
- **THEN** it reports error while other sessions remain operational

#### Scenario: Hub sessions compared
- **WHEN** two Hubs use same node and canonical overlay addresses
- **THEN** no keys, tickets, peers, grants, routes, or DNS state are shared

### Requirement: Agent exposes local management commands
Daemon SHALL provide secured local IPC implementing `join`, `leave`, `list`,
`open`, `close`, `vpn allow`, `vpn remove`, and `removeAll`. CLI subcommands
SHALL use daemon IPC rather than create competing networking state.

#### Scenario: Join succeeds
- **WHEN** `hub-net join <code>` commits membership
- **THEN** output is exactly `Joined <hubname>`, `Host: <virtual-host>`,
  `IP: <virtual-ip>` on three lines

#### Scenario: Mutation repeated
- **WHEN** desired open/close or VPN allow/remove state already exists
- **THEN** command succeeds idempotently

### Requirement: Open publishes TCP and UDP persistently
`hub-net open <port> <hubname>` SHALL validate 1...65535, atomically persist and
publish TCP and UDP loopback resources. `close` SHALL remove both and revoke
active grants. Publications SHALL return after daemon or Hub restart.

#### Scenario: UDP publication fails
- **WHEN** TCP succeeds but UDP publication fails
- **THEN** agent rolls back both and reports command failure

### Requirement: Leave and reset remove scoped data
`leave` SHALL remove one Hub session. `removeAll` SHALL remove every joined-Hub
session, identity, key, alias, node state, and publication while preserving
installation, global settings, and ordinary logs.

#### Scenario: One Hub left
- **WHEN** user leaves one of two Hubs
- **THEN** selected networking/state is removed and other Hub remains connected

#### Scenario: Cleanup interrupted
- **WHEN** daemon stops during removal
- **THEN** record remains unusable in `removing` state and cleanup resumes next start

### Requirement: Singleton state migrates without rotation
Agent SHALL migrate legacy singleton Hub state into one per-Hub session while
preserving identity, WireGuard key, Hub binding, and publications. Migration
SHALL NOT enable gateway serving.

#### Scenario: Legacy agent upgrades
- **WHEN** new daemon sees valid singleton state
- **THEN** one equivalent Hub session starts with byte-identical private keys
