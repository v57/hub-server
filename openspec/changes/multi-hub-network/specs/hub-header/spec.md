## ADDED Requirements

### Requirement: Hub exposes persistent header
hub-pro SHALL persist `HubHeader` with `name`, initialize it from system hostname
on first start, and preserve it across restart.

#### Scenario: Hub starts without header
- **WHEN** hub-pro initializes new storage
- **THEN** it persists `{ name: <hostname> }` before serving header API

#### Scenario: Hub restarts
- **WHEN** persisted header exists
- **THEN** hub-pro uses it instead of rereading hostname

### Requirement: Header is publicly readable
`hub/header` SHALL stream current `HubHeader` to unauthenticated callers and
publish later committed changes.

#### Scenario: Joiner reads one value
- **WHEN** bootstrap client opens `hub/header`
- **THEN** it receives current header without membership and may cancel stream

### Requirement: Header update is owner-only
`hub/header/set` SHALL require Hub owner, validate bounded non-empty name, commit
atomically, then notify stream subscribers.

#### Scenario: Non-owner sets header
- **WHEN** non-owner calls `hub/header/set`
- **THEN** Hub rejects and persisted header stays unchanged

#### Scenario: Owner sets invalid name
- **WHEN** owner sends empty, whitespace-only, or over-limit name
- **THEN** Hub rejects without stream update
