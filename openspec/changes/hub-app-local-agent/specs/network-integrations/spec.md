## MODIFIED Requirements

### Requirement: Hub App can join current local Hub network
`HubNetworkView` SHALL expose `Share Network` toggle that installs VPN profile
when absent, activates it, joins current local Hub, and establishes Apple
app-agent readiness. Turning it off SHALL deactivate App membership and
app-agent availability without deleting Hub or persistent profile state.

#### Scenario: Profile missing
- **WHEN** user enables Share Network
- **THEN** App requests required consent, installs profile, activates membership, and reports app-agent readiness

#### Scenario: Bootstrap readiness fails
- **WHEN** VPN membership activates but extension cannot provide compatible bootstrap readiness
- **THEN** Share Network reports active membership with bootstrap unavailable and Invite Code remains disabled

### Requirement: Hub App creates and copies invitation
Authorized `HubNetworkView` SHALL expose `Invite Code`, call `hub/net/share`,
and copy canonical `hub://net/join/<code>` when either machine-local `hub-net`
or this App's active tunnel is reported bootstrap-ready.

#### Scenario: App tunnel supplies local agent
- **WHEN** owner taps Invite Code while Share Network app-agent is available
- **THEN** one fresh ten-minute link bound to that App tunnel is copied

#### Scenario: No implementation is ready
- **WHEN** neither machine nor Apple local agent is bootstrap-ready
- **THEN** Invite Code is disabled and UI reports specific unavailable state

