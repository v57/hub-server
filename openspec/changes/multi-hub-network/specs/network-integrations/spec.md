## MODIFIED Requirements

### Requirement: Hub App can join current local Hub network
`HubNetworkView` SHALL expose `Share Network` toggle that installs VPN profile
when absent, activates it, and joins current local Hub. Turning it off SHALL
deactivate App membership without deleting Hub or agent state.

#### Scenario: Profile missing
- **WHEN** user enables Share Network
- **THEN** App requests required consent, installs profile, and activates membership

### Requirement: Hub App creates and copies invitation
Authorized HubNetworkView SHALL expose `Invite Code`, call `hub/net/share`, and
copy canonical `hub://net/join/<code>` to clipboard. Control SHALL be hidden or
disabled without owner permission or local agent.

#### Scenario: Invitation succeeds
- **WHEN** owner taps Invite Code
- **THEN** one fresh ten-minute link is copied and confirmation shown

### Requirement: Hub App joins from code
Home SHALL offer one text field and Join button accepting canonical deep link or
bare base64url and SHALL use same invitation validation/join transaction as
hub-net CLI.

#### Scenario: Invalid code submitted
- **WHEN** parser rejects input
- **THEN** App displays bounded error and creates no VPN/session state

### Requirement: Hub App controls gateway serving and use
HubNetworkView SHALL separately expose disabled-by-default gateway-serving toggle
and explicit reachable gateway selection. Serving choice and exit selection MUST
not be conflated with Share Network membership.

#### Scenario: Share Network enabled
- **WHEN** user does not enable gateway serving or select exit
- **THEN** no forwarding/NAT/default route is enabled

### Requirement: Apple VPN implementation keeps extension boundary
Per-Hub overlay translation, gateway serving, full-tunnel routes, DNS, and kill
switch SHALL remain in packet-tunnel/platform networking target, not ordinary
embedded Hub services.

#### Scenario: App consumes gateway
- **WHEN** full tunnel activates
- **THEN** existing application networking uses OS tunnel without app-specific changes
