## ADDED Requirements

### Requirement: Gateway serving is explicit per Hub
Every hub-net and Hub App profile MAY provide internet egress but SHALL default
disabled. Serving SHALL require explicit per-Hub enablement and publish
`internet-gateway-v1` capability only while available.

#### Scenario: Agent joins Hub
- **WHEN** membership first starts
- **THEN** gateway capability is absent

#### Scenario: User allows gateway
- **WHEN** `hub-net vpn allow <hubname>` succeeds
- **THEN** agent enables contained forwarding/NAT and advertises capability

### Requirement: Gateway access uses signed revocable grant
hub-pro SHALL issue short-lived grant binding Hub, client, gateway, WireGuard
keys, default-route and DNS capabilities, expiry, and revocation generation.
Both peers MUST validate all bindings.

#### Scenario: Client from other Hub presents grant
- **WHEN** Hub or profile binding differs
- **THEN** gateway rejects forwarding

### Requirement: Gateway is network-contained
Gateway SHALL forward IPv4/IPv6 internet traffic with stateful NAT while blocking
gateway loopback, LAN, management services, and other Hub sessions unless
separately authorized.

#### Scenario: Client probes gateway LAN
- **WHEN** destination is protected local/LAN prefix
- **THEN** gateway firewall drops traffic

### Requirement: Disabling gateway revokes active use
`hub-net vpn remove <hubname>` and Hub App equivalent SHALL remove advertisement,
reject renewals, revoke grants, remove forwarding/NAT state, and terminate tracked
flows.

#### Scenario: Active gateway disabled
- **WHEN** provider user disables serving
- **THEN** clients lose route immediately and Hub App kill switch blocks fallback

### Requirement: Hub App selects full tunnel explicitly
Only Hub App SHALL consume gateway in this change. It SHALL require explicit
reachable peer selection and install IPv4, IPv6, and DNS default routing only
after grant and peer verification.

#### Scenario: No gateway selected
- **WHEN** Hub App network profile activates normally
- **THEN** only Hub overlay routes install

### Requirement: Full tunnel uses kill switch
Hub App SHALL enable kill switch before default routes. Gateway handshake,
renewal, DNS, or reachability failure SHALL block IPv4, IPv6, and DNS until user
disables full tunnel; normal-network fallback is forbidden.

#### Scenario: Gateway disconnects
- **WHEN** selected peer becomes unreachable
- **THEN** device traffic remains blocked and UI reports gateway failure

#### Scenario: User disables full tunnel
- **WHEN** user turns exit routing off
- **THEN** App atomically removes defaults and kill switch, restoring normal network
