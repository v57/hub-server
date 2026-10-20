## MODIFIED Requirements

### Requirement: Invitation bootstrap coordinates direct peers only
hub-net-node SHALL coordinate direct candidate exchange between joiner and
invitation-selected machine or Apple inviting agent. PacketTunnelExtension MAY
act as native Apple joiner and SHALL present exact signed token, transaction,
joiner key, selected agent, tunnel/generation pins, and expiry. Node SHALL never
relay enrollment or application payload.

#### Scenario: Native Apple joiner connects to Apple inviting agent
- **WHEN** both present matching unexpired authorization and direct candidates
- **THEN** node pairs exactly those peers and exposes no payload-forwarding path

#### Scenario: Joiner identity changes during retry
- **WHEN** retry presents different profile or WireGuard key for staged transaction
- **THEN** node and inviting agent reject before installing peer state

#### Scenario: Inviting Apple peer waits before claim
- **WHEN** an Apple-bound invitation is issued and remains unexpired
- **THEN** its exact selected PacketTunnelExtension may wait for the matching joiner at the rendezvous node without first receiving traffic over the unavailable bootstrap overlay

#### Scenario: Unclaimed rendezvous preparation expires
- **WHEN** no matching joiner completes the invitation transaction before expiry
- **THEN** hub-pro, PacketTunnelExtension, and hub-net-node remove all prepared assignment, peer, candidate, and session state
