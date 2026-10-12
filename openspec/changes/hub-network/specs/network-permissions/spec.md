## ADDED Requirements

### Requirement: Network permissions are independent
Hub MUST evaluate network-resource permissions independently from RPC hosting and calling permissions.

#### Scenario: Encoder uses a presigned URL without S3 RPC permission
- **WHEN** an encoder profile can access the S3 network share but cannot call `s3/read` or `s3/write`
- **THEN** it can use a valid presigned URL while Hub continues to reject those RPC calls

#### Scenario: RPC permission exists without network permission
- **WHEN** a profile can call an RPC API but lacks access to its related network share
- **THEN** Hub does not issue a network connection grant

### Requirement: Supported access policies
Hub SHALL support `hub`, `group`, `keys`, `private`, and `disabled` network policies for each stable resource.

#### Scenario: Hub-wide share
- **WHEN** an authenticated network profile requests access to a resource with `hub` policy
- **THEN** Hub authorizes it unless a stronger Hub-wide restriction blocks that profile

#### Scenario: Group-restricted share
- **WHEN** a profile outside the configured group requests access
- **THEN** Hub rejects the request

#### Scenario: Disabled share
- **WHEN** any non-owner profile requests access to a disabled resource
- **THEN** Hub rejects the request and does not disclose a usable endpoint

### Requirement: Network profile is the calling principal
Connection authorization SHALL use the authenticated network profile identity associated with the requesting `hub-net` instance or app-scoped profile.

#### Scenario: Multiple processes use one device-wide profile
- **WHEN** multiple local processes route through the same device-wide Hub Network profile
- **THEN** remote authorization treats their connections as the same network principal

### Requirement: Owners manage network policy
Hub owners SHALL be able to view and change every network resource policy, while a share owner MAY change its own policy only when allowed by Hub configuration.

#### Scenario: Unauthorized service changes another share
- **WHEN** a non-owner service attempts to change a resource owned by another identity
- **THEN** Hub rejects the update

### Requirement: Revocation stops future authorization
After a policy or group membership is revoked, Hub MUST immediately stop issuing or renewing grants that depended on the revoked permission.

#### Scenario: Group member is removed
- **WHEN** a network profile is removed from a resource's required group
- **THEN** subsequent connection and renewal requests are rejected

### Requirement: Active-flow revocation is defined
Hub and connected agents SHALL support a resource generation update that invalidates active authorization, and the selected policy SHALL define whether agents terminate existing flows immediately.

#### Scenario: Immediate revocation enabled
- **WHEN** an owner revokes access with immediate termination
- **THEN** target and caller agents remove the affected authorization and terminate matching active flows
