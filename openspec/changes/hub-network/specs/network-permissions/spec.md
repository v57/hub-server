## ADDED Requirements

### Requirement: Network permissions are independent
Hub MUST evaluate network-resource permissions independent from RPC hosting/calling permissions.

#### Scenario: Encoder uses presigned URL without S3 RPC permission
- **WHEN** encoder profile can access S3 network share but cannot call `s3/read` or `s3/write`
- **THEN** it can use valid presigned URL while Hub rejects those RPC calls

#### Scenario: RPC permission exists without network permission
- **WHEN** profile can call RPC API but lacks access to related network share
- **THEN** Hub issues no network connection grant

### Requirement: Supported access policies
Hub SHALL support `hub`, `group`, `keys`, `private`, `disabled` network policies per stable resource.

#### Scenario: Hub-wide share
- **WHEN** authenticated network profile requests access to resource with `hub` policy
- **THEN** Hub authorizes unless stronger Hub-wide restriction blocks that profile

#### Scenario: Group-restricted share
- **WHEN** profile outside configured group requests access
- **THEN** Hub rejects request

#### Scenario: Disabled share
- **WHEN** non-owner profile requests access to disabled resource
- **THEN** Hub rejects request, discloses no usable endpoint

### Requirement: Network profile is calling principal
Connection authorization SHALL use authenticated network profile identity from requesting `hub-net` instance or app-scoped profile.

#### Scenario: Multiple processes use one device-wide profile
- **WHEN** multiple local processes route through same device-wide Hub Network profile
- **THEN** remote authorization treats their connections as same network principal

### Requirement: Owners manage network policy
Hub owners SHALL view/change every network resource policy. Share owner MAY change own policy only when allowed by Hub configuration.

#### Scenario: Unauthorized service changes another share
- **WHEN** non-owner service attempts to change resource owned by another identity
- **THEN** Hub rejects update

### Requirement: Revocation stops future authorization
After policy or group membership revoked, Hub MUST immediately stop issuing/renewing grants that depended on revoked permission.

#### Scenario: Group member removed
- **WHEN** network profile removed from resource's required group
- **THEN** subsequent connection/renewal requests rejected

### Requirement: Active-flow revocation defined
Hub and connected agents SHALL support resource generation update that invalidates active authorization. Selected policy SHALL define whether agents terminate existing flows immediately.

#### Scenario: Immediate revocation enabled
- **WHEN** owner revokes access with immediate termination
- **THEN** target and caller agents remove affected authorization, terminate matching active flows