export const HUB_NETWORK_WIRE_VERSION = 1 as const

export type WireVersion = typeof HUB_NETWORK_WIRE_VERSION
export type Timestamp = string
export type Base64 = string
export type ResourceId = `hnr1_${string}`
export type Protocol = 'tcp' | 'udp'

export interface Versioned {
  version: WireVersion
}

export type NetworkPolicy =
  | { mode: 'hub' }
  | { mode: 'group'; group: string }
  | { mode: 'keys'; keys: string[] }
  | { mode: 'private' }
  | { mode: 'disabled' }

export interface LocalTarget {
  host: string
  port: number
}

export interface NetworkShare extends Versioned {
  name: string
  protocol: Protocol
  target: LocalTarget
  policy?: NetworkPolicy
  attestation: AgentAttestation
}

export interface NetworkSharePublication extends Versioned {
  resourceId: ResourceId
  authority: string
  providerId: string
  protocol: Protocol
  overlayAddress: string
  port: number
}

export interface AgentProfile extends Versioned {
  key: string
  wireGuardKey: string
  name?: string
  platform?: string
  overlayAddresses: string[]
  connectedAt: Timestamp
  /** Set in member lists: false for a known member that is not connected. */
  online?: boolean
  /** Member key: `device:<id>` for device-attached agents, else the service key */
  member?: string
  /** Device id when device-attached */
  device?: string
  /** `<label>-<16>.v1-<hub>.hub.invalid`, resolving to the device's overlay address */
  deviceAuthority?: string
}

/** `network/devices/revoked`: peers agents must drop and refuse */
export interface RevokedDevice {
  device: string
  wireGuardKeys: string[]
  at: Timestamp
}

export interface AgentBindRequest extends Omit<AgentProfile, 'key'> {
  bindingKind: LocalAgentBindingKind
  /** Required for a first `join` bind: the inviter-signed bootstrap response. */
  admission?: DirectBootstrapResponse
}

/**
 * Inviter-signed answer to a joiner's direct bootstrap request
 * (`hub-network/direct-bootstrap-response/v1`). A joiner presents it with its
 * first `join` bind as proof that a current agent of this network invited it.
 */
export interface DirectBootstrapResponse extends Versioned {
  signatureDomain: 'hub-network/direct-bootstrap-response/v1'
  replayId: string
  inviterServiceKey: string
  joinerServiceKey: string
  joinerWireGuardKey: string
  inviterWireGuardKey: string
  endpoints: { address: string; port: number; transport: 'udp' }[]
  joinerAddress: { ipv4: string; ipv6: string }
  inviterAddress: { ipv4: string; ipv6: string }
  hubProHost: string
  issuedAt: Timestamp
  expiresAt: Timestamp
  signature: string
}

export type LocalAgentBindingKind = 'machine' | 'apple-app' | 'join'

export type AppleAppAgentCapability = 'invitation-bootstrap-v1'

/** Extension-signed, short-lived proof that one Apple packet tunnel is ready. */
export interface AppleAppAgentReadinessAssertion extends Versioned {
  signatureDomain: 'hub-network/apple-app-agent-readiness/v1'
  hubNetworkId: string
  wireGuardKey: Base64
  tunnelInstanceId: string
  capabilities: AppleAppAgentCapability[]
  generation: number
  issuedAt: Timestamp
  expiresAt: Timestamp
  signature: Base64
}

export interface AppleAppAgentBindRequest extends Versioned {
  assertion: AppleAppAgentReadinessAssertion
}

export interface AppleAppAgentRenewRequest extends Versioned {
  assertion: AppleAppAgentReadinessAssertion
}

export interface AppleAppAgentUnbindRequest extends Versioned {
  hubNetworkId: string
  tunnelInstanceId: string
  generation: number
}

export interface LocalAgentBindingStatus extends Versioned {
  state: 'unbound' | 'available' | 'unavailable'
  bindingKind?: LocalAgentBindingKind
  key?: string
  tunnelInstanceId?: string
  generation?: number
  expiresAt?: Timestamp
  capabilities: string[]
  connected: boolean
  bootstrapCapable: boolean
  updatedAt: Timestamp
  error?: NetworkError
}

export interface AgentAttestation extends Versioned {
  attestationId: string
  serviceKey: string
  key: string
  shareName: string
  protocol: Protocol
  target: LocalTarget
  issuedAt: Timestamp
  expiresAt: Timestamp
  signature: Base64
}

export interface ProfileBinding extends Versioned {
  bindingId: string
  hubNetworkId: string
  key: string
  wireGuardKey: string
  overlayAddresses: string[]
  issuedAt: Timestamp
  expiresAt: Timestamp
  signature: Base64
}

export interface ConnectionGrant extends Versioned {
  grantId: string
  hubKey: string
  hubNetworkId: string
  callerKey: string
  callerWireGuardKey: string
  callerAddress: string
  targetKey: string
  targetWireGuardKey: string
  resourceId: ResourceId
  providerId: string
  protocol: Protocol
  destinationAddress: string
  destinationPort: number
  generation: number
  issuedAt: Timestamp
  expiresAt: Timestamp
  signature: Base64
}

export type NodeRole = 'rendezvous'

export interface RendezvousTicket extends Versioned {
  ticketId: string
  hubKey: string
  hubNetworkId: string
  key: string
  nodeId: string
  roles: NodeRole[]
  sessionPurpose: 'peer-connect'
  issuedAt: Timestamp
  expiresAt: Timestamp
  signature: Base64
}

export type CandidateKind = 'host' | 'server-reflexive'
export type CandidateTransport = 'udp'

export interface Candidate extends Versioned {
  candidateId: string
  sessionId: string
  key: string
  kind: CandidateKind
  transport: CandidateTransport
  address: string
  port: number
  priority: number
  foundation?: string
  expiresAt: Timestamp
}

/** Transport source measured by rendezvous node, never client-declared. */
export interface ObservedEndpoint extends Versioned {
  key: string
  transport: 'tcp' | CandidateTransport
  address: string
  port: number
}

export interface NetworkResource extends Versioned {
  resourceId: ResourceId
  ownerKey: string
  shareName: string
  authority: string
  policy: NetworkPolicy
  generation: number
}

export interface LiveProvider extends Versioned {
  providerId: string
  resourceId: ResourceId
  serviceKey: string
  key: string
  protocol: Protocol
  overlayAddress: string
  port: number
  connectedAt: Timestamp
}

export type ConnectionPhase = 'idle' | 'discovering' | 'connecting' | 'connected' | 'failed'

export interface ConnectionStatus extends Versioned {
  resourceId: ResourceId
  providerId?: string
  phase: ConnectionPhase
  direct: boolean
  updatedAt: Timestamp
  error?: NetworkError
}

export interface AgentStatus extends Versioned {
  key: string
  available: boolean
  addresses: string[]
  peers: number
  shares: number
  updatedAt: Timestamp
  error?: NetworkError
}

/**
 * Snapshot of a stable resource's revocation generation and current policy.
 *
 * Hub pushes these through the `network/resource/generations` stream whenever a
 * resource is revoked or its policy changes. Connected agents compare the
 * generation against any held connection grants and drop flows whose grant
 * generation is older than the current value.
 */
export interface ResourceGenerationSnapshot extends Versioned {
  resourceId: ResourceId
  generation: number
  policy: NetworkPolicy
  updatedAt: Timestamp
}

/** Explicit, disabled-by-default capability advertised by an exit provider. */
export interface GatewayCapability extends Versioned {
  capability: 'internet-gateway-v1'
  ipv4: boolean
  ipv6: boolean
  dns: boolean
  metered: boolean
  updatedAt: Timestamp
}

export type GatewayState = 'disabled' | 'available' | 'unavailable'

/** Permission-filtered reachability and capability view for one gateway peer. */
export interface GatewayStatus extends Versioned {
  hubNetworkId: string
  key: string
  wireGuardKey: string
  endpoint: string
  capability: GatewayCapability
  state: GatewayState
  updatedAt: Timestamp
  error?: NetworkError
}

/** Hub-signed, purpose-separated authorization for one full-tunnel client. */
export interface GatewayGrant extends Versioned {
  grantId: string
  hubKey: string
  hubNetworkId: string
  clientKey: string
  clientWireGuardKey: string
  gatewayKey: string
  gatewayWireGuardKey: string
  ipv4: boolean
  ipv6: boolean
  dns: boolean
  generation: number
  issuedAt: Timestamp
  expiresAt: Timestamp
  signature: Base64
}

/** Current gateway generation; peers drop grants from older generations. */
export interface GatewayRevocation extends Versioned {
  hubNetworkId: string
  gatewayKey: string
  generation: number
  revokedAt: Timestamp
  reason: string
}

/** Bounded, permission-filtered diagnostic for gateway setup or forwarding. */
export interface GatewayDiagnostic extends Versioned {
  hubNetworkId: string
  gatewayKey: string
  code: NetworkErrorCode
  message: string
  retryable: boolean
  updatedAt: Timestamp
  details?: Record<string, string | number | boolean>
}

export type NetworkErrorCode =
  | 'unsupported_version'
  | 'invalid_request'
  | 'unauthorized'
  | 'forbidden'
  | 'agent_unavailable'
  | 'local_agent_unavailable'
  | 'local_agent_rebind_required'
  | 'local_agent_proof_mismatch'
  | 'invalid_attestation'
  | 'resource_id_collision'
  | 'resource_unavailable'
  | 'provider_unavailable'
  | 'grant_expired'
  | 'grant_revoked'
  | 'ticket_expired'
  | 'replay_detected'
  | 'invite_malformed'
  | 'invite_non_canonical'
  | 'invite_unsupported_version'
  | 'invite_invalid_signature'
  | 'invite_invalid_time'
  | 'invite_expired'
  | 'invite_wrong_audience'
  | 'invite_already_claimed'
  | 'invite_consumed'
  | 'direct_connect_failed'
  | 'gateway_unavailable'
  | 'gateway_grant_expired'
  | 'gateway_grant_revoked'
  | 'gateway_not_authorized'
  | 'rate_limited'
  | 'internal'
  | 'device_endpoint_exists'
  | 'share_device_mismatch'

export interface NetworkError extends Versioned {
  code: NetworkErrorCode
  message: string
  retryable: boolean
  details?: Record<string, string | number | boolean>
}

export interface WireEnvelope<TType extends string, TPayload> extends Versioned {
  type: TType
  requestId?: string
  payload: TPayload
}

export type HubNetworkMessage =
  | WireEnvelope<'shares.replace', { shares: NetworkShare[] }>
  | WireEnvelope<'shares.published', { shares: NetworkSharePublication[] }>
  | WireEnvelope<'agent.register', AgentProfile>
  | WireEnvelope<'apple-agent.bind', AppleAppAgentBindRequest>
  | WireEnvelope<'apple-agent.renew', AppleAppAgentRenewRequest>
  | WireEnvelope<'apple-agent.unbind', AppleAppAgentUnbindRequest>
  | WireEnvelope<'connection.grant', ConnectionGrant>
  | WireEnvelope<'rendezvous.ticket', RendezvousTicket>
  | WireEnvelope<'candidate.offer', Candidate>
  | WireEnvelope<'status.agent', AgentStatus>
  | WireEnvelope<'status.connection', ConnectionStatus>
  | WireEnvelope<'resource.generation', ResourceGenerationSnapshot>
  | WireEnvelope<'gateway.status', GatewayStatus>
  | WireEnvelope<'gateway.grant', GatewayGrant>
  | WireEnvelope<'gateway.revocation', GatewayRevocation>
  | WireEnvelope<'gateway.diagnostic', GatewayDiagnostic>
  | WireEnvelope<'error', NetworkError>

export function networkError(
  code: NetworkErrorCode,
  message: string,
  retryable = false,
  details?: NetworkError['details'],
): NetworkError {
  return { version: HUB_NETWORK_WIRE_VERSION, code, message, retryable, ...(details ? { details } : {}) }
}

export interface HubHeader {
  name: string
}
