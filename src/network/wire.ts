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
  profileKey: string
  agentKey: string
  wireGuardKey: string
  name?: string
  platform?: string
  overlayAddresses: string[]
  connectedAt: Timestamp
}

export interface AgentAttestation extends Versioned {
  attestationId: string
  serviceKey: string
  agentKey: string
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
  profileKey: string
  agentKey: string
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
  callerProfileKey: string
  callerWireGuardKey: string
  targetAgentKey: string
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
  profileKey: string
  agentKey: string
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
  agentKey: string
  kind: CandidateKind
  transport: CandidateTransport
  address: string
  port: number
  priority: number
  foundation?: string
  expiresAt: Timestamp
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
  agentKey: string
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
  agentKey: string
  profileKey: string
  available: boolean
  addresses: string[]
  peers: number
  shares: number
  updatedAt: Timestamp
  error?: NetworkError
}

export type NetworkErrorCode =
  | 'unsupported_version'
  | 'invalid_request'
  | 'unauthorized'
  | 'forbidden'
  | 'agent_unavailable'
  | 'invalid_attestation'
  | 'resource_id_collision'
  | 'resource_unavailable'
  | 'provider_unavailable'
  | 'grant_expired'
  | 'grant_revoked'
  | 'ticket_expired'
  | 'replay_detected'
  | 'direct_connect_failed'
  | 'rate_limited'
  | 'internal'

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
  | WireEnvelope<'connection.grant', ConnectionGrant>
  | WireEnvelope<'rendezvous.ticket', RendezvousTicket>
  | WireEnvelope<'candidate.offer', Candidate>
  | WireEnvelope<'status.agent', AgentStatus>
  | WireEnvelope<'status.connection', ConnectionStatus>
  | WireEnvelope<'error', NetworkError>

export function networkError(
  code: NetworkErrorCode,
  message: string,
  retryable = false,
  details?: NetworkError['details'],
): NetworkError {
  return { version: HUB_NETWORK_WIRE_VERSION, code, message, retryable, ...(details ? { details } : {}) }
}

