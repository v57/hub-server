import { sign, verify, type KeyLike } from 'node:crypto'
import { createPublicKey } from 'node:crypto'
import type { ConnectionGrant, GatewayGrant, RendezvousTicket } from './wire'
import { HUB_NETWORK_WIRE_VERSION } from './wire'

export type SignaturePurpose =
  | 'agent-attestation'
  | 'profile-binding'
  | 'connection-grant'
  | 'rendezvous-ticket'
  | 'network-invitation'
  | 'gateway-grant'
  | 'apple-app-agent-readiness'

export const SIGNATURE_DOMAINS: Record<SignaturePurpose, string> = {
  'agent-attestation': 'hub-network/agent-attestation/v1',
  'profile-binding': 'hub-network/profile-binding/v1',
  'connection-grant': 'hub-network/connection-grant/v1',
  'rendezvous-ticket': 'hub-network/rendezvous-ticket/v1',
  'network-invitation': 'hub-network/invitation/v1',
  'gateway-grant': 'hub-network/gateway-grant/v1',
  'apple-app-agent-readiness': 'hub-network/apple-app-agent-readiness/v1',
}

function canonicalJSON(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite numbers cannot be signed')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`
  if (typeof value === 'object') {
    const object = value as Record<string, unknown>
    return `{${Object.keys(object)
      .filter(key => object[key] !== undefined)
      .sort()
      .map(key => `${JSON.stringify(key)}:${canonicalJSON(object[key])}`)
      .join(',')}}`
  }
  throw new Error(`unsupported signed value: ${typeof value}`)
}

export function signatureInput(purpose: SignaturePurpose, envelope: object): Uint8Array {
  const unsigned = { ...(envelope as Record<string, unknown>) }
  delete unsigned.signature
  const payload = Buffer.from(canonicalJSON(unsigned), 'utf8')
  const domain = Buffer.from(SIGNATURE_DOMAINS[purpose], 'ascii')
  const length = Buffer.allocUnsafe(4)
  length.writeUInt32BE(payload.length)
  return Buffer.concat([domain, Buffer.of(0), length, payload])
}

export function signEnvelope(
  purpose: SignaturePurpose,
  envelope: object,
  privateKey: KeyLike,
): string {
  return sign(null, signatureInput(purpose, envelope), privateKey).toString('base64')
}

export function verifyEnvelope(
  purpose: SignaturePurpose,
  envelope: object,
  publicKey: KeyLike,
): boolean {
  const record = envelope as Record<string, unknown>
  if (typeof record.signature !== 'string') return false
  return verify(
    null,
    signatureInput(purpose, record),
    publicKey,
    Buffer.from(record.signature, 'base64'),
  )
}

export const CONNECTION_GRANT_MAX_LIFETIME_MS = 5 * 60 * 1000
export const RENDEZVOUS_TICKET_MAX_LIFETIME_MS = 10 * 60 * 1000
export const GATEWAY_GRANT_MAX_LIFETIME_MS = 5 * 60 * 1000
export const APPLE_APP_AGENT_READINESS_MAX_LIFETIME_MS = 30 * 1000
const MAX_CLOCK_SKEW_MS = 30 * 1000

function publicKeyFromBase64(value: string): KeyLike {
  return createPublicKey({
    key: Buffer.from(value, 'base64'),
    format: 'der',
    type: 'spki',
  })
}

function hasValidLifetime(
  issuedAtValue: string,
  expiresAtValue: string,
  maximumLifetime: number,
  now: number,
): boolean {
  const issuedAt = Date.parse(issuedAtValue)
  const expiresAt = Date.parse(expiresAtValue)
  return Number.isFinite(issuedAt)
    && Number.isFinite(expiresAt)
    && issuedAt <= now + MAX_CLOCK_SKEW_MS
    && expiresAt > now
    && expiresAt > issuedAt
    && expiresAt - issuedAt <= maximumLifetime
}

export function validateConnectionGrant(
  grant: ConnectionGrant,
  now = Date.now(),
  expectedGeneration: number | undefined = undefined,
): boolean {
  if (grant.version !== HUB_NETWORK_WIRE_VERSION || !grant.grantId || !grant.hubKey) return false
  if (expectedGeneration !== undefined && grant.generation !== expectedGeneration) return false
  if (!hasValidLifetime(grant.issuedAt, grant.expiresAt, CONNECTION_GRANT_MAX_LIFETIME_MS, now)) return false
  try {
    return verifyEnvelope('connection-grant', grant, publicKeyFromBase64(grant.hubKey))
  } catch {
    return false
  }
}

export function validateRendezvousTicket(ticket: RendezvousTicket, now = Date.now()): boolean {
  if (ticket.version !== HUB_NETWORK_WIRE_VERSION || !ticket.ticketId || !ticket.hubKey) return false
  if (ticket.sessionPurpose !== 'peer-connect' || ticket.roles.length !== 1 || ticket.roles[0] !== 'rendezvous') {
    return false
  }
  if (!hasValidLifetime(ticket.issuedAt, ticket.expiresAt, RENDEZVOUS_TICKET_MAX_LIFETIME_MS, now)) return false
  try {
    return verifyEnvelope('rendezvous-ticket', ticket, publicKeyFromBase64(ticket.hubKey))
  } catch {
    return false
  }
}

export function validateGatewayGrant(
  grant: GatewayGrant,
  now = Date.now(),
  expectedGeneration: number | undefined = undefined,
): boolean {
  if (grant.version !== HUB_NETWORK_WIRE_VERSION || !grant.grantId || !grant.hubKey) return false
  if (expectedGeneration !== undefined && grant.generation !== expectedGeneration) return false
  if (!grant.ipv4 && !grant.ipv6) return false
  if (!hasValidLifetime(grant.issuedAt, grant.expiresAt, GATEWAY_GRANT_MAX_LIFETIME_MS, now)) return false
  try {
    return verifyEnvelope('gateway-grant', grant, publicKeyFromBase64(grant.hubKey))
  } catch {
    return false
  }
}

export function validateAppleAppAgentReadiness(
  assertion: import('./wire').AppleAppAgentReadinessAssertion,
  key: string,
  now = Date.now(),
  expected?: {
    hubNetworkId: string
    tunnelInstanceId: string
    generation: number
  },
): boolean {
  if (
    assertion.version !== HUB_NETWORK_WIRE_VERSION
    || assertion.signatureDomain !== SIGNATURE_DOMAINS['apple-app-agent-readiness']
    || assertion.capabilities.length !== 1
    || assertion.capabilities[0] !== 'invitation-bootstrap-v1'
  ) return false
  if (
    expected
    && (assertion.hubNetworkId !== expected.hubNetworkId
      || assertion.tunnelInstanceId !== expected.tunnelInstanceId
      || assertion.generation !== expected.generation)
  ) return false
  if (!hasValidLifetime(
    assertion.issuedAt,
    assertion.expiresAt,
    APPLE_APP_AGENT_READINESS_MAX_LIFETIME_MS,
    now,
  )) return false
  try {
    return verifyEnvelope(
      'apple-app-agent-readiness',
      assertion,
      publicKeyFromBase64(key),
    )
  } catch {
    return false
  }
}

/**
 * One-time-use protection for grant and ticket consumers. Entries expire with
 * their signed envelope, keeping the replay cache bounded over time.
 */
export class SignedEnvelopeReplayGuard {
  private consumed = new Map<string, number>()

  consumeGrant(grant: ConnectionGrant, now = Date.now(), expectedGeneration?: number): boolean {
    return validateConnectionGrant(grant, now, expectedGeneration)
      && this.consume(`grant:${grant.grantId}`, grant.expiresAt, now)
  }

  consumeTicket(ticket: RendezvousTicket, now = Date.now()): boolean {
    return validateRendezvousTicket(ticket, now) && this.consume(`ticket:${ticket.ticketId}`, ticket.expiresAt, now)
  }

  private consume(id: string, expiresAtValue: string, now: number): boolean {
    for (const [consumedId, expiresAt] of this.consumed) {
      if (expiresAt <= now) this.consumed.delete(consumedId)
    }
    if (this.consumed.has(id)) return false
    this.consumed.set(id, Date.parse(expiresAtValue))
    return true
  }
}
