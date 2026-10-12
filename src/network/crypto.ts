import { sign, verify, type KeyLike } from 'node:crypto'

export type SignaturePurpose = 'agent-attestation' | 'profile-binding' | 'connection-grant' | 'rendezvous-ticket'

export const SIGNATURE_DOMAINS: Record<SignaturePurpose, string> = {
  'agent-attestation': 'hub-network/agent-attestation/v1',
  'profile-binding': 'hub-network/profile-binding/v1',
  'connection-grant': 'hub-network/connection-grant/v1',
  'rendezvous-ticket': 'hub-network/rendezvous-ticket/v1',
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

export function signatureInput(purpose: SignaturePurpose, envelope: Record<string, unknown>): Uint8Array {
  const unsigned = { ...envelope }
  delete unsigned.signature
  const payload = Buffer.from(canonicalJSON(unsigned), 'utf8')
  const domain = Buffer.from(SIGNATURE_DOMAINS[purpose], 'ascii')
  const length = Buffer.allocUnsafe(4)
  length.writeUInt32BE(payload.length)
  return Buffer.concat([domain, Buffer.of(0), length, payload])
}

export function signEnvelope(
  purpose: SignaturePurpose,
  envelope: Record<string, unknown>,
  privateKey: KeyLike,
): string {
  return sign(null, signatureInput(purpose, envelope), privateKey).toString('base64')
}

export function verifyEnvelope(
  purpose: SignaturePurpose,
  envelope: Record<string, unknown>,
  publicKey: KeyLike,
): boolean {
  if (typeof envelope.signature !== 'string') return false
  return verify(
    null,
    signatureInput(purpose, envelope),
    publicKey,
    Buffer.from(envelope.signature, 'base64'),
  )
}

