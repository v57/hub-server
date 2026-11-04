import { createHmac, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto'

/** How long a `hub/info` challenge stays valid, in seconds */
export const nonceLifetime = 60
/** Most used nonces kept. Reaching it changes the secret instead of growing or forgetting a nonce that still counts. */
export const usedNoncesLimit = 65536

const expiryBytes = 8
const randomLength = 16
const macLength = 16
const nonceBytes = expiryBytes + randomLength + macLength

/**
 * The challenges v1 tokens sign (protocol.md section 2). Handing one out stores nothing: it carries its expiry and a
 * MAC under a secret that lives only in this process, so a restart invalidates them all. Only a token whose signature
 * verified records its nonce as used, until the nonce's own expiry.
 */
export class TokenNonces {
  private secret = randomBytes(32)
  /** Used nonces and when each stops being valid anyway */
  private used = new Map<string, number>()
  constructor(private limit = usedNoncesLimit) {}
  get usedCount(): number {
    return this.used.size
  }
  issue(now = Math.floor(Date.now() / 1000)): string {
    const body = Buffer.alloc(expiryBytes + randomLength)
    body.writeBigUInt64BE(BigInt(now + nonceLifetime))
    randomBytes(randomLength).copy(body, expiryBytes)
    return Buffer.concat([body, this.mac(body)]).toString('base64url')
  }
  /** Whether this hub made the nonce and it hasn't expired. Costs one HMAC, so it runs before the signature check. */
  isValid(nonce: string, now = Math.floor(Date.now() / 1000)): boolean {
    return this.expiry(nonce, now) !== undefined && !this.used.has(nonce)
  }
  /** Records the nonce of a token whose signature verified. False when it can't be used (again). */
  consume(nonce: string, now = Math.floor(Date.now() / 1000)): boolean {
    const expiry = this.expiry(nonce, now)
    if (expiry === undefined || this.used.has(nonce)) return false
    if (this.used.size >= this.limit) this.prune(now)
    if (this.used.size >= this.limit) {
      // Full of nonces that still count: the old secret goes with them, so none of them can come back. This one too.
      this.secret = randomBytes(32)
      this.used.clear()
      return false
    }
    this.used.set(nonce, expiry)
    return true
  }
  private expiry(nonce: string, now: number): number | undefined {
    if (typeof nonce !== 'string' || nonce.length > 128) return
    const bytes = Buffer.from(nonce, 'base64url')
    if (bytes.length !== nonceBytes || bytes.toString('base64url') !== nonce) return
    const body = bytes.subarray(0, expiryBytes + randomLength)
    if (!timingSafeEqual(bytes.subarray(expiryBytes + randomLength), this.mac(body))) return
    const expiry = Number(bytes.readBigUInt64BE())
    return expiry > now ? expiry : undefined
  }
  private mac(body: Buffer): Buffer {
    return createHmac('sha256', this.secret).update(body).digest().subarray(0, macLength)
  }
  private prune(now: number) {
    for (const [nonce, expiry] of this.used) if (expiry <= now) this.used.delete(nonce)
  }
}

/** A client nonce `hub/info` proves the hub's key over */
export const isClientNonce = (nonce: unknown): nonce is string => typeof nonce === 'string' && /^[A-Za-z0-9_-]{16,128}$/.test(nonce)
/** The string `proof` signs */
export const hubInfoSignedData = (hubKey: string, nonce: string) => `hubinfo1:${hubKey}:${nonce}`
/** Whether a `hub/info` answer proves its key over `nonce` */
export function verifyHubProof(info: any, nonce: string): info is { key: string; proof: string; challenge: string } {
  if (typeof info?.key !== 'string' || typeof info?.proof !== 'string' || typeof info?.challenge !== 'string') return false
  try {
    const key = createPublicKey({ key: Buffer.from(info.key, 'base64'), format: 'der', type: 'spki' })
    return verify(null, Buffer.from(hubInfoSignedData(info.key, nonce)), key, Buffer.from(info.proof, 'base64'))
  } catch {
    return false
  }
}
