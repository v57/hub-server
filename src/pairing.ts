import { randomBytes, randomInt, scrypt, timingSafeEqual } from 'crypto'
import { chmod, mkdir, rename, unlink, writeFile } from 'fs/promises'

/** Crockford base32 without `I L O U` (protocol.md section 12) */
export const pairingAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
export const pairingCodeLength = 6
/** Seconds a code stays valid */
export const pairingLifetime = 60 * 60
/** Wrong codes that invalidate a code */
export const pairingMaxAttempts = 10
/** Shortest verification in milliseconds, so guessing gets about one try per second */
export const pairingMinDuration = 1000

/** `data/pairing.json`: only the scrypt hash of the code is stored */
interface PairingFile {
  /** base64, 16 random bytes */
  salt: string
  /** base64 of scrypt(normalized code, salt), N=16384 r=8 p=1, 32 bytes */
  hash: string
  /** Unix seconds */
  expires: number
  /** Wrong codes so far */
  attempts: number
}

export function generatePairingCode(): string {
  let code = ''
  for (let i = 0; i < pairingCodeLength; i++) code += pairingAlphabet[randomInt(pairingAlphabet.length)]
  return code
}

/** `K7Q2MX` → `K7Q-2MX` */
export function formatPairingCode(code: string): string {
  return `${code.slice(0, 3)}-${code.slice(3)}`
}

/** Ignores case, spaces and `-`; undefined unless 6 symbols of the alphabet are left */
export function normalizePairingCode(input: unknown): string | undefined {
  if (typeof input !== 'string') return
  const code = input.replace(/[\s-]/g, '').toUpperCase()
  if (code.length !== pairingCodeLength) return
  for (const symbol of code) if (!pairingAlphabet.includes(symbol)) return
  return code
}

function hashCode(code: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    scrypt(code, salt, 32, { N: 16384, r: 8, p: 1 }, (error, key) => (error ? reject(error) : resolve(key))),
  )
}

const now = () => Math.floor(Date.now() / 1000)

/**
 * The pairing code that makes its first user an owner (protocol.md section 12). The hash lives in
 * `data/pairing.json`, the plain code in `data/pairing-code` for the launcher, both 0600. The running hub re-reads
 * `data/pairing.json` on every attempt, so a code from the one-shot `hub-server --pair` works at once.
 */
export class Pairing {
  readonly path: string
  readonly codePath: string
  /** Shortest verification in milliseconds */
  minDuration: number
  private state?: PairingFile
  private queue: Promise<unknown> = Promise.resolve()
  private expiryTimer?: ReturnType<typeof setTimeout>
  constructor(readonly directory = 'data', options: { minDuration?: number } = {}) {
    this.path = `${directory}/pairing.json`
    this.codePath = `${directory}/pairing-code`
    this.minDuration = options.minDuration ?? pairingMinDuration
  }

  /** Whether a code can be used now */
  get active(): boolean {
    return !!this.state && this.state.expires > now() && this.state.attempts < pairingMaxAttempts
  }
  get expires(): number | undefined {
    return this.state?.expires
  }

  /** Loads a stored code; an expired, used up or unreadable one is removed */
  async load() {
    await this.reload()
    if (this.active) this.scheduleExpiry()
    else await this.clear()
    return this
  }

  /** Reads `data/pairing.json`, which `hub-server --pair` may have replaced from another process */
  private async reload() {
    this.state = await this.read()
  }

  private async read(): Promise<PairingFile | undefined> {
    try {
      const data = await Bun.file(this.path).json()
      if (typeof data?.salt === 'string' && typeof data.hash === 'string' && Number.isFinite(data.expires) && Number.isInteger(data.attempts)) {
        return { salt: data.salt, hash: data.hash, expires: data.expires, attempts: data.attempts }
      }
    } catch {}
  }

  /**
   * At start: a new code when `force`, else when `needed` (no owners) and no valid one is stored. Prints
   * the code. Returns the code in use, if any.
   */
  async start(options: { needed: boolean; force?: boolean }): Promise<string | undefined> {
    if (!options.force) {
      if (!options.needed) return
      const stored = await this.storedCode()
      if (stored) {
        this.print(stored)
        return stored
      }
    }
    const code = await this.create()
    this.print(code)
    return code
  }

  /** A new code replacing the old one, formatted `XXX-XXX` */
  async create(): Promise<string> {
    const code = generatePairingCode()
    const salt = randomBytes(16)
    const hash = await hashCode(code, salt)
    this.state = { salt: salt.toString('base64'), hash: hash.toString('base64'), expires: now() + pairingLifetime, attempts: 0 }
    const formatted = formatPairingCode(code)
    await this.writeState()
    await writePrivate(this.codePath, formatted)
    this.scheduleExpiry()
    return formatted
  }

  /**
   * Checks a code. Verifications run one at a time and each takes at least `minDuration`. Throws `no pairing code`
   * or `invalid pairing code`; a success consumes the code.
   */
  verify(input: unknown): Promise<void> {
    const result = this.queue.then(() => this.verifyNow(input))
    this.queue = result.catch(() => {})
    return result
  }

  private async verifyNow(input: unknown) {
    const started = Date.now()
    try {
      await this.reload()
      if (!this.active) {
        if (this.state) await this.clear()
        throw 'no pairing code'
      }
      const state = this.state!
      const code = normalizePairingCode(input)
      // Hashes even malformed input, so every answer takes the same time
      const hash = await hashCode(code ?? '', Buffer.from(state.salt, 'base64'))
      // `hub-server --pair` replaced the code meanwhile: leave its files alone
      if ((await this.read())?.hash !== state.hash) throw 'invalid pairing code'
      const expected = Buffer.from(state.hash, 'base64')
      if (code && hash.length === expected.length && timingSafeEqual(hash, expected)) {
        await this.clear()
        return
      }
      state.attempts += 1
      if (state.attempts >= pairingMaxAttempts) await this.clear()
      else await this.writeState()
      throw 'invalid pairing code'
    } finally {
      const left = this.minDuration - (Date.now() - started)
      if (left > 0) await Bun.sleep(left)
    }
  }

  /** Forgets the code and deletes both files */
  async clear() {
    this.state = undefined
    if (this.expiryTimer) clearTimeout(this.expiryTimer)
    this.expiryTimer = undefined
    await Promise.all([unlink(this.path).catch(() => {}), unlink(this.codePath).catch(() => {})])
  }

  /** The plain code from `data/pairing-code`, when it matches the stored hash */
  private async storedCode(): Promise<string | undefined> {
    if (!this.active) return
    try {
      const formatted = (await Bun.file(this.codePath).text()).trim()
      const code = normalizePairingCode(formatted)
      if (!code) return
      const hash = await hashCode(code, Buffer.from(this.state!.salt, 'base64'))
      if (hash.equals(Buffer.from(this.state!.hash, 'base64'))) return formatPairingCode(code)
    } catch {}
  }

  private print(code: string) {
    console.log(`Pairing code: ${code} (valid until ${new Date(this.state!.expires * 1000).toISOString()})`)
  }

  private writeState() {
    return writePrivate(this.path, JSON.stringify(this.state))
  }

  private scheduleExpiry() {
    if (this.expiryTimer) clearTimeout(this.expiryTimer)
    const state = this.state
    if (!state) return
    // setTimeout overflows past about 24.8 days; codes live an hour
    const delay = Math.min(Math.max(0, state.expires * 1000 - Date.now()), 2 ** 31 - 1)
    // Through the queue, and only if the file still holds an expired code (`--pair` may have made a new one)
    this.expiryTimer = setTimeout(() => {
      this.queue = this.queue.then(() => this.load()).catch(() => {})
    }, delay)
    this.expiryTimer.unref?.()
  }
}

/** Writes a 0600 file through a temp file and a rename */
async function writePrivate(path: string, text: string) {
  await mkdir(path.slice(0, path.lastIndexOf('/')) || '.', { recursive: true })
  const temp = `${path}.${process.pid}.${Date.now()}.tmp`
  await writeFile(temp, text, { mode: 0o600 })
  await chmod(temp, 0o600)
  await rename(temp, path)
}
