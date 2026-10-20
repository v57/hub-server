import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, verify } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import { homedir, hostname } from 'node:os'
import { dirname, join } from 'node:path'
import { Storage, writeAtomically } from './settings'

// Device layer, protocol.md sections 1, 3, 5, 6 and 8

/** Longest certificate lifetime, 7 days */
export const certificateMaxLifetime = 604800
const clockSkew = 30
const platforms = new Set(['macos', 'ios', 'ipados', 'visionos', 'tvos', 'watchos', 'linux', 'windows', 'android', 'other'])

/** First 32 hex characters of SHA-256 of the device SPKI DER bytes */
export function deviceId(key: string): string {
  return createHash('sha256').update(Buffer.from(key, 'base64')).digest('hex').slice(0, 32)
}

/** Six digits from the key hash, shown as `ddd ddd` on both devices when approving */
export function safetyCode(key: string): string {
  const hash = createHash('sha256').update(Buffer.from(key, 'base64')).digest('hex')
  const code = (parseInt(hash.slice(0, 8), 16) % 1000000).toString().padStart(6, '0')
  return `${code.slice(0, 3)} ${code.slice(3)}`
}

/** A verified `device` header */
export interface Certificate {
  device: string
  deviceId: string
  service: string
  instance: string
  deviceName?: string
  platform?: string
  parent?: string
  iat: number
  exp: number
}

const bytes = (value: string) => Buffer.byteLength(value, 'utf8')
const optionalString = (value: unknown, max: number): value is string | undefined =>
  value === undefined || (typeof value === 'string' && bytes(value) <= max)

/**
 * Checks a `device` header for the service key in `auth`. Returns the certificate or the reason it isn't valid;
 * an invalid certificate makes a plain key connection, it never refuses one.
 */
export function verifyCertificate(
  header: string,
  serviceKey: string,
  hubKey: string | undefined,
  now = Math.floor(Date.now() / 1000),
): Certificate | string {
  const parts = header.split('.')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return 'malformed certificate'
  const [payload, signature] = parts
  let body: any
  try {
    body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
  } catch {
    return 'malformed certificate'
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'malformed certificate'
  if (body.v !== 1) return 'unsupported certificate version'
  if (typeof body.device !== 'string' || typeof body.service !== 'string') return 'malformed certificate'
  if (body.service !== serviceKey) return 'certificate is for another service key'
  if (typeof body.instance !== 'string' || bytes(body.instance) < 1 || bytes(body.instance) > 128) return 'invalid instance'
  if (!optionalString(body.deviceName, 64) || !optionalString(body.parent, 64)) return 'invalid device name or parent'
  if (body.platform !== undefined && typeof body.platform !== 'string') return 'invalid platform'
  if (body.hub !== undefined && body.hub !== hubKey) return 'certificate is for another hub'
  if (!Number.isInteger(body.iat) || !Number.isInteger(body.exp)) return 'invalid times'
  if (body.exp - body.iat > certificateMaxLifetime) return 'certificate lifetime too long'
  if (body.iat > now + clockSkew) return 'certificate issued in the future'
  if (body.exp <= now - clockSkew) return 'certificate expired'
  try {
    const key = createPublicKey({ key: Buffer.from(body.device, 'base64'), format: 'der', type: 'spki' })
    if (key.asymmetricKeyType !== 'ed25519') return 'device key is not Ed25519'
    if (!verify(null, Buffer.from(payload), key, Buffer.from(signature, 'base64'))) return 'invalid certificate signature'
  } catch {
    return 'invalid device key'
  }
  return {
    device: body.device,
    deviceId: deviceId(body.device),
    service: body.service,
    instance: body.instance,
    deviceName: body.deviceName,
    platform: body.platform === undefined ? undefined : platforms.has(body.platform) ? body.platform : 'other',
    parent: body.parent,
    iat: body.iat,
    exp: body.exp,
  }
}

export interface StoredDevice {
  key: string
  name: string
  /** An owner renamed it, the device's own suggestions no longer apply */
  nameByOwner?: boolean
  platform?: string
  os?: string
  arch?: string
  parent?: string
  approved: boolean
  createdAt: string
  lastSeen: string
  revoked: string | null
  capabilities?: Record<string, unknown>
}

export interface StoredService {
  device: string
  instance: string
  name?: string
  lastSeen: string
  previousDevice: string | null
}

export interface DevicesData {
  schema: 1
  devices: Record<string, StoredDevice>
  services: Record<string, StoredService>
  /** Service keys revoked with their device, refused at connect */
  revokedKeys: string[]
}

export interface PendingDevice {
  id: string
  key: string
  name?: string
  platform?: string
  parent?: string
  safetyCode: string
  firstSeen: string
}

/** `data/devices.json`: devices, where each service key runs, and the keys revoked with a device */
export class DeviceRegistry {
  data: DevicesData = emptyDevices()
  storage: Storage
  /** Devices, placements or revocations changed */
  onChange?: () => void
  constructor(path = 'data/devices.json') {
    this.storage = new Storage(
      path,
      () => this.data,
      data => (this.data = decodeDevices(data)),
    )
  }
  async load(): Promise<this> {
    await this.storage.load()
    return this
  }
  private save() {
    this.onChange?.()
    this.storage.save()
  }
  device(id: string): StoredDevice | undefined {
    return this.data.devices[id]
  }
  isKeyRevoked(key: string): boolean {
    return this.data.revokedKeys.includes(key)
  }
  /**
   * Records a connection with a valid certificate: a new device becomes pending, a known one updates its suggested
   * name and `lastSeen`. Returns the device, or undefined when it is revoked.
   */
  seen(certificate: Certificate, approve: boolean): StoredDevice | undefined {
    const now = new Date().toISOString()
    let device = this.data.devices[certificate.deviceId]
    if (device?.revoked) return
    if (!device) {
      device = {
        key: certificate.device,
        name: certificate.deviceName ?? certificate.instance,
        platform: certificate.platform,
        parent: certificate.parent,
        approved: false,
        createdAt: now,
        lastSeen: now,
        revoked: null,
      }
      this.data.devices[certificate.deviceId] = device
    } else {
      device.lastSeen = now
      if (certificate.deviceName && !device.nameByOwner) device.name = certificate.deviceName
      if (certificate.platform) device.platform = certificate.platform
      if (certificate.parent !== undefined) device.parent = certificate.parent
    }
    if (approve) device.approved = true
    this.save()
    return device
  }
  /** Places a service key on an approved device. Returns the device it moved from, if it moved. */
  place(certificate: Certificate, name?: string): string | undefined {
    const now = new Date().toISOString()
    const current = this.data.services[certificate.service]
    const moved = current && current.device !== certificate.deviceId ? current.device : undefined
    this.data.services[certificate.service] = {
      device: certificate.deviceId,
      instance: certificate.instance,
      name: name ?? current?.name,
      lastSeen: now,
      previousDevice: moved ?? current?.previousDevice ?? null,
    }
    this.save()
    return moved
  }
  approve(id: string): StoredDevice {
    const device = this.require(id)
    if (device.revoked) throw 'device revoked'
    device.approved = true
    this.save()
    return device
  }
  rename(id: string, name: unknown): StoredDevice {
    if (typeof name !== 'string' || !name.trim() || bytes(name.trim()) > 64) throw 'invalid name'
    const device = this.require(id)
    device.name = name.trim()
    device.nameByOwner = true
    this.save()
    return device
  }
  update(id: string, update: Partial<Pick<StoredDevice, 'name' | 'os' | 'arch' | 'capabilities'>>) {
    const device = this.require(id)
    if (update.name !== undefined && !device.nameByOwner) device.name = update.name
    if (update.os !== undefined) device.os = update.os
    if (update.arch !== undefined) device.arch = update.arch
    if (update.capabilities !== undefined) device.capabilities = update.capabilities
    this.save()
  }
  /** Forgets the device and its service placements, it can enrol again */
  remove(id: string): string[] {
    this.require(id)
    delete this.data.devices[id]
    const services = this.servicesOn(id)
    for (const key of services) delete this.data.services[key]
    this.save()
    return services
  }
  /** Keeps a tombstone and revokes the service keys placed on it except `keep`. Returns the revoked keys. */
  revoke(id: string, keep: string[] = []): string[] {
    const device = this.require(id)
    device.revoked = new Date().toISOString()
    device.approved = false
    const revoked = this.servicesOn(id).filter(key => !keep.includes(key))
    for (const key of revoked) {
      if (!this.data.revokedKeys.includes(key)) this.data.revokedKeys.push(key)
      delete this.data.services[key]
    }
    this.save()
    return revoked
  }
  servicesOn(id: string): string[] {
    return Object.entries(this.data.services).flatMap(([key, service]) => (service.device === id ? [key] : []))
  }
  pending(): PendingDevice[] {
    return Object.entries(this.data.devices)
      .filter(([, device]) => !device.approved && !device.revoked)
      .map(([id, device]) => ({
        id,
        key: device.key,
        name: device.name,
        platform: device.platform,
        parent: device.parent,
        safetyCode: safetyCode(device.key),
        firstSeen: device.createdAt,
      }))
  }
  private require(id: unknown): StoredDevice {
    const device = typeof id === 'string' ? this.data.devices[id] : undefined
    if (!device) throw 'device not found'
    return device
  }
}

function emptyDevices(): DevicesData {
  return { schema: 1, devices: {}, services: {}, revokedKeys: [] }
}

function decodeDevices(data: any): DevicesData {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not an object')
  if (data.schema !== 1) throw new Error(`unsupported devices schema ${data.schema}`)
  return {
    schema: 1,
    devices: data.devices ?? {},
    services: data.services ?? {},
    revokedKeys: Array.isArray(data.revokedKeys) ? data.revokedKeys : [],
  }
}

/** This machine's device key: `HUB_DEVICE_KEY`, `/var/lib/hub/device.key` for root on Linux, else `~/.hub/device.key` */
export function deviceKeyPath(): string {
  if (Bun.env.HUB_DEVICE_KEY) return Bun.env.HUB_DEVICE_KEY
  if (process.platform === 'linux' && process.getuid?.() === 0) return '/var/lib/hub/device.key'
  return join(homedir(), '.hub', 'device.key')
}

/** Loads the device key file (PKCS#8 then SPKI, base64), creating it if absent. Returns its SPKI. */
export async function loadDeviceKey(path = deviceKeyPath()): Promise<string> {
  const file = Bun.file(path)
  if (await file.exists()) {
    const der = Buffer.from((await file.text()).trim(), 'base64')
    // Derive the public key from the private part, so a damaged file fails here instead of signing wrong
    const privateKey = createPrivateKey({ key: der.subarray(0, 48), format: 'der', type: 'pkcs8' })
    return createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64')
  }
  const keys = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { format: 'der', type: 'pkcs8' },
    publicKeyEncoding: { format: 'der', type: 'spki' },
  })
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  await writeAtomically(path, Buffer.concat([keys.privateKey, keys.publicKey]).toString('base64'), 0o600)
  return keys.publicKey.toString('base64')
}

export function hostPlatform(): string {
  switch (process.platform) {
    case 'darwin':
      return 'macos'
    case 'linux':
      return 'linux'
    case 'win32':
      return 'windows'
    default:
      return 'other'
  }
}

export const hostName = () => hostname().replace(/\.local$/, '')
