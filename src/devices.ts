import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, verify } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import { homedir, hostname } from 'node:os'
import { dirname, join } from 'node:path'
import { Storage, writeAtomically } from './settings'
import { cleanName, freeName, normalizeName } from './names'

// Device layer, protocol.md sections 1, 3, 5, 6 and 8

/** Longest certificate lifetime, 7 days */
export const certificateMaxLifetime = 604800
const clockSkew = 30
const platforms = new Set(['macos', 'ios', 'ipados', 'visionos', 'tvos', 'watchos', 'linux', 'windows', 'android', 'other'])

/** First 32 hex characters of SHA-256 of the device SPKI DER bytes */
export function deviceId(key: string): string {
  return createHash('sha256').update(Buffer.from(key, 'base64')).digest('hex').slice(0, 32)
}

/** What a device's safety code covers besides its key: 32 random bytes, picked once the hub has the key */
export const newCodeValue = () => randomBytes(32).toString('base64url')

/**
 * Six digits shown as `ddd ddd` on the device and to the owner approving it. The value comes from the hub after it has
 * the key, so a key can't be ground offline to match a code: each guess costs one request.
 */
export function safetyCode(hubKey: string, key: string, codeValue: string): string {
  const hash = createHash('sha256').update(`hubcode1:${hubKey}:${key}:${codeValue}`).digest('hex')
  const code = (parseInt(hash.slice(0, 8), 16) % 1000000).toString().padStart(6, '0')
  return `${code.slice(0, 3)} ${code.slice(3)}`
}

/** What a parent signs to take a child: `hubattach1:<hub SPKI>:<parent SPKI>:<child SPKI>:<at>` (protocol.md section 14) */
export const attachSignedData = (hubKey: string, parentKey: string, childKey: string, at: number) =>
  `hubattach1:${hubKey}:${parentKey}:${childKey}:${at}`
/** An attach signature counts for this long either way, in seconds */
export const attachLifetime = 300

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
  /** The name it last asked for, when the one it got differs */
  askedName?: string
  /** What its safety code covers, kept for as long as the hub knows the device */
  codeValue?: string
  platform?: string
  os?: string
  arch?: string
  parent?: string
  approved: boolean
  createdAt: string
  lastSeen: string
  revoked: string | null
  capabilities?: Record<string, unknown>
  /** The parent that signed for this device. Checked once at attach, and calls never walk it. */
  attached?: { parent: string; parentKey: string; at: number; signature: string; linked?: true }
  /** It asked to attach, to `parent` if it named one */
  attachAsk?: { at: string; parent?: string }
  /** An attach request was turned down; further ones are ignored while the hub knows it */
  attachDismissed?: true
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
  codeValue: string
  firstSeen: string
}

/** `hub/device/attach/requests`: a device that asked to attach, with what to compare before signing */
export interface AttachRequest {
  id: string
  key: string
  name: string
  platform?: string
  approved: boolean
  safetyCode: string
  codeValue: string
  parent?: string
  askedAt: string
}

/** Most pending requests a hub keeps. A guess against a code has to be on the list when the owner compares. */
export const maxPendingDevices = 256

/** `data/devices.json`: devices, where each service key runs, and the keys revoked with a device */
export class DeviceRegistry {
  data: DevicesData = emptyDevices()
  storage: Storage
  /** Devices, placements or revocations changed */
  onChange?: () => void
  /** The hub's key, which safety codes cover */
  hubKey = ''
  constructor(path = 'data/devices.json') {
    this.storage = new Storage(
      path,
      () => this.data,
      data => (this.data = decodeDevices(data)),
    )
  }
  async load(): Promise<this> {
    await this.storage.load()
    if (!this.storage.corrupt && this.settleStored()) await this.storage.write()
    return this
  }
  /**
   * Stores from before names were unique and codes covered a value: every device gets a value, and of approved devices
   * with the same name the one that came first keeps it. Names an owner set stay, even two of the same.
   */
  private settleStored(): boolean {
    let changed = false
    const entries = Object.entries(this.data.devices)
    for (const [, device] of entries) {
      if (device.codeValue || device.revoked) continue
      device.codeValue = newCodeValue()
      changed = true
    }
    const holders = entries
      .filter(([, device]) => device.approved && !device.revoked)
      .sort(([a, left], [b, right]) => left.createdAt.localeCompare(right.createdAt) || a.localeCompare(b))
    const held = new Set(holders.filter(([, device]) => device.nameByOwner).map(([, device]) => normalizeName(device.name)))
    for (const [, device] of holders) {
      if (device.nameByOwner) continue
      const name = freeName(device.name, normalized => held.has(normalized))
      if (name !== device.name) {
        device.askedName = device.name
        device.name = name
        changed = true
      }
      held.add(normalizeName(name))
    }
    const pending = entries.filter(([, device]) => !device.approved && !device.revoked)
    pending.sort(([, left], [, right]) => left.createdAt.localeCompare(right.createdAt))
    for (const [id] of pending.slice(0, Math.max(0, pending.length - maxPendingDevices))) {
      delete this.data.devices[id]
      changed = true
    }
    return changed
  }
  /** The names approved devices hold, normalized, except `id`'s. A pending request or a revoked device holds none. */
  private heldNames(id?: string): Map<string, string> {
    const held = new Map<string, string>()
    for (const [other, device] of Object.entries(this.data.devices)) {
      if (other !== id && device.approved && !device.revoked) held.set(normalizeName(device.name), other)
    }
    return held
  }
  private freeNameFor(id: string, asked: string): string {
    const held = this.heldNames(id)
    return freeName(asked, normalized => held.has(normalized))
  }
  /** A device suggests a name for itself: a pending one shows what it asks for, an approved one gets a free name */
  private suggest(id: string, device: StoredDevice, asked: string) {
    if (device.nameByOwner) return
    const clean = cleanName(asked)
    if (!device.approved) {
      device.name = clean
    } else if (clean !== (device.askedName ?? device.name)) {
      device.askedName = clean
      device.name = this.freeNameFor(id, clean)
    }
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
        name: cleanName(certificate.deviceName ?? certificate.instance),
        codeValue: newCodeValue(),
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
      if (certificate.deviceName) this.suggest(certificate.deviceId, device, certificate.deviceName)
      if (certificate.platform) device.platform = certificate.platform
      if (certificate.parent !== undefined) device.parent = certificate.parent
    }
    if (approve) this.settle(certificate.deviceId, device)
    this.save()
    return device
  }
  /** Approved from now on: a request gets its final name here */
  private settle(id: string, device: StoredDevice) {
    if (device.approved) return
    device.approved = true
    if (device.nameByOwner) {
      this.claim(id, device, device.name)
    } else {
      const name = this.freeNameFor(id, device.name)
      if (name !== device.name) device.askedName = device.name
      device.name = name
    }
  }
  /**
   * An owner's name: a device that only asked for the same one moves to a free name. Against a name an owner set, the
   * newer one gets the suffix, for an approval that has no one to ask, or `name taken` for a rename.
   */
  private claim(id: string, device: StoredDevice, name: string, refuse = false) {
    const holder = this.heldNames(id).get(normalizeName(name))
    const other = holder ? this.data.devices[holder] : undefined
    if (other?.nameByOwner) {
      if (refuse) throw 'name taken'
      device.name = this.freeNameFor(id, name)
      return
    }
    device.name = name
    if (other) {
      other.askedName ??= other.name
      other.name = this.freeNameFor(holder!, other.askedName)
    }
  }
  /** A device with a certificate asks to attach. Ignored once attached or turned down. */
  askAttach(id: string, parent?: string) {
    const device = this.require(id)
    if (device.revoked || device.attached || device.attachDismissed) return
    if (device.attachAsk && device.attachAsk.parent === parent) return
    device.attachAsk = { at: new Date().toISOString(), ...(parent ? { parent } : {}) }
    this.save()
  }
  /** Turns an attach request down */
  dismissAttach(id: unknown) {
    const device = this.require(id)
    delete device.attachAsk
    device.attachDismissed = true
    this.save()
  }
  /** What's asked of the hub right now, oldest first */
  attachRequests(): AttachRequest[] {
    return Object.entries(this.data.devices)
      .filter(([, device]) => device.attachAsk && !device.attached && !device.revoked)
      .sort(([, left], [, right]) => left.attachAsk!.at.localeCompare(right.attachAsk!.at))
      .map(([id, device]) => ({
        id,
        key: device.key,
        name: device.name,
        platform: device.platform,
        approved: device.approved,
        safetyCode: safetyCode(this.hubKey, device.key, this.codeValue(device)),
        codeValue: this.codeValue(device),
        parent: device.attachAsk!.parent,
        askedAt: device.attachAsk!.at,
      }))
  }
  /**
   * The parent's signature, checked here and never again. The child must have asked, and it starts with nothing linked.
   * `approve`: the signer is an owner, whose word approves the child too.
   */
  attach(childId: unknown, parentId: string, at: unknown, signature: unknown, approve: boolean, now = Math.floor(Date.now() / 1000)): StoredDevice {
    const child = this.require(childId)
    const parent = this.require(parentId)
    const id = childId as string
    if (child.revoked || parent.revoked) throw 'device revoked'
    if (!parent.approved) throw 'permissions required'
    if (child.attached) throw 'already attached'
    if (!child.attachAsk) throw 'no attach request'
    // Up from the parent: reaching the child would close a loop. Stored links can't loop, the seen set is a guard.
    const seen = new Set<string>()
    for (let current: string | undefined = parentId; current && !seen.has(current); current = this.data.devices[current]?.attached?.parent) {
      if (current === id) throw 'attach would make a loop'
      seen.add(current)
    }
    if (!Number.isInteger(at) || Math.abs((at as number) - now) > attachLifetime) throw 'attach signature expired'
    if (typeof signature !== 'string' || !verifySignature(parent.key, attachSignedData(this.hubKey, parent.key, child.key, at as number), signature)) throw 'invalid signature'
    child.attached = { parent: parentId, parentKey: parent.key, at: at as number, signature }
    delete child.attachAsk
    if (approve) this.settle(id, child)
    this.save()
    return child
  }
  /** Ends a link. The device stays as it is otherwise; the copies it had go with the link. */
  detach(id: unknown): StoredDevice {
    const device = this.require(id)
    if (!device.attached) throw 'not attached'
    delete device.attached
    this.save()
    return device
  }
  /** Whether the chain of linked grants reaches this child: new children start out of it */
  setLinked(id: unknown, linked: boolean): StoredDevice {
    const device = this.require(id)
    if (!device.attached) throw 'not attached'
    if ((device.attached.linked === true) === linked) return device
    if (linked) device.attached.linked = true
    else delete device.attached.linked
    this.save()
    return device
  }
  isChild(id: string): boolean {
    return !!this.data.devices[id]?.attached
  }
  /** The children linked grants pass to: approved, not revoked, and linked by the owner */
  linkedChildren(id: string): string[] {
    return Object.entries(this.data.devices).flatMap(([child, device]) =>
      device.attached?.parent === id && device.attached.linked && device.approved && !device.revoked ? [child] : [],
    )
  }
  /** Every device below this one, linked or not, nearest first */
  below(id: string): string[] {
    const found: string[] = []
    const walk = [id]
    const seen = new Set([id])
    while (walk.length) {
      const current = walk.shift()!
      for (const [child, device] of Object.entries(this.data.devices)) {
        if (device.attached?.parent !== current || seen.has(child)) continue
        seen.add(child)
        found.push(child)
        walk.push(child)
      }
    }
    return found
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
    this.settle(id as string, device)
    this.save()
    return device
  }
  rename(id: string, name: unknown): StoredDevice {
    if (typeof name !== 'string' || !name.trim() || bytes(name.trim()) > 64) throw 'invalid name'
    const device = this.require(id)
    const clean = cleanName(name)
    if (device.approved) this.claim(id, device, clean, true)
    else device.name = clean
    device.nameByOwner = true
    delete device.askedName
    this.save()
    return device
  }
  update(id: string, update: Partial<Pick<StoredDevice, 'name' | 'os' | 'arch' | 'capabilities'>>) {
    const device = this.require(id)
    if (update.name !== undefined) this.suggest(id, device, update.name)
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
        safetyCode: safetyCode(this.hubKey, device.key, this.codeValue(device)),
        codeValue: this.codeValue(device),
        firstSeen: device.createdAt,
      }))
  }
  /** Its value, which it keeps once picked */
  codeValue(device: StoredDevice): string {
    return (device.codeValue ??= newCodeValue())
  }
  /** The ids of pending requests, oldest first */
  pendingIds(): string[] {
    return Object.entries(this.data.devices)
      .filter(([, device]) => !device.approved && !device.revoked)
      .sort(([, left], [, right]) => left.createdAt.localeCompare(right.createdAt))
      .map(([id]) => id)
  }
  private require(id: unknown): StoredDevice {
    const device = typeof id === 'string' ? this.data.devices[id] : undefined
    if (!device) throw 'device not found'
    return device
  }
}

function verifySignature(spki: string, text: string, signature: string): boolean {
  try {
    const key = createPublicKey({ key: Buffer.from(spki, 'base64'), format: 'der', type: 'spki' })
    return key.asymmetricKeyType === 'ed25519' && verify(null, Buffer.from(text), key, Buffer.from(signature, 'base64'))
  } catch {
    return false
  }
}

/** A request waits its turn with these at most: per source, and sources */
const maxWaitingPerSource = 8
const maxWaitingSources = 4096

/**
 * The one way a new device gets on the pending list: one request a second for the whole hub, sources taking turns, so
 * rotating addresses doesn't buy guesses and one flooding address doesn't push others out. A flood delays a real
 * request. What waits is bounded; a request beyond that isn't queued, and the connection asks again when its stream
 * recomputes or it reconnects.
 */
export class RequestGate<Request extends { deviceId: string }> {
  /** Milliseconds between requests */
  interval = 1000
  /** Oldest turn first */
  private waiting = new Map<string, Request[]>()
  private lastAdmission = -Infinity
  private timer?: ReturnType<typeof setTimeout>
  constructor(private admit: (request: Request) => void) {}
  has(deviceId: string): boolean {
    for (const requests of this.waiting.values()) if (requests.some(request => request.deviceId === deviceId)) return true
    return false
  }
  /** Queues a request, once per device. Admits at once while the hub is idle. */
  ask(source: string, request: Request) {
    if (this.has(request.deviceId)) return
    const queue = this.waiting.get(source)
    if (queue ? queue.length >= maxWaitingPerSource : this.waiting.size >= maxWaitingSources) return
    if (queue) queue.push(request)
    else this.waiting.set(source, [request])
    this.next()
  }
  /** Forgets what `matches` picks: its connection went, or it needs no turn any more */
  forget(matches: (request: Request) => boolean) {
    for (const [source, requests] of this.waiting) {
      const left = requests.filter(request => !matches(request))
      if (left.length) this.waiting.set(source, left)
      else this.waiting.delete(source)
    }
  }
  private next() {
    if (this.timer || !this.waiting.size) return
    const wait = this.lastAdmission + this.interval - performance.now()
    if (wait > 0) {
      this.timer = setTimeout(() => {
        this.timer = undefined
        this.next()
      }, wait)
      this.timer.unref?.()
      return
    }
    const [source, requests] = this.waiting.entries().next().value!
    const request = requests.shift()!
    // The source goes to the end of the line
    this.waiting.delete(source)
    if (requests.length) this.waiting.set(source, requests)
    this.lastAdmission = performance.now()
    this.admit(request)
    this.next()
  }
}

/**
 * The address a request counts against: IPv4, or the /64 of IPv6, which is what one host usually has. Behind a proxy
 * every request has the proxy's address, so they share one turn; the hub trusts no forwarded header, as a client could
 * send any, and the limit for the whole hub holds either way.
 */
export function requestSource(address: string | undefined): string {
  if (!address) return 'unknown'
  const plain = address.split('%')[0]!.toLowerCase()
  if (plain.startsWith('::ffff:') && plain.includes('.')) return plain.slice(7)
  if (!plain.includes(':')) return plain
  const [head = '', tail] = plain.split('::')
  const leading = head ? head.split(':') : []
  const trailing = tail ? tail.split(':') : []
  const groups = [...leading, ...Array(Math.max(0, 8 - leading.length - trailing.length)).fill('0'), ...trailing]
  return groups.slice(0, 4).map(group => parseInt(group, 16).toString(16)).join(':') + '::/64'
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
