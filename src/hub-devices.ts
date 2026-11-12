import type { BodyContext, Channel, Sender } from 'channel/server'
import { LazyStates } from 'channel/more'
import { FreshState } from './fresh-state'
import { createPublicKey, verify } from 'node:crypto'
import type { Hub, State } from './hub'
import {
  DeviceRegistry,
  RequestGate,
  hostName,
  hostPlatform,
  loadDeviceKey,
  maxPendingDevices,
  requestSource,
  verifyCertificate,
  type AttachRequest,
  type Certificate,
  type PendingDevice,
  type StoredDevice,
} from './devices'
import { deviceId } from './devices'
import type { Caller, Security } from './security'

/** A device as `hub/devices` lists it (protocol.md section 6) */
export interface Device {
  id: string
  key: string
  name: string
  platform?: string
  os?: string
  arch?: string
  parent?: string
  approved: boolean
  revoked: boolean
  /** An owner denied its request (`hub/device/deny`) */
  denied?: true
  online: boolean
  network?: 'online' | 'offline'
  overlay?: { address: string; authority: string }
  lastSeen: string
  capabilities?: Record<string, unknown>
  services: { key: string; instance: string; name?: string; online: boolean; paths: string[] }[]
  /** What the device's safety code covers: only for owners and the device itself */
  codeValue?: string
  /** The device that signed for it as its parent. `parent` above is only a name it declares. */
  attachedTo?: string
  /** Linked grants pass to it */
  linked?: boolean
}

/** `hub/device/request`: how a connection's device stands. No code before `codeValue` comes from the hub. */
export interface DeviceRequest {
  id: string
  status: 'waiting' | 'pending' | 'approved' | 'denied'
  name?: string
  codeValue?: string
  /** The parent that signed for it, once attached */
  attachedTo?: string
}

/** A request waiting for its turn, with the connection it came on */
interface WaitingRequest {
  deviceId: string
  certificate: Certificate
  state: State
}

/** What revoking or removing a device took away, for Hub Network */
export interface DeviceRemoval {
  id: string
  revoked: boolean
  revokedKeys: string[]
}

/**
 * Devices on the hub: certificates at connect, enrolment and approval, presence, and the device APIs. The registry
 * itself is `DeviceRegistry` in `data/devices.json`.
 */
export class HubDevices {
  registry = new DeviceRegistry()
  /** The device this hub runs on */
  selfId?: string
  /** Who a connection's `hub/devices` is for: a merged hub's connection is that hub, never an owner */
  private listCallers = new WeakMap<State, () => Caller>()
  /** `hub/devices` per caller: each sees what's shared with it (protocol.md section 13) */
  devicesState = new LazyStates<State, Device[]>(state => this.listFor(state)).dedupe('json')
  pendingState = new FreshState<PendingDevice[]>(() => this.registry.pending())
  /** `hub/device/request` per connection */
  requestState = new LazyStates<State, DeviceRequest>(state => this.request(state)).dedupe('json')
  /** `hub/device/attach/requests` per connection: an owner sees all, a parent those naming it */
  attachRequestsState = new LazyStates<State, AttachRequest[]>(state => this.attachRequestsFor(state)).dedupe('json')
  /** New requests, one a second */
  gate = new RequestGate<WaitingRequest>(request => this.admit(request))
  /** Hub Network removes the member of a removed or revoked device */
  onRemoved?: (removal: DeviceRemoval) => void
  /** Network presence of a device, from Hub Network */
  networkState?: (id: string) => 'online' | 'offline' | undefined
  /** Overlay address and DNS name of a device member, from Hub Network */
  overlay?: (id: string) => { address: string; authority: string } | undefined
  /** A device's reporter described it: Hub Network reopens links for its SSH port */
  onDescribed?: (id: string) => void
  /** Devices fronting a share this caller may open or offering it their internet, with the shares' ports, from Hub Network */
  sharedWith?: (state: State) => Map<string, Set<number>>
  /** Whether this caller may sign in to the SSH server of the hub's machine, from Hub Network */
  canUseHostSSH?: (state: State) => boolean
  /** The device of the hub's machine as Hub Network knows it, else the one the hub runs on */
  hostDevice: () => string | undefined = () => this.selfId
  /** Connections that asked for the reporter role, oldest first; the first attached one of a device reports */
  private reporterCandidates: State[] = []
  /** Latest live data per device, in memory only */
  private liveData = new Map<string, Record<string, unknown>>()
  /** `hub/devices/data` per connection and device, empty once the caller may not see it any more */
  private liveDataStreams = new Map<string, { id: string; caller: () => Caller }>()
  liveDataState = new LazyStates<string, Record<string, unknown>>(stream => {
    const entry = this.liveDataStreams.get(stream)
    if (!entry) return {}
    return this.seesLiveData(entry.caller(), entry.id) ? (this.liveData.get(entry.id) ?? {}) : {}
  }).dedupe('json')

  constructor(
    private hub: Hub,
    private security: Security,
  ) {
    this.registry.onChange = () => this.setNeedsUpdate()
    security.deviceName = id => this.registry.device(id)?.name
    security.isChild = id => this.registry.isChild(id)
  }

  /** Loads the registry and enrols the hub's own device, approved, with the hub key as its service */
  async load(hubKey: string | undefined) {
    this.registry.hubKey = hubKey ?? ''
    await this.registry.load()
    // Lost tombstones would let revoked devices and keys back in
    if (this.registry.storage.corrupt) this.security.lockDown()
    try {
      const key = await loadDeviceKey()
      const id = deviceId(key)
      this.selfId = id
      const now = Math.floor(Date.now() / 1000)
      this.registry.seen(
        { device: key, deviceId: id, service: hubKey ?? '', instance: 'hub-server', deviceName: hostName(), platform: hostPlatform(), iat: now, exp: now },
        true,
      )
      if (hubKey) this.registry.place({ device: key, deviceId: id, service: hubKey, instance: 'hub-server', iat: now, exp: now })
    } catch (error) {
      console.error('Hub device key unavailable, the hub has no device:', error)
    }
  }

  /** At connect: refuses revoked keys and keeps a valid certificate on the state, attaching it if approved */
  connect(state: State, headers: Record<string, string | undefined>) {
    if (!state.key) return
    if (this.registry.isKeyRevoked(state.key)) throw 'key revoked'
    const header = headers['device']
    if (!header) return
    const certificate = verifyCertificate(header, state.key, this.security.hubKey)
    if (typeof certificate === 'string') {
      console.log('Ignored device certificate of', state.key, certificate)
      return
    }
    const id = certificate.deviceId
    const approve =
      this.security.isOwner({ key: state.key }) ||
      this.security.isOwner({ device: id }) ||
      (!!this.security.launcher && state.key === this.security.launcher) ||
      id === this.selfId
    // A new request waits its turn; it holds nothing until then, and connects as a plain key
    if (!approve && !this.registry.device(id)) {
      state.certificate = certificate
      this.gate.ask(requestSource(state.ip), { deviceId: id, certificate, state })
      return
    }
    const device = this.registry.seen(certificate, approve)
    if (!device) {
      console.log('Ignored certificate of revoked device', id)
      return
    }
    state.certificate = certificate
    if (device.approved) this.placeOnDevice(state)
    this.pendingState.setNeedsUpdate()
  }

  /** A new request's turn: it joins the pending list, pushing out the oldest once that is full */
  private admit({ certificate, state }: WaitingRequest) {
    if (this.registry.device(certificate.deviceId)) return
    const pending = this.registry.pendingIds()
    const online = new Set(Array.from(this.hub.connections, connection => connection.state.certificate?.deviceId))
    while (pending.length >= maxPendingDevices) {
      const index = Math.max(0, pending.findIndex(id => !online.has(id)))
      const [oldest] = pending.splice(index, 1) as [string]
      this.registry.remove(oldest)
      // It asks again when it reconnects
      for (const connection of this.connectionsOf(oldest)) connection.sender.stop()
    }
    this.registry.seen(certificate, false)
    if (state.attachAsk) this.registry.askAttach(certificate.deviceId, state.attachAsk.parent)
    this.requestState.setNeedsUpdate()
  }

  /** Where a connection's device stands. A connection still without a place in line takes one. */
  private request(state: State): DeviceRequest {
    const certificate = state.certificate
    if (!certificate) throw 'no device certificate'
    const id = certificate.deviceId
    const device = this.registry.device(id)
    if (!device) {
      this.gate.ask(requestSource(state.ip), { deviceId: id, certificate, state })
      if (!this.registry.device(id)) return { id, status: 'waiting' }
      return this.request(state)
    }
    // A denied device hears so, with no code to compare
    if (device.denied) return { id, status: 'denied' }
    return {
      id,
      status: device.approved ? 'approved' : 'pending',
      name: device.name,
      codeValue: this.registry.codeValue(device),
      ...(device.attached ? { attachedTo: device.attached.parent } : {}),
    }
  }

  private attachRequestsFor(state: State): AttachRequest[] {
    const requests = this.registry.attachRequests()
    if (this.security.isOwner(state)) return requests
    return state.device ? requests.filter(request => request.parent === state.device) : []
  }

  /** `hub/device/attach/ask`: this connection's device asks to attach, to `parent` if it names one */
  askAttach(state: State, parent: unknown): DeviceRequest {
    const certificate = state.certificate
    if (!certificate) throw 'no device certificate'
    if (parent !== undefined && typeof parent !== 'string') throw 'invalid parent'
    const id = certificate.deviceId
    if (this.registry.device(id)) {
      this.registry.askAttach(id, parent)
    } else {
      // Its row comes at its turn, which keeps the question
      state.attachAsk = parent ? { parent } : {}
      this.gate.ask(requestSource(state.ip), { deviceId: id, certificate, state })
    }
    return this.request(state)
  }

  /**
   * `hub/device/attach` on the parent's own connection, with its signature. Only an owner's word also approves the child;
   * a member's device takes only a child that named it, and an owner still approves that child.
   */
  attach(state: State, sender: Sender, body: any): Device {
    const parent = state.device
    if (!parent || this.hub.merger.connectionFor(sender)) throw 'permissions required'
    const owner = this.hub.caller(state, sender).owner
    const id = body?.child
    const asked = typeof id === 'string' ? this.registry.device(id)?.attachAsk : undefined
    if (!owner && asked?.parent !== parent) throw 'permissions required'
    if (asked?.parent && asked.parent !== parent) throw 'named another parent'
    if (typeof id === 'string' && this.isOwnerDevice(id)) throw 'an owner can not be a child'
    this.registry.attach(id, parent, body?.at, body?.signature, owner)
    const child = id as string
    this.gate.forget(request => request.deviceId === child)
    if (this.registry.device(child)!.approved) for (const connection of this.connectionsOf(child)) this.placeOnDevice(connection.state)
    this.linksChanged()
    return this.describe(child)!
  }

  /** The device itself, or a key on it, in the owners group */
  private isOwnerDevice(id: string): boolean {
    return this.security.isStoredOwner({ device: id }) || this.registry.servicesOn(id).some(key => this.security.isStoredOwner({ key }))
  }

  /** `hub/device/detach`: an owner, or the parent on its own connection, ends a link */
  detach(state: State, sender: Sender, id: unknown): Device {
    const owner = this.hub.caller(state, sender).owner
    const parent = typeof id === 'string' ? this.registry.device(id)?.attached?.parent : undefined
    if (!owner && (!parent || parent !== state.device)) throw 'permissions required'
    this.registry.detach(id)
    this.linksChanged()
    return this.describe(id as string)!
  }

  /** `hub/device/link`: whether linked grants pass to this child */
  link(id: unknown, linked: unknown): Device {
    if (typeof linked !== 'boolean') throw 'invalid linked'
    this.registry.setLinked(id, linked)
    this.linksChanged()
    return this.describe(id as string)!
  }

  /** `hub/device/attach/dismiss`: an owner, or the parent it named */
  dismissAttach(state: State, sender: Sender, id: unknown) {
    const owner = this.hub.caller(state, sender).owner
    const named = typeof id === 'string' ? this.registry.device(id)?.attachAsk?.parent : undefined
    if (!owner && (!named || named !== state.device)) throw 'permissions required'
    this.registry.dismissAttach(id)
    this.setNeedsUpdate()
  }

  /** Links or approvals changed: the copies follow in one save, Hub Network closes what they took */
  private linksChanged() {
    this.security.grants.settleCopies()
    this.hub.connectionsChanged()
    this.setNeedsUpdate()
  }

  /** Makes a connection with a certificate from an approved device a device connection */
  private placeOnDevice(state: State) {
    const certificate = state.certificate
    if (!certificate) return
    state.device = certificate.deviceId
    state.instance = certificate.instance
    const moved = this.registry.place(certificate, state.name)
    if (moved) console.log('Service', certificate.service, 'moved from device', moved, 'to', certificate.deviceId)
  }

  setNeedsUpdate() {
    this.devicesState.setNeedsUpdate()
    this.pendingState.setNeedsUpdate()
    this.requestState.setNeedsUpdate()
    this.attachRequestsState.setNeedsUpdate()
    this.liveDataState.setNeedsUpdate()
  }

  /** Approves the device of a connection that proved itself otherwise (pairing, a Hub Network join), waiting or not */
  approveConnection(state: State) {
    const certificate = state.certificate
    if (!certificate) return
    if (!this.registry.device(certificate.deviceId)) this.registry.seen(certificate, false)
    this.approve(certificate.deviceId)
  }

  /** Approves a pending device, also an owner's or a Hub Network joiner's, and attaches its open connections */
  approve(id: string): Device {
    this.registry.approve(id)
    this.gate.forget(request => request.deviceId === id)
    for (const connection of this.connectionsOf(id)) this.placeOnDevice(connection.state)
    this.linksChanged()
    return this.describe(id)!
  }

  /** Denies a pending request. Its connections stay, as plain keys that hear "denied", so it doesn't come back as a new one. */
  deny(id: string) {
    this.registry.deny(id)
    this.gate.forget(request => request.deviceId === id)
  }

  rename(id: string, name: unknown): Device {
    this.registry.rename(id, name)
    this.setNeedsUpdate()
    this.hub.connectionsChanged()
    return this.describe(id)!
  }

  /**
   * Forgets a device that still works: it can enrol again, as pending (protocol.md section 8). Its children came in on its
   * word, so they go too and ask again.
   */
  remove(id: string) {
    const below = this.registry.below(id)
    for (const device of [id, ...below]) this.registry.remove(device)
    for (const device of [id, ...below]) {
      this.cleanUp(device, [])
      this.onRemoved?.({ id: device, revoked: false, revokedKeys: [] })
    }
  }

  /**
   * Revokes a lost device and the service keys on it, except `keepServices` (protocol.md section 8), and everything below
   * it. Revoking a child leaves its parent alone.
   */
  revoke(id: string, keepServices: unknown) {
    const keep = Array.isArray(keepServices) ? keepServices.filter(key => typeof key === 'string') : []
    const below = this.registry.below(id)
    const removals = [id, ...below].map(device => ({ id: device, revokedKeys: this.registry.revoke(device, device === id ? keep : []) }))
    for (const { id: device, revokedKeys } of removals) {
      this.cleanUp(device, revokedKeys)
      this.onRemoved?.({ id: device, revoked: true, revokedKeys })
    }
  }

  /** Closes the device's connections and those of revoked keys, and drops their grants and group memberships */
  private cleanUp(id: string, revokedKeys: string[]) {
    this.liveData.delete(id)
    const revoked = new Set(revokedKeys)
    for (const connection of this.hub.connections) {
      const { state } = connection
      if (state.certificate?.deviceId === id || (state.key && revoked.has(state.key))) connection.sender.stop()
    }
    this.security.removeDevice(id)
    for (const key of revokedKeys) this.security.revokeKey(key)
    this.setNeedsUpdate()
    this.hub.connectionsChanged()
  }

  private connectionsOf(id: string): BodyContext<State>[] {
    return Array.from(this.hub.connections).filter(connection => connection.state.certificate?.deviceId === id)
  }

  describe(id: string): Device | undefined {
    const device = this.registry.device(id)
    if (!device) return
    return this.encode(id, device)
  }

  list(): Device[] {
    return Object.entries(this.registry.data.devices).map(([id, device]) => this.encode(id, device))
  }

  /** Owners and those an owner granted `hub/devices` itself see every device */
  private seesEverything(caller: Caller): boolean {
    return caller.owner || (!this.security.lockdown && this.security.granted(caller, 'hub/devices'))
  }

  /**
   * A caller's own devices: the one it's attached to, the one its key runs on, and those of a person group it's in
   * (protocol.md section 13).
   */
  private ownDevices(caller: Caller): Set<string> {
    const own = new Set<string>()
    const placed = (key: string | undefined) => key && this.registry.data.services[key]?.device
    if (caller.device) own.add(caller.device.id)
    if (caller.key && placed(caller.key)) own.add(placed(caller.key) as string)
    for (const group of caller.groups) {
      if (!this.security.group.isPerson(group)) continue
      for (const member of this.security.members.members(group)) {
        if (member.startsWith('device:')) own.add(member.slice('device:'.length))
        else if (placed(member.slice('key:'.length))) own.add(placed(member.slice('key:'.length)) as string)
      }
    }
    return own
  }

  /** `hub/devices` for one connection */
  private listFor(state: State): Device[] {
    const caller = this.listCallers.get(state)?.() ?? this.security.caller(state)
    const everything = this.seesEverything(caller)
    const own = everything ? new Set<string>() : this.ownDevices(caller)
    const shared = everything ? new Map<string, Set<number>>() : (this.sharedWith?.(state) ?? new Map<string, Set<number>>())
    const hostSSH = !everything && !!this.canUseHostSSH?.(state)
    return Object.entries(this.registry.data.devices).flatMap(([id, device]) => {
      if (everything) return [{ ...this.encode(id, device), codeValue: this.registry.codeValue(device) }]
      if (!device.approved || device.revoked) return []
      if (own.has(id)) return [{ ...this.encode(id, device), codeValue: this.registry.codeValue(device) }]
      const entry = this.encodeShared(id, device, caller, shared.get(id), hostSSH && id === this.hostDevice())
      return entry ? [entry] : []
    })
  }

  /**
   * A device someone else runs, as a member sees it: its identity and how to reach it, the services it may call, and its
   * SSH details only where it may use them. Undefined while nothing on it is shared with the caller.
   */
  private encodeShared(id: string, device: StoredDevice, caller: Caller, ports: Set<number> | undefined, hostSSH: boolean): Device | undefined {
    const full = this.encode(id, device)
    const services = full.services.flatMap(service => {
      const paths = service.paths.filter(path => this.security.granted(caller, path))
      return paths.length ? [{ ...service, paths }] : []
    })
    if (!ports && !services.length && !hostSSH) return
    const ssh = device.capabilities?.ssh as { port?: number } | undefined
    const seesSSH = !!ssh && (hostSSH || (ssh.port !== undefined && !!ports?.has(ssh.port)))
    const { os: _os, arch: _arch, parent: _parent, capabilities: _capabilities, attachedTo: _attachedTo, linked: _linked, ...visible } = full
    return { ...visible, services, ...(seesSSH ? { capabilities: { ssh } } : {}) }
  }

  /** Live data stays with the device's own person, and owners */
  private seesLiveData(caller: Caller, id: string): boolean {
    return !!this.registry.device(id) && (this.seesEverything(caller) || this.ownDevices(caller).has(id))
  }

  private encode(id: string, device: StoredDevice): Device {
    const attached = Array.from(this.hub.connections, c => c.state).filter(state => state.device === id)
    const services = Object.entries(this.registry.data.services)
      .filter(([, service]) => service.device === id)
      .map(([key, service]) => {
        const states = attached.filter(state => state.key === key)
        const paths = new Set(states.flatMap(state => Array.from(state.services)))
        return { key, instance: service.instance, name: service.name, online: states.length > 0, paths: Array.from(paths) }
      })
    const network = this.networkState?.(id)
    const overlay = this.overlay?.(id)
    return {
      id,
      key: device.key,
      name: device.name,
      platform: device.platform,
      os: device.os,
      arch: device.arch,
      parent: device.parent,
      approved: device.approved,
      revoked: !!device.revoked,
      ...(device.denied ? { denied: true as const } : {}),
      online: attached.length > 0 || id === this.selfId,
      ...(network ? { network } : {}),
      ...(overlay ? { overlay } : {}),
      lastSeen: id === this.selfId ? new Date().toISOString() : device.lastSeen,
      capabilities: device.capabilities,
      services,
      ...(device.attached ? { attachedTo: device.attached.parent, linked: device.attached.linked === true } : {}),
    }
  }

  /** `hub/service/update` with `reporter: true` */
  requestReporter(state: State) {
    if (!this.reporterCandidates.includes(state)) this.reporterCandidates.push(state)
  }
  disconnected(state: State) {
    const index = this.reporterCandidates.indexOf(state)
    if (index >= 0) this.reporterCandidates.splice(index, 1)
    this.gate.forget(request => request.state === state)
    for (const stream of this.liveDataStreams.keys()) {
      if (stream.startsWith(`${state.id}\n`)) this.liveDataStreams.delete(stream)
    }
    // Another connection of the same device takes its place in line
    this.requestState.setNeedsUpdate()
  }
  /** The connection that reports for a device: the first connected candidate attached to it */
  reporter(id: string): State | undefined {
    return this.reporterCandidates.find(state => state.device === id)
  }
  private requireReporter(state: State): string {
    const id = state.device
    if (!id || this.reporter(id) !== state) throw 'not the device reporter'
    return id
  }

  /** `hub/device/describe` from the reporter: its name suggestion, OS, architecture and capabilities */
  describeSelf(state: State, body: unknown) {
    const id = this.requireReporter(state)
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw 'invalid description'
    const { name, os, arch, capabilities } = body as Record<string, unknown>
    const text = (value: unknown, max: number) =>
      value === undefined || (typeof value === 'string' && Buffer.byteLength(value) <= max)
    if (!text(name, 64) || !text(os, 64) || !text(arch, 32)) throw 'invalid description'
    if (capabilities !== undefined) {
      if (!capabilities || typeof capabilities !== 'object' || Array.isArray(capabilities)) throw 'invalid capabilities'
      if (JSON.stringify(capabilities).length > 65536) throw 'capabilities too large'
      this.checkSSH(id, (capabilities as Record<string, any>).ssh)
    }
    this.registry.update(id, {
      name: name as string | undefined,
      os: os as string | undefined,
      arch: arch as string | undefined,
      capabilities: capabilities as Record<string, unknown> | undefined,
    })
    this.onDescribed?.(id)
  }

  /** `ssh.hostKey` and every `ssh.hostKeys` entry must carry the device's signature over `ssh1:<hostKey>` */
  private checkSSH(id: string, ssh: any) {
    if (ssh === undefined) return
    const device = this.registry.device(id)!
    if (!ssh || !Number.isInteger(ssh.port) || (ssh.hostKeys !== undefined && !Array.isArray(ssh.hostKeys))) {
      throw 'invalid ssh capability'
    }
    const key = createPublicKey({ key: Buffer.from(device.key, 'base64'), format: 'der', type: 'spki' })
    for (const entry of [ssh, ...(ssh.hostKeys ?? [])]) {
      if (typeof entry?.hostKey !== 'string' || typeof entry.hostKeySignature !== 'string') throw 'invalid ssh capability'
      if (!verify(null, Buffer.from(`ssh1:${entry.hostKey}`), key, Buffer.from(entry.hostKeySignature, 'base64'))) {
        throw 'invalid ssh host key signature'
      }
    }
  }

  /** `hub/device/data` from the reporter: live CPU, memory, battery and so on, kept in memory */
  reportData(state: State, body: unknown) {
    const id = this.requireReporter(state)
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw 'invalid data'
    if (JSON.stringify(body).length > 16384) throw 'data too large'
    this.liveData.set(id, body as Record<string, unknown>)
    for (const [stream, entry] of this.liveDataStreams) {
      if (entry.id === id) this.liveDataState.setNeedsUpdate(stream)
    }
  }

  register(channel: Channel<State>) {
    channel
      .post('hub/device/describe', ({ body, state }) => this.describeSelf(state, body))
      .post('hub/device/data', ({ body, state }) => this.reportData(state, body))
      .stream('hub/devices/data', ({ body, state, sender, context }) => {
        const id = body?.id
        const caller = () => this.hub.caller(state, sender, context)
        // The same answer for a device that's hidden as for one that doesn't exist
        if (typeof id !== 'string' || !this.seesLiveData(caller(), id)) throw 'device not found'
        const stream = `${state.id}\n${id}`
        this.liveDataStreams.set(stream, { id, caller })
        return this.liveDataState.makeIterator(stream)
      })
      .stream('hub/device/request', ({ state }) => {
        if (!state.certificate) throw 'no device certificate'
        return this.requestState.makeIterator(state)
      })
      .post('hub/device/attach/ask', ({ body, state }) => this.askAttach(state, body?.parent))
      .stream('hub/device/attach/requests', ({ state }) => this.attachRequestsState.makeIterator(state))
      .post('hub/device/attach', ({ body, state, sender }) => this.attach(state, sender, body))
      .post('hub/device/attach/dismiss', ({ body, state, sender }) => this.dismissAttach(state, sender, body?.id))
      .post('hub/device/detach', ({ body, state, sender }) => this.detach(state, sender, body?.id))
      .post('hub/device/link', ({ body }) => this.link(body?.id, body?.linked))
    channel
      .stream('hub/devices', ({ state, sender, context }) => {
        this.listCallers.set(state, () => this.hub.caller(state, sender, context))
        this.devicesState.state(state).delay(0.1)
        return this.devicesState.makeIterator(state)
      })
      .stream('hub/devices/pending', () => this.pendingState.makeIterator())
      .post('hub/device/approve', ({ body }) => this.approve(body?.id))
      .post('hub/device/deny', ({ body }) => this.deny(body?.id))
      .post('hub/device/rename', ({ body }) => this.rename(body?.id, body?.name))
      .post('hub/device/remove', ({ body }) => this.remove(body?.id))
      .post('hub/device/revoke', ({ body }) => this.revoke(body?.id, body?.keepServices))
  }
}
