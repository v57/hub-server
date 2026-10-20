import type { BodyContext, Channel } from 'channel/server'
import { LazyState } from 'channel/more'
import type { Hub, State } from './hub'
import {
  DeviceRegistry,
  hostName,
  hostPlatform,
  loadDeviceKey,
  verifyCertificate,
  type PendingDevice,
  type StoredDevice,
} from './devices'
import { deviceId } from './devices'
import { deviceMember, keyMember, type Security } from './security'

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
  online: boolean
  network?: 'online' | 'offline'
  lastSeen: string
  capabilities?: Record<string, unknown>
  services: { key: string; instance: string; name?: string; online: boolean; paths: string[] }[]
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
  devicesState = new LazyState<Device[]>(() => this.list()).delay(0.1)
  pendingState = new LazyState<PendingDevice[]>(() => this.registry.pending())
  /** Hub Network removes the member of a removed or revoked device */
  onRemoved?: (removal: DeviceRemoval) => void
  /** Network presence of a device, from Hub Network */
  networkState?: (id: string) => 'online' | 'offline' | undefined

  constructor(
    private hub: Hub,
    private security: Security,
  ) {
    this.registry.onChange = () => this.setNeedsUpdate()
    security.deviceName = id => this.registry.device(id)?.name
  }

  /** Loads the registry and enrols the hub's own device, approved, with the hub key as its service */
  async load(hubKey: string | undefined) {
    await this.registry.load()
    // Lost tombstones would let revoked devices and keys back in
    if (this.registry.storage.corrupt) this.security.lockDown()
    try {
      const key = await loadDeviceKey()
      const id = deviceId(key)
      this.selfId = id
      const now = Math.floor(Date.now() / 1000)
      this.registry.seen(
        { device: key, deviceId: id, service: hubKey ?? '', instance: 'hub-pro', deviceName: hostName(), platform: hostPlatform(), iat: now, exp: now },
        true,
      )
      if (hubKey) this.registry.place({ device: key, deviceId: id, service: hubKey, instance: 'hub-pro', iat: now, exp: now })
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
    const device = this.registry.seen(certificate, approve)
    if (!device) {
      console.log('Ignored certificate of revoked device', id)
      return
    }
    state.certificate = certificate
    if (device.approved) this.attach(state)
    this.pendingState.setNeedsUpdate()
  }

  /** Makes a connection with a certificate from an approved device a device connection */
  private attach(state: State) {
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
  }

  /** Approves a pending device, also an owner's or a Hub Network joiner's, and attaches its open connections */
  approve(id: string): Device {
    this.registry.approve(id)
    for (const connection of this.connectionsOf(id)) this.attach(connection.state)
    this.hub.connectionsChanged()
    this.setNeedsUpdate()
    return this.describe(id)!
  }

  rename(id: string, name: unknown): Device {
    this.registry.rename(id, name)
    this.setNeedsUpdate()
    this.hub.connectionsChanged()
    return this.describe(id)!
  }

  /** Forgets a device that still works: it can enrol again, as pending (protocol.md section 8) */
  remove(id: string) {
    this.registry.remove(id)
    this.cleanUp(id, [])
    this.onRemoved?.({ id, revoked: false, revokedKeys: [] })
  }

  /** Revokes a lost device and the service keys on it, except `keepServices` (protocol.md section 8) */
  revoke(id: string, keepServices: unknown) {
    const keep = Array.isArray(keepServices) ? keepServices.filter(key => typeof key === 'string') : []
    const revokedKeys = this.registry.revoke(id, keep)
    this.cleanUp(id, revokedKeys)
    this.onRemoved?.({ id, revoked: true, revokedKeys })
  }

  /** Closes the device's connections and those of revoked keys, and drops their grants and group memberships */
  private cleanUp(id: string, revokedKeys: string[]) {
    const revoked = new Set(revokedKeys)
    for (const connection of this.hub.connections) {
      const { state } = connection
      if (state.certificate?.deviceId === id || (state.key && revoked.has(state.key))) connection.sender.stop()
    }
    this.security.members.removeEverywhere(deviceMember(id))
    for (const key of revokedKeys) {
      this.security.members.removeEverywhere(keyMember(key))
      this.security.revokeKey(key)
    }
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
      online: attached.length > 0 || id === this.selfId,
      ...(network ? { network } : {}),
      lastSeen: id === this.selfId ? new Date().toISOString() : device.lastSeen,
      capabilities: device.capabilities,
      services,
    }
  }

  register(channel: Channel<State>) {
    channel
      .stream('hub/devices', () => this.devicesState.makeIterator())
      .stream('hub/devices/pending', () => this.pendingState.makeIterator())
      .post('hub/device/approve', ({ body }) => this.approve(body?.id))
      .post('hub/device/rename', ({ body }) => this.rename(body?.id, body?.name))
      .post('hub/device/remove', ({ body }) => this.remove(body?.id))
      .post('hub/device/revoke', ({ body }) => this.revoke(body?.id, body?.keepServices))
  }
}
