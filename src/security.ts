import { ObjectMap } from 'channel/channel'
import { createPublicKey, verify } from 'crypto'
import { Storage, settings, type SecurityMode } from './settings'
import { deviceId } from './devices'
import { LazyState } from 'channel/more'

interface SecurityInterface {
  requireOwner(user: Caller | Principal | string | undefined, path: string): void
  addOwner(user: string): void
  allowsCall(caller: Caller | Principal | string | undefined, path: string, isPublic?: boolean): boolean
  allowsHost(user: Principal | string | undefined, path: string): boolean

  // Keys
  keys: {
    verify(signedKey: string | undefined, whitelist: Whitelist, options?: TokenOptions): string | undefined
  }

  // Create api
  host: {
    allows(user: string, path: string): boolean
    ask(user: string, path: string): void
    allow(user: string, paths: string[] | undefined): void
    revoke(user: string, paths: string[] | undefined): void
    allowed(user: string): Set<string>
    pending(user: string): Set<string>
    pendingUsers(): string[]
  }

  // Call api
  call: {
    allows(user: string, path: string): boolean
    ask(user: string, path: string): void
    allow(user: string, paths: string[]): void
    allowed(user: string): Set<string>
    pending(user: string): Set<string>
  }

  // Groups
  group: {
    allowsUser(user: string, path: string): boolean
    restricted(user: string | undefined): Set<string>

    allows(group: string, path: string): boolean
    create(group: string): void
    remove(group: string): void
    rename(group: string, name: string): void
    update(group: string, add: string[], remove: string[]): void
    replace(group: string, paths: string[]): void
    allowed(group: string): Set<string>

    // User groups
    users: {
      group(user: string): string | undefined
      users(group: string): Set<string>
      add(user: string, group: string): void
      remove(user: string, group: string): void
      rename(oldValue: string, group: string): void
    }

    // Path names
    names: {
      add(path: string, name: string): void
      remove(path: string): void
      contains(path: string): boolean
      list(): { path: string; name: string }[]
    }
  }
  whitelist: {
    enabled: boolean
    add(user: string): void
    remove(user: string): void
    allows(user: string): boolean
    setEnabled(enabled: boolean | undefined): void
  }
}

const hubApi = {
  'hub/merge/add': 'Hub: Merge Hubs',
  'hub/merge/remove': 'Hub: Merge Hubs',
  'hub/key': 'Hub: Merge Hubs',
  'hub/proxy/add': 'Hub: Add Proxy Hubs',
  'hub/proxy/remove': 'Hub: Add Proxy Hubs',
  'hub/balancer/set': 'Hub: Manage Load Balancer',
  'hub/balancer/limit': 'Hub: Manage Load Balancer',
  'hub/whitelist': 'Hub: Whitelist mode',
  'hub/host/update': 'Hub: Manage Permissions',
  'hub/host/pending': 'Hub: Manage Permissions',
  'hub/host/allowed': 'Hub: Manage Permissions',
  'hub/call/update': 'Hub: Manage Permissions',
  'hub/call/pending': 'Hub: Manage Permissions',
  'hub/call/allowed': 'Hub: Manage Permissions',
  'hub/group/create': 'Hub: Manage Permissions',
  'hub/group/rename': 'Hub: Manage Permissions',
  'hub/group/remove': 'Hub: Manage Permissions',
  'hub/group/update': 'Hub: Manage Permissions',
  'hub/group/update/users': 'Hub: Manage Permissions',
}

export const ownerApi = new Set(Object.keys(hubApi))

/** Who may call a built-in API (protocol.md section 7) */
export type BuiltinAccess = 'public' | 'auth' | 'reporter' | 'grant' | 'owner' | 'own'

const publicBuiltins = new Set([
  'hub/info',
  'hub/profile/update',
  'hub/service/update',
  'hub/api',
  'hub/status',
  'hub/status/badges',
  'hub/proxy/join',
  'hub/header',
])
// `hub/net/bind` keeps the proof of its bind kind, `hub/net/node` tells agents where their node is
const authBuiltins = new Set(['hub/api/services', 'hub/net/bind', 'hub/net/node'])
const reporterBuiltins = new Set(['hub/device/describe', 'hub/device/data'])
const grantBuiltins = new Set(['hub/devices', 'hub/devices/data'])

/** Access of a built-in path, undefined for service paths. `own`: `network/*` checks its callers itself. */
export function builtinAccess(path: string): BuiltinAccess | undefined {
  if (path === 'network' || path.startsWith('network/')) return 'own'
  if (path !== 'hub' && !path.startsWith('hub/')) return
  if (publicBuiltins.has(path)) return 'public'
  if (authBuiltins.has(path)) return 'auth'
  if (reporterBuiltins.has(path)) return 'reporter'
  if (grantBuiltins.has(path)) return 'grant'
  return 'owner'
}

/** The caller as services see it in `context.hub.caller` */
export interface Caller {
  key?: string
  device?: { id: string; name: string }
  groups: string[]
  owner: boolean
  /** Key of the hub a merged request came through */
  via?: string
  /** The caller that hub reported, unverified */
  claimed?: unknown
}

export const ownersGroup = 'owners'

/** A connection's identity: its key and, when device-attached, its device id */
export interface Principal {
  key?: string
  device?: string
}
type Who = Caller | Principal | string | undefined

/** Group members are `key:<SPKI>` or `device:<id>` */
export const keyMember = (key: string) => `key:${key}`
export const deviceMember = (id: string) => `device:${id}`

/**
 * `data/group-members.json`: members of stored groups. Holds the built-in `owners` group, which `--owner` and
 * `HUBOWNER` add to.
 */
class Members {
  private groups = new Map<string, Set<string>>()
  subscription = new LazyState<Record<string, string[]>>(() => this.encodeGroups())
  storage = new Storage(
    'data/group-members.json',
    () => ({ schema: 1, groups: this.encodeGroups() }),
    data => {
      if (!data || typeof data !== 'object' || data.schema !== 1) throw new Error('unsupported group members file')
      this.groups = new Map(Object.entries(data.groups ?? {}).map(([group, members]) => [group, new Set(members as string[])]))
    },
  )
  private encodeGroups(): Record<string, string[]> {
    return Object.fromEntries(Array.from(this.groups, ([group, members]) => [group, Array.from(members)]))
  }
  has(group: string, member: string): boolean {
    return this.groups.get(group)?.has(member) ?? false
  }
  members(group: string): Set<string> {
    return this.groups.get(group) ?? new Set()
  }
  /** Groups the principal is in, by key or by device */
  groupsOf(principal: Principal): string[] {
    const key = principal.key ? keyMember(principal.key) : undefined
    const device = principal.device ? deviceMember(principal.device) : undefined
    const result: string[] = []
    for (const [group, members] of this.groups) {
      if ((key && members.has(key)) || (device && members.has(device))) result.push(group)
    }
    return result
  }
  add(group: string, member: string) {
    let members = this.groups.get(group)
    if (!members) this.groups.set(group, (members = new Set()))
    if (members.has(member)) return
    members.add(member)
    this.changed()
  }
  remove(group: string, member: string) {
    if (!this.groups.get(group)?.delete(member)) return
    this.changed()
  }
  /** Takes the member out of every group */
  removeEverywhere(member: string) {
    let changed = false
    for (const members of this.groups.values()) changed = members.delete(member) || changed
    if (changed) this.changed()
  }
  private changed() {
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
}

export class Security implements SecurityInterface {
  keys = new Keys()
  host = new Host()
  call = new Call()
  group = new Group()
  members = new Members()
  launcher?: string
  whitelist = new Whitelist(user => this.isOwner(user))
  /** Device names for `caller.device`, set by the hub */
  deviceName?: (id: string) => string | undefined
  /** This hub's own key, which v1 tokens are bound to */
  hubKey?: string
  mode: SecurityMode = 'default-allow'
  requireV1 = false
  /** A store that grants failed to load: only owners may call service paths until an owner sets the mode */
  lockdown = false

  async load() {
    await Promise.all([
      this.host.storage.load(),
      this.call.storage.load(),
      this.group.storage.load(),
      this.group.names.storage.load(),
      this.group.users.storage.load(),
      this.whitelist.storage.load(),
      this.members.storage.load(),
    ])
    this.mode = settings.data.security.mode
    this.requireV1 = settings.data.security.requireV1
    // An empty path list or whitelist opens the hub, so a corrupt one locks it down instead
    // An empty owners group keeps owners out, so a corrupt one also locks down until the startup owners return
    const stores = [settings.storage, this.group.names.storage, this.whitelist.storage, this.members.storage]
    if (stores.some(storage => storage.corrupt)) this.lockDown()
    return this
  }
  /** Only owners may call service paths, and the hub stays `default-deny` after a restart */
  lockDown() {
    this.lockdown = true
    this.setMode({ mode: 'default-deny' }, false)
  }
  /** `default-deny` while locked down */
  get effectiveMode(): SecurityMode {
    return this.lockdown ? 'default-deny' : this.mode
  }
  /** Changes and stores the mode. An owner setting it ends a lockdown. */
  setMode(update: { mode?: SecurityMode; requireV1?: boolean }, endsLockdown = true) {
    if (update.mode !== undefined && update.mode !== 'default-allow' && update.mode !== 'default-deny') throw 'invalid mode'
    if (update.requireV1 !== undefined && typeof update.requireV1 !== 'boolean') throw 'invalid requireV1'
    if (update.mode) this.mode = update.mode
    if (update.requireV1 !== undefined) this.requireV1 = update.requireV1
    if (endsLockdown) this.lockdown = false
    settings.setSecurity({ mode: this.mode, requireV1: this.requireV1 })
  }
  requireOwner(who: Who, path: string): void {
    if (!this.isOwner(who)) throw 'Permissions required'
  }
  /** Adds a service or device SPKI to the stored `owners` group */
  addOwner(key: string): void {
    this.members.add(ownersGroup, keyMember(key))
    this.members.add(ownersGroup, deviceMember(deviceId(key)))
  }
  /** Caller of a connection, no key for anonymous ones and a device only when device-attached */
  caller(who: Principal | string | undefined): Caller {
    const principal = typeof who === 'string' ? { key: who } : (who ?? {})
    const groups = this.groups(principal)
    const name = principal.device ? (this.deviceName?.(principal.device) ?? principal.device) : undefined
    return {
      ...(principal.key ? { key: principal.key } : {}),
      ...(principal.device ? { device: { id: principal.device, name: name! } } : {}),
      groups,
      owner: groups.includes(ownersGroup),
    }
  }
  private asCaller(who: Who): Caller {
    if (who && typeof who === 'object' && Array.isArray((who as Caller).groups)) return who as Caller
    return this.caller(who as Principal | string | undefined)
  }
  /** Every group the key or its device belongs to, `owners` first */
  groups(principal: Principal): string[] {
    const groups = this.members.groupsOf(principal)
    const group = principal.key ? this.group.users.group(principal.key) : undefined
    if (group && !groups.includes(group)) groups.push(group)
    return groups.sort((a, b) => (a === ownersGroup ? -1 : b === ownersGroup ? 1 : 0))
  }
  /**
   * A call to a service path. Owners always; then grants (per-key call lists and group path lists); then in
   * `default-deny` only paths the providing service marked public, in `default-allow` every path no group restricts.
   */
  allowsCall(caller: Who, path: string, isPublic = false): boolean {
    const c = this.asCaller(caller)
    if (c.owner) return true
    if (this.lockdown) return false
    if (this.granted(c, path)) return true
    if (this.mode === 'default-deny') return isPublic
    return !this.group.names.contains(path)
  }
  /** Whether a grant (per-key call list or a group's path list) names this path for the caller */
  granted(caller: Caller, path: string): boolean {
    if (caller.key && this.call.allows(caller.key, path)) return true
    return caller.groups.some(group => this.group.lists(group, path))
  }
  /** Access check for a built-in path, throws `permissions required` */
  checkBuiltin(caller: Caller, path: string, access = builtinAccess(path)) {
    switch (access) {
      case undefined:
      case 'own':
      case 'public':
      // Handlers check that the caller is its device's reporter
      case 'reporter':
        return
      case 'auth':
        if (!caller.key) throw 'unauthorized'
        return
      case 'grant':
        if (caller.owner || (!this.lockdown && this.granted(caller, path))) return
        throw 'permissions required'
      case 'owner':
        if (caller.owner) return
        throw 'permissions required'
    }
  }
  allowsBuiltin(caller: Caller, path: string): boolean {
    try {
      this.checkBuiltin(caller, path)
      return true
    } catch {
      return false
    }
  }
  allowsHost(who: Principal | string | undefined, path: string): boolean {
    const principal = typeof who === 'string' ? { key: who } : (who ?? {})
    const user = principal.key
    if (!user) return false
    if (path.startsWith('hub/')) return false
    if (this.launcher && path.startsWith('launcher/') && user === this.launcher) return true
    if (this.isOwner(principal)) return true
    if (this.host.allows(user, path)) return true
    this.host.ask(user, path)
    return false
  }
  /** The paths of `api` this caller may call, for `hub/api` */
  allowedApi(caller: Who, api: Set<string>, isPublic: (path: string) => boolean = () => false): string[] {
    const c = this.asCaller(caller)
    return Array.from(api).filter(path =>
      builtinAccess(path) ? this.allowsBuiltin(c, path) : this.allowsCall(c, path, isPublic(path)),
    )
  }
  userGroup(user: string | undefined): string | undefined {
    if (!user) return
    return this.group.users.group(user)
  }
  /** Drops what a revoked key was granted: call and host lists and its group */
  revokeKey(key: string) {
    this.call.revoke(key, Array.from(this.call.allowed(key)))
    this.call.pendingList.deleteAll(key)
    this.host.revoke(key, Array.from(this.host.allowed(key)))
    this.host.pendingList.deleteAll(key)
    const group = this.group.users.group(key)
    if (group) this.group.users.remove(key, group)
  }
  /** A member of `owners` by key, or by the device the connection is attached to */
  isOwner(who: Who): boolean {
    if (!who) return false
    if (typeof who === 'string') return this.members.has(ownersGroup, keyMember(who))
    if (Array.isArray((who as Caller).groups)) return (who as Caller).owner
    const principal = who as Principal
    return (
      (!!principal.key && this.members.has(ownersGroup, keyMember(principal.key))) ||
      (!!principal.device && this.members.has(ownersGroup, deviceMember(principal.device)))
    )
  }
  registerProtectedApis(apis: Record<string, string>): void {
    for (const [path, name] of Object.entries(apis)) {
      ownerApi.add(path)
      this.group.names.register(path, name)
    }
  }
}

// Longest auth token lifetime the hub accepts, in seconds
export const authMaxLifetime = 5 * 60
// Tolerated clock difference between signer and hub, in seconds
export const authClockSkew = 30

export interface TokenOptions {
  /** The `v` header: missing or "0" signs the expiry, "1" signs `hub1:<hub key>:<expiry>` */
  version?: string
  hubKey?: string
  requireV1?: boolean
}

class Keys {
  verify(signedKey: string | undefined, whitelist: Whitelist, options: TokenOptions = {}): string | undefined {
    const version = options.version ?? '0'
    if (version !== '0' && version !== '1') throw 'unsupported version'
    if (!signedKey?.length) {
      if (whitelist.enforced) throw 'hub is not available'
      else return
    }
    if (version === '0' && options.requireV1) throw 'unsupported version'
    const parts = signedKey.split('.')
    if (parts.length !== 4 || parts[0] !== 'key') throw 'invalid key'
    const [_, key, hash, time] = parts
    if (whitelist.enforced && !whitelist.allows(key)) throw 'hub is not available'
    if (version === '1' && !options.hubKey) throw 'unsupported version'
    const signed = version === '1' ? `hub1:${options.hubKey}:${time}` : time
    if (!this.verifyPub(key, hash, time, signed)) throw 'invalid signature'
    return key
  }
  // Can handle around 38k verifications per second
  private verifyPub(key: string, signature: string, time: string, signed: string): boolean {
    // Signers write the expiry as decimal Unix seconds (now + 10 by default, 60 in Swift)
    if (!/^\d{1,12}$/.test(time)) throw 'invalid key'
    const expiry = Number(time)
    const now = Math.round(Date.now() / 1000)
    if (expiry + authClockSkew <= now) throw 'authorization expired'
    if (expiry > now + authMaxLifetime + authClockSkew) throw 'authorization expires too late'
    const pubKey = createPublicKey({ key: Buffer.from(key, 'base64'), format: 'der', type: 'spki' })
    const verified = verify(null, Buffer.from(signed), pubKey, Buffer.from(signature, 'base64'))
    return verified
  }
}

class Host {
  allowedList = new MapSet<string>()
  pendingList = new MapSet<string>()
  pendingSubscription = new LazyState(() => this.pendingList.encode())
  storage = new Storage(
    'data/services.json',
    () => ({
      allowed: this.allowedList.encode(),
    }),
    data => {
      this.allowedList.decode(data?.allowed)
    },
  )
  allows(user: string, path: string): boolean {
    return this.allowedList.has(user, path)
  }
  ask(user: string, path: string): void {
    this.pendingList.set(user, path)
    this.pendingSubscription.setNeedsUpdate()
  }
  allow(user: string, paths: string[] | undefined): void {
    if (!paths?.length) return
    for (const path of paths) {
      this.pendingList.delete(user, path)
      this.allowedList.set(user, path)
    }
    this.pendingSubscription.setNeedsUpdate()
    this.storage.save()
  }
  revoke(user: string, paths: string[] | undefined): void {
    if (!paths?.length) return
    for (const path of paths) {
      this.pendingList.set(user, path)
      this.allowedList.delete(user, path)
    }
    this.pendingSubscription.setNeedsUpdate()
    this.storage.save()
  }
  allowed(user: string): Set<string> {
    return this.allowedList.get(user) ?? new Set()
  }
  pending(user: string): Set<string> {
    return this.pendingList.get(user) ?? new Set()
  }
  pendingUsers(): string[] {
    return this.pendingList.keys()
  }
}

class Call {
  allowedList = new MapSet<string>()
  pendingList = new MapSet<string>()
  pendingSubscription = new LazyState(() => this.pendingList.encode())
  storage = new Storage(
    'data/clients.json',
    () => ({
      allowed: this.allowedList.encode(),
    }),
    data => this.allowedList.decode(data?.allowed),
  )
  allows(user: string, path: string): boolean {
    return this.allowedList.has(user, path)
  }
  ask(user: string, path: string): void {
    this.pendingList.set(user, path)
    this.pendingSubscription.setNeedsUpdate()
  }
  allow(user: string, paths: string[] | undefined): void {
    if (!paths?.length) return
    for (const path of paths) {
      this.pendingList.delete(user, path)
      this.pendingSubscription.setNeedsUpdate()
      this.allowedList.set(user, path)
    }
    this.storage.save()
  }
  revoke(user: string, paths: string[] | undefined): void {
    if (!paths?.length) return
    for (const path of paths) {
      this.pendingList.set(user, path)
      this.pendingSubscription.setNeedsUpdate()
      this.allowedList.delete(user, path)
    }
    this.storage.save()
  }
  allowed(user: string): Set<string> {
    return this.allowedList.get(user) ?? new Set()
  }
  pending(user: string): Set<string> {
    return this.pendingList.get(user) ?? new Set()
  }
}

class Group {
  private groups = new MapSet<string>()
  users = new GroupUsers()
  names = new GroupNames()
  storage = new Storage(
    'data/groups.json',
    () => this.groups.encode(),
    data => this.groups.decode(data),
  )
  subscription = new LazyState<any>(() => {
    return this.groups.encode()
  })
  allowsUser(user: string | undefined, path: string): boolean {
    if (!this.names.contains(path)) return true
    if (!user) return false
    const group = this.users.group(user)
    if (!group) return false
    return this.allows(group, path)
  }
  restricted(user: string | undefined): Set<string> {
    let restricted = this.names.restricted
    if (!user) return restricted
    const group = this.users.group(user)
    if (!group) return restricted
    return restricted.difference(this.allowed(group))
  }
  allows(group: string, path: string): boolean {
    if (!this.names.contains(path)) return true
    return this.groups.has(group, path)
  }
  /** Whether the group's path list names the path */
  lists(group: string, path: string): boolean {
    return this.groups.has(group, path)
  }
  create(group: string): void {
    if (!this.groups.hasKey(group)) {
      this.groups.replace(group, new Set())
      this.subscription.setNeedsUpdate()
      this.storage.save()
    }
  }
  remove(group: string): void {
    const removed = this.groups.deleteAll(group)
    this.users.removeGroup(group)
    if (removed) {
      this.subscription.setNeedsUpdate()
      this.storage.save()
    }
  }
  rename(group: string, name: string): void {
    this.users.rename(group, name)
    const paths = this.groups.move(group, name)
    if (!paths) return
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  update(group: string, add: string[], remove: string[]): void {
    const paths = this.groups.get(group)
    if (!paths) return
    add.forEach(path => paths.add(path))
    remove.forEach(path => paths.delete(path))
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  replace(group: string, paths: string[]): void {
    this.groups.replace(group, new Set(paths))
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  allowed(group: string): Set<string> {
    return this.groups.get(group) ?? new Set<string>()
  }
}

class GroupUsers {
  private groupUsers = new MapSet<string>()
  private userGroups = new ObjectMap<string, string>()
  storage = new Storage(
    'data/group_users.json',
    () => this.groupUsers.encode(),
    data => {
      this.groupUsers.decode(data)
      this.groupUsers.forEach((group, users) => {
        users.forEach((user: string) => this.userGroups.set(user, group))
      })
    },
  )
  subscription = new LazyState<any>(() => this.groupUsers.encode())
  group(user: string): string | undefined {
    return this.userGroups.get(user)
  }
  users(group: string): Set<string> {
    return this.groupUsers.get(group)
  }
  edit(group: string, add: string[] | undefined, remove: string[] | undefined) {
    add?.forEach(user => this.add(user, group))
    remove?.forEach(user => this.remove(user, group))
  }
  add(user: string, group: string): void {
    const oldValue = this.userGroups.get(user)
    if (oldValue === group) return
    if (oldValue) this.groupUsers.delete(oldValue, user)
    this.groupUsers.set(group, user)
    this.userGroups.set(user, group)
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  remove(user: string, group: string): void {
    this.userGroups.delete(user)
    this.groupUsers.delete(group, user)
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  removeGroup(group: string) {
    const set = this.groupUsers.get(group)
    if (!set.size) return
    set.forEach(user => this.userGroups.delete(user))
    this.groupUsers.deleteAll(group)
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  rename(oldValue: string, group: string): void {
    const users = this.groupUsers.move(oldValue, group)
    if (!users) return
    users.forEach(user => this.userGroups.set(user, group))
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
}

class GroupNames {
  names = new ObjectMap<string, string>()
  private paths = new MapSet<string>()
  restricted = new Set<string>()
  storage = new Storage(
    'data/paths.json',
    () => this.names.storage,
    data => {
      this.names.storage = data
      this.paths = new MapSet<string>()
      this.restricted = new Set()
      this.setHubApi()
      Object.entries(data).forEach(([path, name]) => {
        this.restricted.add(path)
        this.paths.set(name as string, path)
      })
    },
  )
  subscription = new LazyState<any>(() => this.names.storage)
  constructor() {
    this.setHubApi()
  }
  private setHubApi() {
    Object.entries(hubApi).forEach(([path, name]) => {
      this.names.storage[path] = name
      this.restricted.add(path)
      this.paths.set(name, path)
    })
  }
  register(path: string, name: string): void {
    const oldName = this.names.get(path)
    if (oldName === name && this.restricted.has(path)) return
    if (oldName) this.paths.delete(oldName, path)
    this.names.set(path, name)
    this.paths.set(name, path)
    this.restricted.add(path)
    this.subscription.setNeedsUpdate()
  }
  add(path: string, name: string): void {
    const oldName = this.names.get(path)
    if (oldName) this.paths.delete(oldName, path)
    this.names.set(path, name)
    this.paths.set(name, path)
    this.restricted.add(path)
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  remove(path: string): void {
    const name = this.names.get(path)
    if (!name) return
    this.paths.delete(name, path)
    this.names.delete(path)
    this.restricted.delete(path)
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  contains(path: string): boolean {
    return this.restricted.has(path)
  }
  list(): { path: string; name: string }[] {
    return Object.entries(this.names.storage).map(([path, name]) => ({ path, name: name as string }))
  }
}

class Whitelist {
  constructor(private exempt: (user: string) => boolean = () => false) {}
  enabled: boolean = false
  private users = new Set<string>()
  storage = new Storage(
    'data/whitelist.json',
    () => ({
      enabled: this.enabled,
      whitelist: Array.from(this.users),
    }),
    data => {
      this.enabled = data.enabled ? true : false
      this.users = new Set(data.whitelist)
    },
  )
  subscription = new LazyState<{ enabled: boolean; users: string[] }>(() => ({
    enabled: this.enabled,
    users: Array.from(this.users),
  }))
  add(user: string): void {
    if (this.users.has(user)) return
    this.users.add(user)
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  remove(user: string): void {
    if (!this.users.has(user)) return
    this.users.delete(user)
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
  /** Enabled, or its file is corrupt and only exempt users (owners) get in */
  get enforced(): boolean {
    return this.enabled || this.storage.corrupt
  }
  allows(user: string): boolean {
    if (this.exempt(user)) return true
    if (this.storage.corrupt) return false
    return this.users.has(user)
  }
  setEnabled(enabled: boolean | undefined) {
    if (enabled !== true && enabled !== false) return
    if (this.enabled === enabled) return
    this.enabled = enabled
    this.subscription.setNeedsUpdate()
    this.storage.save()
  }
}

class MapSet<Value> {
  content = new ObjectMap<string, Set<Value>>()
  size = 0
  set(key: string, value: Value) {
    const set = this.content.get(key)
    if (set) {
      if (!set.has(value)) {
        set.add(value)
        this.size += 1
      }
    } else {
      this.content.set(key, new Set([value]))
      this.size += 1
    }
  }
  keys(): string[] {
    return Object.keys(this.content.storage)
  }
  replace(key: string, value: Set<Value>) {
    const oldValue = this.content.get(key)
    if (oldValue) this.size -= oldValue.size
    this.content.set(key, value)
    this.size += value.size
  }
  move(from: string, to: string): Set<Value> | undefined {
    const set = this.content.get(from)
    if (!set) return
    const oldTarget = this.content.get(to)
    if (oldTarget) this.size -= oldTarget.size
    this.content.delete(from)
    this.content.set(to, set)
    return set
  }
  has(key: string, value: Value): boolean {
    const set = this.content.get(key)
    if (!set) return false
    return set.has(value)
  }
  hasKey(key: string): boolean {
    return this.content.get(key) !== undefined
  }
  get(key: string): Set<Value> {
    return this.content.get(key) ?? new Set<Value>()
  }
  delete(key: string, value: Value): boolean {
    const set = this.content.get(key)
    if (!set?.delete(value)) return false
    if (set.size === 0) this.content.delete(key)
    this.size -= 1
    return true
  }
  deleteAll(key: string): boolean {
    const set = this.content.get(key)
    if (!set) return false
    this.size -= set.size
    this.content.delete(key)
    return true
  }
  encode(): any {
    let result: any = {}
    this.forEach((key, value) => (result[key] = Array.from(value)))
    return result
  }
  decode(value: any | undefined) {
    this.content = new ObjectMap()
    this.size = 0
    if (!value) return
    Object.entries(value).forEach(([key, value]) => {
      this.replace(key, new Set(value as Value[]))
    })
  }
  forEach(action: (key: string, value: Set<Value>) => void) {
    Object.entries(this.content.storage).forEach(([key, value]) => action(key, value as Set<Value>))
  }
}
