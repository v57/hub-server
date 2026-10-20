import { Channel, type Sender, type BodyContext, ObjectMap } from 'channel/server'
import 'channel/client'
import { LazyState, LazyStates } from 'channel/more'
import { HubMerger, ServiceUpdateContext } from './merge.ts'
import { settings } from './settings.ts'
import { publicKey } from './keychain.ts'
import * as LoadBalancer from './load balancers.ts'
import type { Cancellable } from 'channel/channel'
import { Security, builtinAccess, ownersGroup, type Caller, type Principal } from './security.ts'
import { randomUUIDv7 } from 'bun'
import {
  appleAgentAPIsEnabled,
  appleAgentProtectedApi,
  networkProtectedApi,
  registerNetworkAPIs,
} from './network/hub'
import { NetworkAPI } from './network/api'
import { HubHeaderStore, registerHubHeaderAPIs } from './header'
import { HubNetNodeStore } from './network/node-store'
import { HubDevices } from './hub-devices'
import type { Certificate } from './devices'

export type { Sender } from 'channel/client'

export const security = await new Security().load()
security.hubKey = await publicKey()

const paddr = (a?: string) => (a ? (isNaN(Number(a)) ? a : Number(a)) : 1997)

export interface State {
  id: string
  key?: string
  name?: string
  icon?: any
  services: Set<string>
  apps: Set<string>
  ip?: string
  /** Device id, when the connection has a certificate from an approved device */
  device?: string
  /** Instance name from the certificate of a device connection */
  instance?: string
  /** A valid certificate, also from a pending device */
  certificate?: Certificate
}

interface ServiceProvider {
  /** Connection id */
  id: string
  key?: string
  name?: string
  device?: { id: string; name: string }
  instance?: string
  online: true
}
interface HubNetInfo {
  id: string
  localIp: string
}

let requests = 0
export class Hub {
  services = new ObjectMap<string, Services>()
  channel = new Channel<State>()
  connections = new Set<BodyContext<State>>()
  merger = new HubMerger(this)
  proxies = new Map<string, Sender>()
  apps = new Apps()
  api = new Set<string>()
  networkAPI?: NetworkAPI
  header = new HubHeaderStore()
  hubNetNode = new HubNetNodeStore()
  devices = new HubDevices(this, security)
  ready: Promise<void>
  apiList = new LazyStates<State, string[]>(state => this.allowedApi(security.caller(state)))
  /** Keyed by JSON `[key, device, path]` */
  serviceProviders = new LazyStates<string, ServiceProvider[]>((id: string) => {
    const [key, device, path] = JSON.parse(id)
    return this.servicesFor(path, { key, device })
  })
  /** Connections, their devices or their groups changed */
  connectionsChanged: () => void = () => {}
  constructor(address = paddr(Bun.env.HUBLISTEN)) {
    const services = this.services
    const hub = this
    const statusState = new LazyState<StatusState>(() => ({
      requests,
      services: this.services.map(a => a.status),
      pro: true,
    }))
    const connectionsState = new LazyState(() => this.connectionsInfo()).delay(1)
    const statusBadges = new LazyState<StatusBadges>(() => this.statusBadges)
    const hubNetList = new LazyState<HubNetInfo[]>(() => {
      const providers = this.services.get('net/invite')?.services ?? []
      return providers.flatMap(provider => provider.state.key ? [{
        id: provider.state.key,
        localIp: provider.state.ip === '::1' ? '127.0.0.1' : (provider.state.ip ?? ''),
      }] : [])
    }).delay(1)
    const hubNetNode = new LazyState(() => this.hubNetNode.value)
    const securityMode = new LazyState(() => ({ mode: security.effectiveMode, requireV1: security.requireV1 }))
    const sendUpdates = () => {
      statusState.setNeedsUpdate()
      statusBadges.setNeedsUpdate()
      this.serviceProviders.setNeedsUpdate()
      hubNetList.setNeedsUpdate()
      this.apiList.setNeedsUpdate()
    }
    const appleAgentEnabled = appleAgentAPIsEnabled()
    security.registerProtectedApis({
      ...networkProtectedApi,
      ...(appleAgentEnabled ? appleAgentProtectedApi : {}),
    })
    const networkAPI = new NetworkAPI(security)
    this.networkAPI = registerNetworkAPIs(this.channel, security, networkAPI, appleAgentEnabled)
    registerHubHeaderAPIs(this.channel, security, this.header)
    this.ready = Promise.all([
      networkAPI.load(),
      this.header.load(),
      this.hubNetNode.load(),
      this.devices.load(security.hubKey),
    ]).then(() => {
      hubNetNode.setNeedsUpdate()
    })

    // Built-in APIs by access class (protocol.md section 7); service paths are checked when forwarded
    this.channel.use((ctx, next) => {
      if (builtinAccess(ctx.path)) security.checkBuiltin(this.caller(ctx.state, ctx.sender, ctx.context), ctx.path)
      return next()
    })

    this.connectionsChanged = () => {
      connectionsState.setNeedsUpdate()
      this.devices.devicesState.setNeedsUpdate()
      sendUpdates()
    }
    this.devices.register(this.channel)
    this.channel
      .post('hub/info', () => ({ key: security.hubKey, protocol: 1, pro: true, mode: security.effectiveMode }))
      .stream('hub/security/mode', () => securityMode.makeIterator())
      .post('hub/security/mode/set', ({ body }) => {
        security.setMode({ mode: body?.mode, requireV1: body?.requireV1 })
        securityMode.setNeedsUpdate()
        sendUpdates()
      })
      .post('hub/api', ({ state, sender, context }) => this.allowedApi(this.caller(state, sender, context)))
      .stream('hub/net/list', () => hubNetList.makeIterator())
      .stream('hub/net/node', () => hubNetNode.makeIterator())
      .post('hub/net/node/set', async ({ body, state, path }) => {
        security.requireOwner(state, path)
        await this.hubNetNode.set(body)
        hubNetNode.setNeedsUpdate()
      })
      .post('hub/profile/update', ({ body: { name, icon }, state }) => {
        if (icon) state.icon = icon
        if (name) state.name = name
        this.connectionsChanged()
      })
      .stream('hub/api', ({ state }) => this.apiList.makeIterator(state))
      .stream('hub/api/services', ({ body, state: { key, device } }) => {
        return this.serviceProviders.makeIterator(JSON.stringify([key, device, body]))
      })
      .post('hub/service/update', ({ body: { add, remove, addApps, removeApps, services, apps, reporter }, state, sender }) => {
        if (reporter === true) this.devices.requestReporter(state)
        const context = this.merger.context()
        if (services && Array.isArray(services)) {
          const s = services as ServiceHeader[]
          const paths = new Set(s.map(a => a.path))
          const add = paths.difference(state.services)
          const remove = state.services.difference(paths)
          this.addServices(sender, state, Array.from(add), context)
          this.removeServices(sender, state, Array.from(remove), context)
          for (const service of s) {
            this.services.get(service.path)?.setPublic(sender, service.public === true)
            const limit = service.limit ?? 0
            if (Number.isFinite(limit) && limit >= 0) {
              this.services.get(service.path)?.setLimit(sender, service.limit ?? 0)
            }
            const p = service.permissions
            if (p) {
              const group = p.group ?? service.path.split('/')[0]
              security.group.names.add(service.path, `${group}: ${p.name}`)
            }
          }
        }
        if (apps && Array.isArray(apps)) {
          const paths = new Set((apps as AppHeader[]).map(a => a.path))
          const add = paths.difference(state.apps)
          const remove = state.apps.difference(paths)
          const newApps = (apps as AppHeader[]).filter(app => add.has(app.path))
          this.apps.add(sender, state, newApps)
          this.apps.remove(sender, state, Array.from(remove))
        }
        if (add && Array.isArray(add)) this.addServices(sender, state, add, context)
        if (remove && Array.isArray(remove)) this.removeServices(sender, state, remove, context)
        if (addApps && Array.isArray(addApps)) this.apps.add(sender, state, addApps)
        if (removeApps && Array.isArray(removeApps)) this.apps.remove(sender, state, removeApps)
        context.applyChanges()
        sendUpdates()
        this.devices.devicesState.setNeedsUpdate()
      })
      .post('hub/merge/add', ({ body: address, state, path }) => {
        security.requireOwner(state, path)
        this.merger.connect(address, this)
      })
      .post('hub/merge/remove', ({ body: address, state, path }) => {
        security.requireOwner(state, path)
        this.merger.disconnect(address)
      })
      .stream('hub/merge/status', () => this.merger.state.makeIterator())
      .post('hub/key', ({ state, path }) => {
        security.requireOwner(state, path)
        return publicKey()
      })
      .stream('hub/connections', () => connectionsState.makeIterator())
      .post('hub/proxy', ({ body: { body, path, name } }) => {
        const proxy = this.proxies.get(name)
        if (!proxy) throw 'proxy not found'
        return proxy.send(path, body)
      })
      .stream('hub/proxy', ({ body: { body, path, name } }) => {
        const proxy = this.proxies.get(name)
        if (!proxy) throw 'proxy not found'
        return proxy.values(path, body)
      })
      .post('hub/proxy/add', ({ body: address, state, path }) => {
        security.requireOwner(state, path)
        this.merger.connectProxy(address, this)
      })
      .post('hub/proxy/remove', ({ body: address, state, path }) => {
        security.requireOwner(state, path)
        this.merger.disconnectProxy(address)
      })
      .post('hub/proxy/join', ({ sender, state }) => {
        if (!state.key) throw 'unauthorized'
        this.proxies.set(state.key, sender)
        return state.key
      })
      .post('hub/balancer/set', ({ body: { path, type }, state, path: api }) => {
        security.requireOwner(state, api)
        settings.updateApi(path, settings => {
          if ((settings.loadBalancer ?? 'counter') === type) return false
          settings.loadBalancer = type
          return true
        })
        this.services.get(path)?.setBalancer(type)
      })
      .post('hub/balancer/limit', ({ body: { limit }, state, path }) => {
        security.requireOwner(state, path)
        if (settings.data.pendingLimit !== limit) {
          settings.data.pendingLimit = limit
          settings.setNeedsSave()
        }
      })
      .post('hub/host/update', async ({ body: { key, allow, revoke }, state, path }) => {
        security.requireOwner(state, path)
        security.host.allow(key, allow)
        security.host.revoke(key, revoke)
        const context = this.merger.context()
        allow?.forEach?.((path: string) => this.services.get(path)?.allowKey(key, context))
        revoke?.forEach?.((path: string) => this.services.get(path)?.revokeKey(key, context))
        context.applyChanges()
        sendUpdates()
      })
      .stream('hub/host/pending', ({ state, path }) => {
        security.requireOwner(state, path)
        return security.host.pendingSubscription.makeIterator()
      })
      .post('hub/host/allowed', async ({ body: key, state, path }) => {
        security.requireOwner(state, path)
        return Array.from(security.host.allowed(key))
      })
      .post('hub/call/update', async ({ body: { key, allow, revoke }, state, path }) => {
        security.requireOwner(state, path)
        security.call.allow(key, allow)
        security.call.revoke(key, revoke)
      })
      .stream('hub/call/pending', ({ state, path }) => {
        security.requireOwner(state, path)
        return security.call.pendingSubscription.makeIterator()
      })
      .post('hub/call/allowed', async ({ body: key, state, path }) => {
        security.requireOwner(state, path)
        return Array.from(security.call.allowed(key))
      })
      .post('hub/group/create', async ({ body: name, state, path }) => {
        security.requireOwner(state, path)
        security.group.create(name)
      })
      .post('hub/group/rename', async ({ body: { group, name }, state, path }) => {
        security.requireOwner(state, path)
        security.group.rename(group, name)
        this.networkAPI?.handleGroupRenamed(group, name)
        connectionsState.setNeedsUpdate()
      })
      .post('hub/group/remove', async ({ body: group, state, path }) => {
        security.requireOwner(state, path)
        security.group.remove(group)
        this.networkAPI?.handleGroupMembershipChanged(group)
      })
      .post('hub/group/update', async ({ body: { group, add, remove, set }, state, path }) => {
        security.requireOwner(state, path)
        if (set) {
          security.group.replace(group, set)
        } else {
          security.group.update(group, add, remove)
        }
      })
      .post('hub/group/update/users', async ({ body: { group, add, remove }, state, path }) => {
        security.requireOwner(state, path)
        security.group.users.edit(group, add, remove)
        this.networkAPI?.handleGroupMembershipChanged(group)
        const users = security.group.users.users(group)
        let changes = 0
        const context = this.merger.context()
        add?.forEach((service: string) => {
          const s = this.services.get(service)
          if (!s) return
          users.forEach(user => (changes += s.allowKey(user, context)))
        })
        remove?.forEach((service: string) => {
          const s = this.services.get(service)
          if (!s) return
          users.forEach(user => (changes += s.revokeKey(user, context)))
        })
        context.applyChanges()
        connectionsState.setNeedsUpdate()
        if (changes) {
          sendUpdates()
        }
      })
      .stream('hub/group/list', () => security.group.subscription.makeIterator())
      .stream('hub/group/users', () => security.group.users.subscription.makeIterator())
      .stream('hub/group/names', () => security.group.names.subscription.makeIterator())
      .post('hub/whitelist', async ({ body: { enabled, add, remove, allowsCurrent }, state, path }) => {
        security.requireOwner(state, path)
        security.whitelist.setEnabled(enabled)
        add?.forEach?.((user: string) => security.whitelist.add(user))
        remove?.forEach?.((user: string) => security.whitelist.remove(user))
        if (allowsCurrent) {
          this.connections.forEach(c => {
            if (c.state.key) security.whitelist.add(c.state.key)
          })
        }
        if (security.whitelist.enabled) {
          this.connections.forEach(c => {
            if (!c.state.key || !security.whitelist.allows(c.state.key)) {
              c.sender.stop()
            }
          })
        }
      })
      .stream('hub/whitelist/status', () => security.whitelist.subscription.makeIterator())
      .stream('hub/status', () => statusState.makeIterator())
      .stream('hub/status/badges', () => statusBadges.makeIterator())
      .postOther(other, async ({ body, path, context, task, state, sender }) => {
        const service = this.services.get(path)
        if (!service) throw 'api not found'
        const caller = this.caller(state, sender, context)
        if (!security.allowsCall(caller, path, service.isPublic)) throw 'permissions required'
        const selected = service.selectFor(context)
        let s = selected ?? service.next()
        if (!s) s = await service.addPending()
        if (!s) throw 'api not found'
        if (task?.isCancelled) {
          service.completed(s)
          throw 'cancelled'
        }
        service.requests += 1
        requests += 1
        statusState.setNeedsUpdate()
        const request = s.sender.request(path, body, { context: forwardedContext(context, caller) })
        try {
          if (task) {
            s.sending.add(task)
            task.onCancel(() => {
              request.cancel()
              s.sending.delete(task)
              service.completed(s)
            })
          }
          return await request.response
        } finally {
          if (task) s.sending.delete(task)
          service.completed(s)
          statusState.setNeedsUpdate()
        }
      })
      .streamOther(other, async function* ({ body, path, context, state, sender }) {
        const service = services.get(path)
        if (!service) throw 'api not found'
        const caller = hub.caller(state, sender, context)
        if (!security.allowsCall(caller, path, service.isPublic)) throw 'permissions required'
        const selected = service.selectFor(context)
        let s = selected ?? service.next()
        if (!s) s = await service.addPending()
        if (!s) throw 'api not found'
        service.requests += 1
        requests += 1
        s.streams += 1
        statusState.setNeedsUpdate()
        try {
          for await (const value of s.sender.values(path, body, { context: forwardedContext(context, caller) })) {
            yield value
          }
        } finally {
          s.streams -= 1
          service.completed(s)
        }
      })
      .onDisconnect((state, sender) => {
        const context = this.merger.context()
        this.removeServices(sender, state, Array.from(state.services), context)
        const sendUpdates = state.apps.size > 0
        this.apps.removeSender(sender, state)
        if (state.id) this.proxies.delete(state.id)
        context.applyChanges()
        statusState.setNeedsUpdate()
        this.serviceProviders.setNeedsUpdate()
        if (sendUpdates) statusBadges.setNeedsUpdate()
        // Cleanup network agent profile and providers
        this.networkAPI?.handleDisconnect(state)
        this.devices.disconnected(state)
        if (state.device) this.devices.devicesState.setNeedsUpdate()
      })
    this.ready.then(() => this.channel.listen(address, {
        async state(headers: Record<string, string | undefined>): Promise<State> {
          const key = security.keys.verify(headers['auth'] ?? undefined, security.whitelist, {
            version: headers['v'],
            hubKey: security.hubKey,
            requireV1: security.requireV1,
          })
          const state: State = {
            id: randomUUIDv7(),
            key,
            services: new Set<string>(),
            apps: new Set<string>(),
            ip: headers['x-hub-remote-ip'],
          }
          hub.devices.connect(state, headers)
          return state
        },
        onConnect: (connection: BodyContext<State>) => {
          this.connections.add(connection)
          connectionsState.setNeedsUpdate()
          statusBadges.setNeedsUpdate()
        },
        onDisconnect: (connection: BodyContext<State>) => {
          this.connections.delete(connection)
          connectionsState.setNeedsUpdate()
          statusBadges.setNeedsUpdate()
        },
      }))

    this.api = new Set([...Object.keys(this.channel.postApi.storage), ...Object.keys(this.channel.streamApi.storage)])
    settings.data.merge.forEach(address => this.merger.connect(address, this))
  }
  stats() {
    this.services.map(a => a)
  }
  servicesFor(path: string, principal: Principal): ServiceProvider[] {
    if (!path || !this.api.has(path)) return []
    const service = this.services.get(path)
    if (!security.allowsCall(security.caller(principal), path, service?.isPublic)) return []
    return service?.providers(security) ?? []
  }
  /** Paths the caller may call, for `hub/api` */
  allowedApi(caller: Caller): string[] {
    return security.allowedApi(caller, this.api, path => this.services.get(path)?.isPublic ?? false)
  }
  /**
   * Who sent a request. A request from a hub this one merges into is that hub's caller: its key as `hub/info`
   * reported it (never an owner, since it isn't verified), `via` that key and the caller it claims.
   */
  caller(state: State, sender: Sender, context?: any): Caller {
    const merge = this.merger.connectionFor(sender)
    if (!merge) return security.caller(state)
    const caller = security.caller(merge.hubKey)
    const claimedHub = typeof context?.hub === 'object' ? context.hub : undefined
    const via = merge.hubKey ?? (typeof claimedHub?.hubKey === 'string' ? claimedHub.hubKey : undefined)
    return {
      ...caller,
      groups: caller.groups.filter(group => group !== ownersGroup),
      owner: false,
      ...(via ? { via } : {}),
      ...(claimedHub?.caller !== undefined ? { claimed: claimedHub.caller } : {}),
    }
  }
  addServices(sender: Sender, state: State, services: string[], context: ServiceUpdateContext) {
    services.forEach(s => {
      if (state.services.has(s)) return
      state.services.add(s)
      let service = this.services.get(s)
      if (!service) {
        service = new Services(s)
        this.services.set(s, service)
      }
      const enabled = security.allowsHost(state, s)
      service.add({ sender, state, enabled, sending: new Set(), streams: 0, limit: 0 }, context)
    })
    console.log('+', services.length, 'api')
  }
  removeServices(sender: Sender, state: State, services: string[], context: ServiceUpdateContext) {
    services.forEach(s => {
      if (!state.services.has(s)) return
      state.services.delete(s)
      let service = this.services.get(s)
      if (!service) return
      service.remove(sender, context)
    })
  }
  private connectionsInfo(): ConnectionInfo[] {
    return Array.from(
      this.connections,
      c =>
        ({
          id: c.state.id,
          key: c.state.key,
          name: c.state.name,
          icon: c.state.icon,
          services: c.state.services.size,
          apps: c.state.apps.size,
          group: security.userGroup(c.state.key),
          ...(c.state.device ? { device: c.state.device, instance: c.state.instance } : {}),
        }) as ConnectionInfo,
    )
  }
  get statusBadges(): StatusBadges {
    return {
      connections: this.connections.size,
      services: this.services.size,
      security: security.host.pendingList.size,
      apps: this.apps.headers,
    }
  }
}

const other = () => true

/** The client's context with `hub` replaced by the caller (protocol.md section 4) */
export function forwardedContext(context: any, caller: Caller): any {
  const { hub: _, ...rest } = context && typeof context === 'object' ? context : {}
  return { ...rest, hub: { caller, hubKey: security.hubKey } }
}

export interface Service {
  state: State
  sender: Sender
  sending: Set<Cancellable>
  streams: number
  enabled: boolean
  limit: number
}

class Services {
  name: string
  requests = 0
  services: Service[] = []
  disabled: Service[] = []
  pending: ((service: Service | undefined) => void)[] = []
  /** Connections whose header marked this path `public` */
  publicSenders = new Set<Sender>()
  loadBalancer: LoadBalancer.Type
  isEnabled = false
  limited = false
  constructor(name: string) {
    this.name = name
    this.loadBalancer = new LoadBalancer.Counter()
  }
  add(service: Service, context: ServiceUpdateContext) {
    if (service.enabled) {
      if (this.services.findIndex(a => a.sender === service.sender) === -1) {
        this.loadBalancer.add(this.services, service)
        this.enableServiceIfNeeded(context)
        if (this.pending.length) {
          const service = this.loadBalancer.next(this.services)
          this.pending.shift()?.(service)
        }
      }
    } else {
      if (this.disabled.findIndex(a => a.sender === service.sender) === -1) {
        this.disabled.push(service)
      }
    }
  }
  setLimit(sender: Sender, limit: number) {
    if (limit > 0 && !this.limited) {
      this.limited = true
      if (!this.loadBalancer.allowsLimit) {
        this.loadBalancer = new LoadBalancer.Counter()
      }
    }
    let index = this.services.findIndex(a => a.sender === sender)
    if (index >= 0) {
      this.services[index].limit = limit
      return
    }
    index = this.disabled.findIndex(a => a.sender === sender)
    if (index >= 0) {
      this.disabled[index].limit = limit
      return
    }
  }
  select(id: string, device?: string): Service | undefined {
    return this.services.find(
      service => (service.state.key === id || service.state.id === id) && (!device || service.state.device === device),
    )
  }
  /**
   * The provider `context.service` (connection id or key) or `context.device` (device id) asks for. A device with
   * no provider of the path fails with `api not found`; an unknown service falls back to load balancing as before.
   */
  selectFor(context: any): Service | undefined {
    const device = typeof context?.device === 'string' ? context.device : undefined
    const selected = typeof context?.service === 'string' ? this.select(context.service, device) : undefined
    if (selected || !device) return selected
    const onDevice = this.services.filter(service => service.state.device === device)
    if (!onDevice.length) throw 'api not found'
    return onDevice.reduce((a, b) => (b.sending.size + b.streams < a.sending.size + a.streams ? b : a))
  }
  allowKey(key: string, context: ServiceUpdateContext): number {
    let enabled = new Set<Service>()
    this.disabled.forEach(s => {
      if (s.state.key !== key) return
      enabled.add(s)
      s.enabled = true
      this.loadBalancer.add(this.services, s)
      this.enableServiceIfNeeded(context)
    })
    if (!enabled.size) return 0
    this.disabled = this.disabled.filter(a => !enabled.has(a))
    return enabled.size
  }
  revokeKey(key: string, context: ServiceUpdateContext): number {
    let disabled: Service[] = []
    this.services.forEach(s => {
      if (s.state.key !== key) return
      disabled.push(s)
      s.enabled = false
      this.disabled.push(s)
    })
    if (!disabled.length) return 0
    for (const service of disabled) {
      this.loadBalancer.remove(this.services, service.sender)?.sending.forEach(a => a.cancel())
    }
    this.disableServiceIfNeeded(context)
    return disabled.length
  }
  setPublic(sender: Sender, isPublic: boolean) {
    if (isPublic) this.publicSenders.add(sender)
    else this.publicSenders.delete(sender)
  }
  /** Callable by anyone in `default-deny`: an enabled provider marked the path public */
  get isPublic(): boolean {
    return this.services.some(service => this.publicSenders.has(service.sender))
  }
  remove(sender: Sender, context: ServiceUpdateContext) {
    this.publicSenders.delete(sender)
    const s = this.loadBalancer.remove(this.services, sender)
    s?.sending.forEach(a => a.cancel())
    this.disableServiceIfNeeded(context)
    const index = this.disabled.findIndex(a => a.sender === sender)
    if (index >= 0) this.disabled.splice(index, 1)
  }
  private enableServiceIfNeeded(context: ServiceUpdateContext) {
    // console.log('Enable if needed', this.name, this.isEnabled, this.services.length)
    if (this.isEnabled || !this.services.length) return
    this.isEnabled = true
    context.add(this.name)
  }
  private disableServiceIfNeeded(context: ServiceUpdateContext) {
    if (!this.isEnabled || this.services.length) return
    this.isEnabled = false
    context.remove(this.name)
    if (this.pending.length) {
      this.pending.forEach(a => a(undefined))
      this.pending = []
    }
  }
  private _next(): Service | undefined {
    return this.loadBalancer.next(this.services)
  }
  next(): Service | undefined {
    if (this.pending.length > 0) return
    return this._next()
  }
  addPending(): Promise<Service | undefined> {
    if (settings.data.pendingLimit > 0) {
      const deleteCount = this.pending.length + 1 - settings.data.pendingLimit
      if (deleteCount > 0) this.pending.splice(0, deleteCount)
    }
    return new Promise(success => this.pending.push(service => success(service)))
  }
  get status(): ServicesStatus {
    return {
      name: this.name,
      services: this.services.length,
      disabled: this.disabled.length,
      requests: this.requests,
      balancer: this.loadBalancer.name,
      pending: this.pending.length,
      running: this.services.reduce((a, b) => a + b.sending.size + b.streams, 0),
    }
  }
  providers(security: Security): ServiceProvider[] {
    return this.services
      .map(({ state }): ServiceProvider => {
        const device = state.device ? security.caller({ device: state.device }).device : undefined
        return {
          id: state.id,
          ...(state.key ? { key: state.key } : {}),
          name: state.name?.trim() || undefined,
          ...(device ? { device } : {}),
          ...(state.instance ? { instance: state.instance } : {}),
          online: true,
        }
      })
      .sort((left, right) => {
        const leftLabel = left.name ?? left.id
        const rightLabel = right.name ?? right.id
        const nameDiff = leftLabel.localeCompare(rightLabel)
        if (nameDiff !== 0) return nameDiff
        return left.id.localeCompare(right.id)
      })
  }
  setBalancer(name: LoadBalancer.Name) {
    if (this.loadBalancer.name === name) return
    let loadBalancer: LoadBalancer.Type
    switch (name) {
      case 'random':
        loadBalancer = new LoadBalancer.Random()
        break
      case 'counter':
        loadBalancer = new LoadBalancer.Counter()
        break
      case 'first':
        loadBalancer = new LoadBalancer.FirstAvailable()
        break
      case 'available':
        loadBalancer = new LoadBalancer.CounterAvailable()
        break
    }
    if (!this.limited || loadBalancer.allowsLimit) {
      this.loadBalancer = loadBalancer
    }
  }
  completed(service: Service) {
    if (this.pending.length === 0) return
    this.pending.shift()?.(service)
  }
}

class Apps {
  states = new ObjectMap<string, AppState>()
  headers: AppHeader[] = []
  add(sender: Sender, senderState: State, headers: AppHeader[]) {
    headers.forEach(header => {
      this.addOne(sender, senderState, header)
    })
  }
  addOne(sender: Sender, senderState: State, header: AppHeader) {
    if (senderState.apps.has(header.path)) return
    senderState.apps.add(header.path)
    let state: AppState | undefined = this.states.get(header.path)
    if (!state) {
      state = { senders: new Set([sender]), header }
      this.states.set(header.path, state)
      header.services = 1
      this.headers.push(header)
    } else {
      const i = this.headers.findIndex(h => h.path === header.path)
      if (i !== -1) this.headers[i].services = (this.headers[i].services ?? 0) + 1
      state.senders.add(sender)
    }
  }
  removeSender(sender: Sender, senderState: State) {
    senderState.apps.forEach(path => {
      this.removeOne(sender, path)
    })
    senderState.apps = new Set()
  }
  remove(sender: Sender, senderState: State, paths: string[]) {
    for (const path of paths) {
      if (!senderState.apps.has(path)) continue
      senderState.apps.delete(path)
      this.removeOne(sender, path)
    }
  }
  removeOne(sender: Sender, path: string) {
    let state: AppState | undefined = this.states.get(path)
    if (!state) return
    state.senders.delete(sender)
    const i = this.headers.findIndex(h => h.path === path)
    if (i !== -1) this.headers[i].services = Math.max((this.headers[i].services ?? 0) - 1, 0)
  }
}
interface AppState {
  senders: Set<Sender>
  header: AppHeader
}

interface AppHeader {
  type: 'app'
  name: string
  path: string
  services?: number
}

interface ServiceHeader {
  path: string
  permissions?: ServicePermissions
  limit?: number
  /** Callable by anyone in `default-deny` */
  public?: boolean
}
interface ServicePermissions {
  group?: string
  name: string
}

interface StatusState {
  requests: number
  services: ServicesStatus[]
  pro?: boolean
}
interface ServicesStatus {
  name: string
  requests: number
  services: number
  disabled: number
  balancer: LoadBalancer.Name
  pending: number
  running: number
}
interface StatusBadges {
  services: number
  security: number
  connections: number
  apps: AppHeader[]
}
interface ConnectionInfo {
  device?: string
  instance?: string
  id?: string
  key?: string
  services?: number
  apps?: number
  group?: string
  name?: string
  icon?: any
}
