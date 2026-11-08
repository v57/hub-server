import { Channel, type Sender, type BodyContext, ObjectMap } from 'channel/server'
import 'channel/client'
import { LazyStates } from 'channel/more'
import { HubMerger, ServiceUpdateContext } from './merge.ts'
import { settings } from './settings.ts'
import { publicKey, signChallenge } from './keychain.ts'
import { hubInfoSignedData, isClientNonce } from './nonces.ts'
import * as LoadBalancer from './load balancers.ts'
import type { Cancellable } from 'channel/channel'
import { HubError, Security, builtinAccess, deviceMember, keyMember, ownersGroup, type Caller, type Principal } from './security.ts'
import { randomUUIDv7, type Server } from 'bun'
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
import { FreshState } from './fresh-state'
import { Pairing } from './pairing'
import type { Certificate } from './devices'
import { describePath, readDescriptions, type ApiDescription, type ApiKind, type PathDescriptions } from './api-descriptions'

export type { Sender } from 'channel/client'

export const security = await new Security().load()
security.hubKey = await publicKey()

const paddr = (a?: string) => (a ? (isNaN(Number(a)) ? a : Number(a)) : 1997)

/** The port of a listen address: `1997` and `0.0.0.0:1997` → `1997` */
export function listenPort(address: number | string): number | undefined {
  const port = typeof address === 'number' ? address : Number(address.slice(address.lastIndexOf(':') + 1))
  return Number.isInteger(port) && port > 0 ? port : undefined
}

/** The listen address on 127.0.0.1 only, keeping its port: `1997` and `0.0.0.0:1997` → `127.0.0.1:1997` */
export function localAddress(address: number | string): string {
  return `127.0.0.1:${listenPort(address) ?? 1997}`
}

export interface HubOptions {
  /** Local mode (`--local`, `HUB_MODE=local`): 127.0.0.1 only, `default-allow`, the first owner pairs like anywhere */
  local?: boolean
}

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
  /** Its device asked to attach before it had a row (`hub/device/attach/ask`) */
  attachAsk?: { parent?: string }
  /** Its paths take no new calls (`hub/service/update { draining: true }`); running calls go on */
  draining?: boolean
  /** It authenticated with a v1 token */
  v1?: boolean
  /** What its last `services` update said about its paths (protocol.md section 15) */
  apiDescriptions?: Map<string, PathDescriptions>
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
  /** Streams forwarded to each provider connection, ended when it disconnects */
  forwarded = new Map<Sender, Set<ForwardedStream>>()
  apps = new Apps()
  api = new Set<string>()
  networkAPI?: NetworkAPI
  header = new HubHeaderStore()
  hubNetNode = new HubNetNodeStore()
  devices = new HubDevices(this, security)
  pairing = new Pairing()
  readonly local: boolean
  /** The listening server, once ready */
  server?: Server
  ready: Promise<void>
  apiList = new LazyStates<State, string[]>(state => this.allowedApi(security.caller(state)))
  /** `hub/api/list` streams */
  apiDescriptions = new LazyStates<State, ApiDescription[]>(state => this.describedApi(security.caller(state)))
  /** Kinds of the hub's own paths, for `hub/api/list` */
  builtinKinds = new Map<string, ApiKind[]>()
  /** Keyed by JSON `[key, device, path]` */
  serviceProviders = new LazyStates<string, ServiceProvider[]>((id: string) => {
    const [key, device, path] = JSON.parse(id)
    return this.servicesFor(path, { key, device })
  })
  /** Connections, their devices or their groups changed */
  connectionsChanged: () => void = () => {}
  constructor(address: number | string = paddr(Bun.env.HUBLISTEN), options: HubOptions = {}) {
    this.local = options.local === true
    if (this.local) {
      address = localAddress(address)
      security.enableLocalMode()
    }
    const services = this.services
    const hub = this
    const statusState = new FreshState<StatusState>(() => ({
      requests,
      services: this.services.map(a => a.status),
      pro: true,
    }))
    const connectionsState = new FreshState(() => this.connectionsInfo()).delay(1)
    const statusBadges = new FreshState<StatusBadges>(() => this.statusBadges)
    const hubNetList = new FreshState<HubNetInfo[]>(() => {
      const providers = this.services.get('net/invite')?.services ?? []
      return providers.flatMap(provider => provider.state.key ? [{
        id: provider.state.key,
        localIp: provider.state.ip === '::1' ? '127.0.0.1' : (provider.state.ip ?? ''),
      }] : [])
    }).delay(1)
    const hubNetNode = new FreshState(() => this.hubNetNode.value)
    const securityMode = new FreshState(() => {
      const v0Until = settings.data.security.v0Until
      return { mode: security.effectiveMode, requireV1: security.refusesV0(), ...(typeof v0Until === 'string' ? { v0Until } : {}) }
    })
    const sendUpdates = () => {
      statusState.setNeedsUpdate()
      statusBadges.setNeedsUpdate()
      this.serviceProviders.setNeedsUpdate()
      hubNetList.setNeedsUpdate()
      this.apiList.setNeedsUpdate()
      this.apiDescriptions.setNeedsUpdate()
    }
    const appleAgentEnabled = appleAgentAPIsEnabled()
    security.registerProtectedApis({
      ...networkProtectedApi,
      ...(appleAgentEnabled ? appleAgentProtectedApi : {}),
    })
    const networkAPI = new NetworkAPI(security)
    this.networkAPI = registerNetworkAPIs(this.channel, security, networkAPI, appleAgentEnabled)
    registerHubHeaderAPIs(this.channel, security, this.header)
    // Hub Network members are devices: binding approves the device, removing it removes the member
    const networkStateChanged = networkAPI.onStateChanged
    networkAPI.onStateChanged = () => {
      networkStateChanged?.()
      this.devices.devicesState.setNeedsUpdate()
    }
    networkAPI.onBindApprove = state => this.devices.approveConnection(state)
    networkAPI.deviceLabel = id => this.devices.registry.device(id)?.name
    networkAPI.serviceDevice = key => this.devices.registry.data.services[key]?.device
    this.devices.sharedWith = state => networkAPI.devicesSharedWith(state)
    this.devices.canUseHostSSH = state => networkAPI.canSignInToHost(state)
    this.devices.hostDevice = () => networkAPI.hubHostProfile()?.device ?? this.devices.selfId
    networkAPI.deviceSSHPort = id => {
      const port = (this.devices.registry.device(id)?.capabilities?.ssh as { port?: unknown } | undefined)?.port
      return Number.isInteger(port) && (port as number) > 0 && (port as number) < 65536 ? (port as number) : undefined
    }
    this.devices.onDescribed = () => networkAPI.onStateChanged?.()
    networkAPI.coordinator = () => this.hubNetNode.value
    const port = listenPort(address)
    if (port) networkAPI.hubPort = port
    this.devices.networkState = id => networkAPI.deviceNetworkState(id)
    this.devices.overlay = id => networkAPI.deviceOverlay(id)
    this.devices.onRemoved = ({ id, revokedKeys }) => networkAPI.removeDevice(id, revokedKeys)
    // Grants and group membership decide calls, `hub/api` lists and share connections
    security.grants.onChange = changed => {
      networkAPI.handleGrantsChanged(changed)
      this.connectionsChanged()
    }
    security.members.onChange = group => {
      networkAPI.handleGroupMembershipChanged(group)
      security.group.infoSubscription.setNeedsUpdate()
      this.connectionsChanged()
    }
    this.ready = Promise.all([
      networkAPI.load(),
      this.header.load(),
      this.hubNetNode.load(),
      this.devices.load(security.hubKey),
      this.pairing.load(),
    ]).then(() => {
      // Everything is loaded: copies follow the stored links, and the launcher has its grant
      security.grants.chain = id => this.devices.registry.linkedChildren(id)
      security.grants.settleCopies()
      security.settleLauncher(key => this.devices.registry.isKeyRevoked(key))
      hubNetNode.setNeedsUpdate()
      networkAPI.onStateChanged?.()
    })

    // Built-in APIs by access class (protocol.md section 7); service paths are checked when forwarded
    this.channel.use((ctx, next) => {
      // A known client's way to its challenge: on a whitelisted hub an anonymous connection can do nothing else
      if (ctx.path !== 'hub/info' && !ctx.state.key && security.whitelist.enforced && !this.merger.connectionFor(ctx.sender)) {
        throw 'hub is not available'
      }
      if (builtinAccess(ctx.path)) security.checkBuiltin(this.caller(ctx.state, ctx.sender, ctx.context), ctx.path)
      return next()
    })

    this.connectionsChanged = () => {
      connectionsState.setNeedsUpdate()
      this.devices.devicesState.setNeedsUpdate()
      this.devices.liveDataState.setNeedsUpdate()
      sendUpdates()
    }
    this.devices.register(this.channel)
    this.channel
      .post('hub/info', async ({ body }) => {
        const nonce = body?.nonce
        if (nonce !== undefined && !isClientNonce(nonce)) throw 'invalid nonce'
        return {
          key: security.hubKey,
          protocol: 2,
          pro: true,
          mode: security.effectiveMode,
          challenge: security.nonces.issue(),
          ...(nonce === undefined ? {} : { proof: await signChallenge(hubInfoSignedData(security.hubKey!, nonce)) }),
        }
      })
      .post('hub/pair', async ({ body, state, sender }) => {
        if (!state.key || this.merger.connectionFor(sender)) throw 'unauthorized'
        // Asked before the code is used up: a child never becomes an owner
        if (state.certificate && this.devices.registry.isChild(state.certificate.deviceId)) throw 'an owner can not be a child'
        await this.pairing.verify(body?.code)
        this.addPairedOwner(state)
        return { owner: true, hubKey: security.hubKey, name: (await this.header.load()).name }
      })
      .post('hub/pair/new', async ({ sender }) => {
        // Owner-only as a built-in; a merged hub's caller is never one
        if (this.merger.connectionFor(sender)) throw 'permissions required'
        const code = await this.pairing.create()
        console.log(`Pairing code: ${code}`)
        return { code, expires: this.pairing.expires }
      })
      .stream('hub/security/mode', () => securityMode.makeIterator())
      .post('hub/security/mode/set', ({ body }) => {
        security.setMode({ mode: body?.mode, requireV1: body?.requireV1 })
        securityMode.setNeedsUpdate()
        sendUpdates()
      })
      .post('hub/api', ({ state, sender, context }) => this.allowedApi(this.caller(state, sender, context)))
      .post('hub/api/list', ({ state, sender, context }) => this.describedApi(this.caller(state, sender, context)))
      .stream('hub/api/list', ({ state }) => this.apiDescriptions.makeIterator(state))
      .stream('hub/net/list', () => hubNetList.makeIterator())
      .stream('hub/net/node', () => hubNetNode.makeIterator())
      .post('hub/net/node/set', async ({ body, state, path }) => {
        security.requireOwner(state, path)
        await this.hubNetNode.set(body)
        hubNetNode.setNeedsUpdate()
        networkAPI.onStateChanged?.()
      })
      // A label for this connection, for owners and callers of its services. It's never a device's name (protocol.md
      // section 13), and a device's request shows only what its certificate asks for
      .post('hub/profile/update', ({ body: { name, icon }, state }) => {
        if (icon) state.icon = icon
        if (name) state.name = name
        this.connectionsChanged()
      })
      .stream('hub/api', ({ state }) => this.apiList.makeIterator(state))
      .stream('hub/api/services', ({ body, state: { key, device } }) => {
        return this.serviceProviders.makeIterator(JSON.stringify([key, device, body]))
      })
      .post('hub/service/update', ({ body: { add, remove, addApps, removeApps, services, apps, reporter, draining }, state, sender }) => {
        if (reporter === true) this.devices.requestReporter(state)
        const context = this.merger.context()
        if (services && Array.isArray(services)) {
          const s = services as ServiceHeader[]
          state.apiDescriptions = readDescriptions(s)
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
        if (typeof draining === 'boolean') this.setDraining(sender, state, draining, context)
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
        // hub/status names each path's balancer: without this, apps showed the old one until the next request
        statusState.setNeedsUpdate()
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
        security.call.allow(key, allow, state.key)
        security.call.revoke(key, revoke)
        sendUpdates()
      })
      .stream('hub/call/pending', ({ state, path }) => {
        security.requireOwner(state, path)
        return security.call.pendingSubscription.makeIterator()
      })
      .post('hub/call/allowed', async ({ body: key, state, path }) => {
        security.requireOwner(state, path)
        return Array.from(security.call.allowed(key))
      })
      .post('hub/group/create', async ({ body, state, path }) => {
        security.requireOwner(state, path)
        return security.group.create(body)
      })
      .post('hub/group/rename', async ({ body: { group, name }, state, path }) => {
        security.requireOwner(state, path)
        security.group.rename(group, name)
        this.networkAPI?.handleGroupRenamed(group, name)
        security.members.subscription.setNeedsUpdate()
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
          security.group.replace(group, set, state.key)
        } else {
          security.group.update(group, add, remove, state.key)
        }
        sendUpdates()
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
      .stream('hub/groups', () => security.group.infoSubscription.makeIterator())
      .stream('hub/grants', () => security.grants.subscription.makeIterator())
      .post('hub/grant/add', ({ body, state }) => security.addGrant(body, state))
      .post('hub/grant/check', ({ body, state, sender }) => this.checkGrant(body, state, sender))
      .post('hub/grant/link', ({ body }) => {
        if (typeof body?.linked !== 'boolean') throw 'invalid linked'
        return security.grants.setLinked(body?.id, body.linked)
      })
      .post('hub/grant/remove', ({ body }) => security.removeGrant(body?.id))
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
        if (!service) throw HubError.notFound()
        const caller = this.caller(state, sender, context)
        if (!security.allowsCall(caller, path, service.isPublic)) throw HubError.forbidden()
        const selected = service.selectFor(context)
        let s = selected ?? service.next()
        if (!s) {
          s = await service.addPending()
          if (s) service.claimed(s)
        }
        if (!s) throw HubError.notFound()
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
      .streamOther(other, async ({ body, path, context, state, sender }) => {
        const service = services.get(path)
        if (!service) throw HubError.notFound()
        const caller = hub.caller(state, sender, context)
        if (!security.allowsCall(caller, path, service.isPublic)) throw HubError.forbidden()
        const selected = service.selectFor(context)
        let s = selected ?? service.next()
        if (!s) {
          s = await service.addPending()
          if (s) service.claimed(s)
        }
        if (!s) throw HubError.notFound()
        service.requests += 1
        requests += 1
        s.streams += 1
        statusState.setNeedsUpdate()
        const provider = s
        const forwarded: ForwardedStream = new ForwardedStream(provider.sender.values(path, body, { context: forwardedContext(context, caller) }), () => {
          provider.streams -= 1
          service.completed(provider)
          hub.forwarded.get(provider.sender)?.delete(forwarded)
        })
        let streams = hub.forwarded.get(provider.sender)
        if (!streams) hub.forwarded.set(provider.sender, (streams = new Set()))
        streams.add(forwarded)
        return forwarded
      })
      .onDisconnect((state, sender) => {
        // Streams this provider was serving would otherwise wait forever: end them so callers can resubscribe
        const streams = this.forwarded.get(sender)
        this.forwarded.delete(sender)
        streams?.forEach(stream => stream.fail(new HubError('service disconnected', 'unavailable')))
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
    this.ready.then(() => (this.server = this.channel.listen(address, {
        async state(headers: Record<string, string | undefined>): Promise<State> {
          const key = security.keys.verify(headers['auth'] ?? undefined, security.whitelist, {
            version: headers['v'],
            hubKey: security.hubKey,
            requireV1: security.refusesV0(),
            nonces: security.nonces,
            v1Keys: security.v1Keys,
            anonymousAllowed: true,
          })
          const state: State = {
            id: randomUUIDv7(),
            key,
            services: new Set<string>(),
            apps: new Set<string>(),
            ip: headers['x-hub-remote-ip'],
          }
          hub.devices.connect(state, headers)
          if (key && headers['v'] === '1') {
            state.v1 = true
            security.usedV1(state)
          }
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
      })))

    this.api = new Set([...Object.keys(this.channel.postApi.storage), ...Object.keys(this.channel.streamApi.storage)])
    for (const path of Object.keys(this.channel.postApi.storage)) this.builtinKinds.set(path, ['post'])
    for (const path of Object.keys(this.channel.streamApi.storage)) this.builtinKinds.set(path, [...(this.builtinKinds.get(path) ?? []), 'stream'])
    settings.data.merge.forEach(address => this.merger.connect(address, this))
  }
  stats() {
    this.services.map(a => a)
  }
  /** At start: a pairing code when the hub has no owners, see `Pairing.start`, in local mode too */
  async startPairing(): Promise<string | undefined> {
    await this.ready
    return this.pairing.start({ needed: security.members.members(ownersGroup).size === 0 })
  }
  /** `hub/pair` succeeded: the key and, with a certificate, its device (approved) join the owners */
  private addPairedOwner(state: State) {
    security.members.add(ownersGroup, keyMember(state.key!))
    const id = state.certificate?.deviceId
    if (id) {
      this.devices.approveConnection(state)
      security.members.add(ownersGroup, deviceMember(id))
    }
    if (state.v1) security.usedV1(state)
    this.connectionsChanged()
    console.log('Paired owner', state.key, id ? `on device ${id}` : '')
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
   * `hub/api/list`: the caller's paths with what their providers say about them (protocol.md section 15). Only
   * providers calls are routed to count, draining ones included, so a key waiting for approval describes nothing.
   */
  describedApi(caller: Caller): ApiDescription[] {
    return this.allowedApi(caller)
      .sort()
      .flatMap(path => {
        const service = this.services.get(path)
        const providers = service ? [...service.services, ...service.draining].map(provider => provider.state.apiDescriptions?.get(path)) : []
        return describePath(path, this.builtinKinds.get(path), providers)
      })
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
      service.add({ sender, state, enabled, sending: new Set(), streams: 0, limit: 0, reserved: 0, draining: state.draining === true }, context)
    })
    console.log('+', services.length, 'api')
  }
  /**
   * `hub/service/update { draining }`: while draining, the connection's paths take no new calls and its running calls
   * go on. A path whose last provider drains leaves `hub/api`; calls to it wait for another provider (`pendingWait`).
   */
  setDraining(sender: Sender, state: State, draining: boolean, context: ServiceUpdateContext) {
    state.draining = draining
    state.services.forEach(path => this.services.get(path)?.setDraining(sender, draining, context))
  }
  /**
   * `hub/grant/check { path, caller }` → `{ allowed }`: whether `path` is granted to `caller` (a request's
   * `context.hub.caller`, or `{ key?, device? }`), for permissions a service checks itself. Owners always are; grants
   * count unless the hub is locked down. Services ask about paths under the first segment of a path they registered,
   * owners about any path.
   */
  checkGrant(body: any, state: State, sender: Sender): { allowed: boolean } {
    const path = body?.path
    if (typeof path !== 'string' || !path) throw new HubError('invalid path', 'invalid_input')
    if (!this.caller(state, sender).owner) {
      const scope = path.split('/')[0]
      if (!Array.from(state.services).some(registered => registered.split('/')[0] === scope)) throw HubError.forbidden()
    }
    const subject = body?.caller
    const key = typeof subject?.key === 'string' ? subject.key : undefined
    const device = typeof subject?.device === 'string' ? subject.device : typeof subject?.device?.id === 'string' ? subject.device.id : undefined
    let caller = security.caller({ key, device })
    // A caller through a merged hub is never an owner here, as when its call was forwarded
    if (subject?.via !== undefined) caller = { ...caller, groups: caller.groups.filter(group => group !== ownersGroup), owner: false }
    return { allowed: caller.owner || (!security.lockdown && security.granted(caller, path)) }
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
          // A device still asking holds no name yet
          name: c.state.certificate && !c.state.device ? undefined : c.state.name,
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

/**
 * A provider's stream as the hub passes it on. Cancelling it cancels the provider's stream at once, also while a
 * value is pending: an async generator would only see `return()` once the provider sent its next value.
 */
class ForwardedStream implements AsyncIterator<any, void, any> {
  private finished = false
  private stop!: (result: IteratorResult<any, void>) => void
  private abort!: (error: unknown) => void
  private readonly stopped = new Promise<IteratorResult<any, void>>((resolve, reject) => {
    this.stop = resolve
    this.abort = reject
  })
  constructor(
    private readonly values: AsyncIterator<any, void, any>,
    private readonly onFinish: () => void,
  ) {
    // A failure nobody is waiting for yet isn't unhandled: the next `next()` sees it
    this.stopped.catch(() => {})
  }
  /** Ends the stream for the caller with `error` (its provider went away) */
  fail(error: unknown) {
    if (this.finished) return
    this.finish()
    this.abort(error)
    void Promise.resolve(this.values.return?.()).catch(() => {})
  }
  next(): Promise<IteratorResult<any, void>> {
    if (this.finished) return Promise.resolve({ done: true, value: undefined })
    return Promise.race([this.values.next(), this.stopped]).then(
      result => {
        if (result.done) this.finish()
        return result
      },
      error => {
        this.finish()
        throw error
      },
    )
  }
  async return(): Promise<IteratorResult<any, void>> {
    if (!this.finished) {
      this.finish()
      this.stop({ done: true, value: undefined })
      await this.values.return?.()
    }
    return { done: true, value: undefined }
  }
  private finish() {
    if (this.finished) return
    this.finished = true
    this.onFinish()
  }
}

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
  /** Handed to waiting calls that haven't started yet; counts against `limit` */
  reserved: number
  /** Takes no new calls, see `Hub.setDraining` */
  draining: boolean
}

/** How long a call waits for a provider of its path before failing with `api not available` */
export const pendingWait = { timeout: 30_000 }

interface Waiter {
  resolve(service: Service | undefined): void
  reject(error: HubError): void
  timer: ReturnType<typeof setTimeout>
}

class Services {
  name: string
  requests = 0
  services: Service[] = []
  disabled: Service[] = []
  /** Enabled providers that take no new calls; their running calls go on */
  draining: Service[] = []
  /** Calls waiting for a provider, oldest first */
  pending: Waiter[] = []
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
    if (service.enabled && service.draining) {
      if (!this.draining.some(a => a.sender === service.sender)) this.draining.push(service)
    } else if (service.enabled) {
      if (this.services.findIndex(a => a.sender === service.sender) === -1) {
        this.loadBalancer.add(this.services, service)
        this.enableServiceIfNeeded(context)
        this.drain()
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
      this.drain()
      return
    }
    const other = this.disabled.find(a => a.sender === sender) ?? this.draining.find(a => a.sender === sender)
    if (other) other.limit = limit
  }
  /** Moves an enabled provider out of or back into load balancing, keeping its running calls */
  setDraining(sender: Sender, draining: boolean, context: ServiceUpdateContext) {
    const disabled = this.disabled.find(a => a.sender === sender)
    if (disabled) {
      disabled.draining = draining
      return
    }
    if (draining) {
      const service = this.loadBalancer.remove(this.services, sender)
      if (!service) return
      service.draining = true
      this.draining.push(service)
      // Waiting calls keep waiting for another provider
      if (this.isEnabled && !this.services.length) {
        this.isEnabled = false
        context.remove(this.name)
      }
    } else {
      const index = this.draining.findIndex(a => a.sender === sender)
      if (index === -1) return
      const [service] = this.draining.splice(index, 1)
      service.draining = false
      this.loadBalancer.add(this.services, service)
      this.enableServiceIfNeeded(context)
      this.drain()
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
    if (!onDevice.length) throw HubError.notFound()
    return onDevice.reduce((a, b) => (b.sending.size + b.streams < a.sending.size + a.streams ? b : a))
  }
  allowKey(key: string, context: ServiceUpdateContext): number {
    let enabled = new Set<Service>()
    this.disabled.forEach(s => {
      if (s.state.key !== key) return
      enabled.add(s)
      s.enabled = true
      if (s.draining) return void this.draining.push(s)
      this.loadBalancer.add(this.services, s)
      this.enableServiceIfNeeded(context)
    })
    if (!enabled.size) return 0
    this.disabled = this.disabled.filter(a => !enabled.has(a))
    this.drain()
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
    for (const service of this.draining.filter(s => s.state.key === key)) {
      this.draining.splice(this.draining.indexOf(service), 1)
      service.enabled = false
      this.disabled.push(service)
      disabled.push(service)
      service.sending.forEach(a => a.cancel())
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
    return [this.services, this.draining].some(list => list.some(service => this.publicSenders.has(service.sender)))
  }
  remove(sender: Sender, context: ServiceUpdateContext) {
    this.publicSenders.delete(sender)
    const drainingIndex = this.draining.findIndex(a => a.sender === sender)
    const s = this.loadBalancer.remove(this.services, sender) ?? (drainingIndex >= 0 ? this.draining.splice(drainingIndex, 1)[0] : undefined)
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
    const pending = this.pending
    this.pending = []
    for (const waiter of pending) {
      clearTimeout(waiter.timer)
      waiter.resolve(undefined)
    }
  }
  private _next(): Service | undefined {
    return this.loadBalancer.next(this.services)
  }
  /** A provider for a new call. Older waiting calls are served first; a provider left over goes to this one. */
  next(): Service | undefined {
    this.drain()
    if (this.pending.length > 0) return
    return this._next()
  }
  /**
   * Waits for a provider; `next()` had none. Fails with `api not available` after `pendingWait.timeout` or when
   * `pendingLimit` newer calls push it out. The caller passes the provider it gets to `claimed`.
   */
  addPending(): Promise<Service | undefined> {
    return new Promise((resolve, reject) => {
      const waiter: Waiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const index = this.pending.indexOf(waiter)
          if (index === -1) return
          this.pending.splice(index, 1)
          reject(HubError.unavailable())
        }, pendingWait.timeout),
      }
      this.pending.push(waiter)
      if (settings.data.pendingLimit > 0) {
        const evicted = this.pending.splice(0, Math.max(0, this.pending.length - settings.data.pendingLimit))
        for (const old of evicted) {
          clearTimeout(old.timer)
          old.reject(HubError.unavailable())
        }
      }
    })
  }
  /** Hands free providers to waiting calls, oldest first, reserving each until its call starts */
  private drain() {
    while (this.pending.length) {
      const service = this._next()
      if (!service) return
      const waiter = this.pending.shift()!
      clearTimeout(waiter.timer)
      service.reserved += 1
      waiter.resolve(service)
    }
  }
  /** A waiting call got `service` and starts now */
  claimed(service: Service) {
    if (service.reserved > 0) service.reserved -= 1
  }
  get status(): ServicesStatus {
    return {
      name: this.name,
      services: this.services.length,
      disabled: this.disabled.length,
      requests: this.requests,
      balancer: this.loadBalancer.name,
      pending: this.pending.length,
      running: [...this.services, ...this.draining].reduce((a, b) => a + b.sending.size + b.streams, 0),
      ...(this.draining.length ? { draining: this.draining.length } : {}),
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
  /** A call on `service` ended, so it may take a waiting one */
  completed(service: Service) {
    this.drain()
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
  /** Which handler the description fields are about (protocol.md section 15), see `readDescriptions` */
  kind?: 'post' | 'stream'
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
  /** Providers that take no new calls */
  draining?: number
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
