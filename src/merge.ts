import type { Hub } from './hub'
import { sign } from './keychain'
import { settings } from './settings'
import { FreshState } from './fresh-state'
import { Channel, type Sender } from 'channel/client'
import { randomBytes } from 'node:crypto'
import { verifyHubProof } from './nonces'

export class HubMerger {
  connections = new Map<string, Connection>()
  proxies = new Map<string, Connection>()
  state: FreshState<ConnectionStatus[]>
  hub: Hub
  constructor(hub: Hub) {
    this.hub = hub
    this.state = new FreshState<ConnectionStatus[]>(async () =>
      this.connections
        .values()
        .map(a => a.status)
        .toArray(),
    )
  }
  connect(address: string, hub: Hub, save: boolean = true) {
    if (this.connections.has(address)) return
    const connection = new Connection(address, hub, true)
    this.connections.set(address, connection)
    if (save) settings.addMerge(address)
    this.state.setNeedsUpdate()
  }
  disconnect(address: string) {
    const connection = this.connections.get(address)
    if (!connection) return
    this.connections.delete(address)
    connection.disconnect()
    settings.removeMerge(address)
    this.state.setNeedsUpdate()
  }
  connectProxy(address: string, hub: Hub, save: boolean = true) {
    if (this.proxies.has(address)) return
    const connection = new Connection(address, hub, false)
    this.proxies.set(address, connection)
    if (save) settings.addProxy(address)
  }
  disconnectProxy(address: string) {
    const connection = this.proxies.get(address)
    if (!connection) return
    this.proxies.delete(address)
    connection.disconnect()
    settings.removeProxy(address)
  }
  context(): ServiceUpdateContext {
    return new ServiceUpdateContext(this)
  }
  /** The merge or proxy connection a request arrived on, if it came from another hub */
  connectionFor(sender: Sender): Connection | undefined {
    for (const connection of this.connections.values()) if (connection.sender === sender) return connection
    for (const connection of this.proxies.values()) if (connection.sender === sender) return connection
  }
}

interface ConnectionStatus {
  address: string
  error?: string
  isConnected: boolean
}

export class ServiceUpdateContext {
  added: string[] = []
  removed: string[] = []
  merger: HubMerger
  isActive: boolean
  hasChanges = false
  constructor(merger: HubMerger) {
    this.merger = merger
    this.isActive = merger.connections.size > 0
  }
  get hub(): Hub {
    return this.merger.hub
  }
  add(service: string) {
    console.log('+', service)
    this.hasChanges = true
    this.hub.api.add(service)
    if (!this.isActive || !allows(service)) return
    this.added.push(service)
  }
  remove(service: string) {
    console.log('-', service)
    this.hasChanges = true
    this.hub.api.delete(service)
    if (!this.isActive) return
    this.removed.push(service)
  }
  applyChanges() {
    if (!this.hasChanges) return
    this.hub.apiList.setNeedsUpdate()
    this.hub.apiDescriptions.setNeedsUpdate()
    if (!this.isActive) return
    this.merger.connections.forEach(a => a.update(this.added, this.removed))
  }
}

export class Connection {
  address: string
  channel?: any
  error?: string
  /** The other hub's key, pinned once it proved it through `hub/info`. Tokens are bound to it. */
  hubKey?: string
  sender?: Sender
  constructor(address: string, hub: Hub, merge: boolean) {
    this.address = address
    this.hubKey = settings.data.mergeKeys[address]
    if (merge) {
      console.log('Merging to', address)
    } else {
      console.log('Proxying to', address)
    }
    const t = this
    this.channel = hub.channel.connect(this.address, {
      headers: () => t.headers(),
      async onConnect(sender) {
        t.sender = sender
        if (merge) {
          const add = Object.keys(hub.services.storage).filter(allows)
          if (!add.length) return
          try {
            await sender.send('hub/service/update', { add })
          } catch (error) {
            t.error = `${error}`
          }
        } else {
          console.log('joining proxy')
          await sender.send('hub/proxy/join')
          console.log('joined proxy')
        }
      },
    })
  }
  /**
   * Headers for the next attempt (protocol.md section 2): asks the other hub for a challenge on an anonymous
   * connection, pins its key once it proved it, and signs a token for that challenge alone. Waits while the other hub
   * doesn't answer, or doesn't prove the key it claims, since a token is never sent to one that hasn't.
   */
  private async headers(): Promise<Record<string, string>> {
    while (this.channel !== null) {
      try {
        const nonce = randomBytes(32).toString('base64url')
        const info = await this.askInfo(nonce)
        if (!verifyHubProof(info, nonce)) throw 'no proof of its key'
        if (this.hubKey && info.key !== this.hubKey) throw `key changed, pinned ${this.hubKey}`
        if (!this.hubKey) {
          this.hubKey = info.key
          settings.setMergeKey(this.address, info.key)
        }
        this.error = undefined
        return { auth: await sign(info.key, info.challenge), v: '1' }
      } catch (error) {
        this.error = `${error}`
        await Bun.sleep(5000)
      }
    }
    return {}
  }
  private async askInfo(nonce: string): Promise<any> {
    const probe = new Channel<any>().connect(this.address) as any
    try {
      return await probe.send('hub/info', { nonce }, { timeout: 10 })
    } finally {
      probe.stop()
    }
  }
  async update(add: string[], remove: string[]) {
    try {
      await this.channel?.send('hub/service/update', { add, remove })
    } catch (error) {
      this.error = `${error}`
    }
  }
  disconnect() {
    this.channel?.stop()
    this.channel = null
  }
  get status(): ConnectionStatus {
    return {
      address: this.address,
      error: this.error,
      isConnected: this.channel?.ws.isConnected ?? false,
    }
  }
}

function allows(service: string): boolean {
  return (
    !(service.startsWith('auth/') || service === 'auth' || service.startsWith('launcher/') || service === 'auth') ||
    service.startsWith('hub/') ||
    service === 'hub'
  )
}
