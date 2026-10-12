import { randomUUIDv7 } from 'bun'
import type { NetworkPolicy, NetworkResource, LiveProvider, AgentProfile, AgentStatus, ConnectionStatus, ResourceGenerationSnapshot } from './wire'
import { Storage } from '../settings'
import { ObjectMap } from 'channel/channel'
import { OVERLAY_RANGES } from './foundation'

/**
 * Persistent Hub network registry.
 *
 * This stores:
 * - Hub network identity and ID
 * - Overlay address allocations
 * - Stable network resources (shares with policies)
 * - Resource generations for revocation
 *
 * Ephemeral state (agent profiles, live providers) is tracked separately.
 */
export class NetworkRegistry {
  storage: Storage
  data: RegistryData
  private needsMigration = false

  constructor(storagePath = 'data/network.json') {
    this.data = defaultRegistryData()
    this.storage = new Storage(
      storagePath,
      () => this.data,
      data => {
        this.needsMigration = data?.schemaVersion !== REGISTRY_SCHEMA_VERSION
        this.data = migrateRegistryData(data)
        assertUniqueAllocations(this.data.allocations)
      },
    )
  }

  async load(): Promise<this> {
    await this.storage.load()
    assertUniqueAllocations(this.data.allocations)
    const needsIdentity = !this.data.hubNetworkId
    if (needsIdentity) {
      this.data.hubNetworkId = this.generateHubNetworkId()
    }
    if (needsIdentity || this.needsMigration) {
      this.data.schemaVersion = REGISTRY_SCHEMA_VERSION
      await this.storage.save()
    }
    return this
  }

  private generateHubNetworkId(): string {
    return randomUUIDv7()
  }

  /**
   * Allocate overlay addresses to a network profile.
   * Returns one IPv4 and one IPv6 address, or throws if unavailable.
   */
  allocateAddresses(key: string): { ipv4: string; ipv6: string } {
    if (!key) throw new Error('profile key is required')
    if (this.data.allocations[key]) {
      const existing = this.data.allocations[key]
      return { ipv4: existing[0], ipv6: existing[1] }
    }

    const usedIPv4 = new Set(Object.values(this.data.allocations).map(addresses => addresses[0]))
    const usedIPv6 = new Set(Object.values(this.data.allocations).map(addresses => addresses[1]))
    let nextIPv4 = BigInt(this.data.nextIPv4)
    const lastIPv4 = BigInt(this.data.lastIPv4)
    let nextIPv6 = BigInt(this.data.nextIPv6)
    const lastIPv6 = BigInt(this.data.lastIPv6)

    while (nextIPv4 <= lastIPv4 && usedIPv4.has(formatAddress(nextIPv4))) nextIPv4++
    while (nextIPv6 <= lastIPv6 && usedIPv6.has(formatAddress(nextIPv6))) nextIPv6++

    if (nextIPv4 > lastIPv4 || nextIPv6 > lastIPv6) {
      throw new Error('overlay address exhausted')
    }

    const ipv4 = formatAddress(nextIPv4)
    const ipv6 = formatAddress(nextIPv6)

    this.data.nextIPv4 = (nextIPv4 + 1n).toString()
    this.data.nextIPv6 = (nextIPv6 + 1n).toString()

    this.data.allocations[key] = [ipv4, ipv6]
    this.storage.save()
    return { ipv4, ipv6 }
  }

  /**
   * Release addresses when a profile is disconnected.
   * Addresses remain reserved to the profile for stability.
   */
  releaseAddresses(key: string): void {
    // Keep allocation for stability - don't reuse within session
  }

  /**
   * Register or update a network resource.
   * Throws if resourceId collides with different owner.
   */
  registerResource(resource: NetworkResource): void {
    const existing = this.data.resources[resource.resourceId]
    if (existing && existing.ownerKey !== resource.ownerKey) {
      throw new Error('resource_id_collision')
    }
    this.data.resources[resource.resourceId] = resource
    this.storage.save()
  }

  /**
   * Get a network resource by ID.
   */
  getResource(resourceId: string): NetworkResource | undefined {
    return this.data.resources[resourceId]
  }

  /**
   * List all resources owned by a key.
   */
  listResources(ownerKey: string): NetworkResource[] {
    return Object.values(this.data.resources).filter(r => r.ownerKey === ownerKey)
  }

  /**
   * Update the policy and generation for a resource.
   */
  updateResource(resourceId: string, policy: NetworkPolicy, generation: number): void {
    const resource = this.data.resources[resourceId]
    if (!resource) throw new Error('resource not found')
    resource.policy = policy
    resource.generation = generation
    this.storage.save()
  }

  /**
   * Delete a resource.
   */
  deleteResource(resourceId: string): void {
    delete this.data.resources[resourceId]
    this.storage.save()
  }

  /**
   * Increment the generation for a resource (revocation).
   */
  incrementGeneration(resourceId: string): number {
    const resource = this.data.resources[resourceId]
    if (!resource) throw new Error('resource not found')
    resource.generation++
    this.storage.save()
    return resource.generation
  }

  /**
   * Get the current Hub network identity.
   */
  getIdentity(): { hubNetworkId: string; hubKey: string } {
    return {
      hubNetworkId: this.data.hubNetworkId,
      hubKey: this.data.hubKey,
    }
  }

  /**
   * Set the Hub public key for signing grants and tickets.
   */
  setHubKey(hubKey: string): void {
    this.data.hubKey = hubKey
    this.storage.save()
  }
}

/**
 * Ephemeral agent profile registry.
 * Profiles exist only while their connection is active.
 */
export class AgentRegistry {
  profiles = new Map<string, AgentProfile>() // key -> profile
  private connectionAgents = new Map<string, Set<string>>() // connectionId -> agent keys
  private agentConnections = new Map<string, Set<string>>() // agent key -> connection IDs
  private connectionProviders = new Map<string, Set<string>>() // service connectionId -> provider IDs
  providers = new ObjectMap<string, LiveProvider>() // providerId -> provider
  connectionStatus = new Map<string, ConnectionStatus>() // resourceId -> status
  agentStatus = new Map<string, AgentStatus>() // key -> status
  /**
   * Latest generation snapshot pushed to each connected agent for a resource.
   * Keyed by key so revocation reaches only the affected target/caller
   * agents rather than every connection.
   */
  private agentResourceGenerations = new Map<string, Map<string, ResourceGenerationSnapshot>>()

  /**
   * Register or update an agent profile.
   * Profiles are tied to authenticated connections.
   */
  registerProfile(profile: AgentProfile, connectionId?: string): void {
    const existing = this.profiles.get(profile.key)
    if (existing && existing.key !== profile.key) throw new Error('key mismatch')
    this.profiles.set(profile.key, profile)
    if (connectionId) {
      const agents = this.connectionAgents.get(connectionId) ?? new Set<string>()
      agents.add(profile.key)
      this.connectionAgents.set(connectionId, agents)
      const connections = this.agentConnections.get(profile.key) ?? new Set<string>()
      connections.add(connectionId)
      this.agentConnections.set(profile.key, connections)
    }
    const status: AgentStatus = {
      version: profile.version,
      key: profile.key,
      available: true,
      addresses: profile.overlayAddresses,
      peers: 0,
      shares: 0,
      updatedAt: new Date().toISOString(),
    }
    this.agentStatus.set(profile.key, status)
  }

  /**
   * Unregister an agent profile on disconnect.
   */
  unregisterProfile(key: string): void {
    const connections = this.agentConnections.get(key)
    if (connections) {
      for (const connectionId of connections) {
        const agents = this.connectionAgents.get(connectionId)
        agents?.delete(key)
        if (agents?.size === 0) this.connectionAgents.delete(connectionId)
      }
      this.agentConnections.delete(key)
    }
    const profile = this.profiles.get(key)
    if (profile) {
      this.profiles.delete(key)
      this.agentStatus.delete(key)
      this.agentResourceGenerations.delete(key)
      // Clean up all providers for this agent
      const providerIds: string[] = []
      this.providers.forEach((provider: LiveProvider, providerId: string) => {
        if (provider.key === key) {
          providerIds.push(providerId)
        }
      })
      for (const providerId of providerIds) {
        this.removeProvider(providerId)
      }
    }
  }

  /**
   * Remove only profiles registered by the disconnected authenticated connection.
   */
  unregisterConnection(connectionId: string): Set<string> {
    const removedKeys = new Set<string>()
    const keys = this.connectionAgents.get(connectionId)
    if (!keys) return removedKeys
    this.connectionAgents.delete(connectionId)
    for (const key of keys) {
      const connections = this.agentConnections.get(key)
      connections?.delete(connectionId)
      if (connections?.size) continue
      this.agentConnections.delete(key)
      this.unregisterProfile(key)
      removedKeys.add(key)
    }
    return removedKeys
  }

  /**
   * Get a profile by agent key.
   */
  getProfile(key: string): AgentProfile | undefined {
    return this.profiles.get(key)
  }

  /**
   * Resolve a network access principal by its persistent profile key.
   */
  getProfileByKey(key: string): AgentProfile | undefined {
    for (const profile of this.profiles.values()) {
      if (profile.key === key) return profile
    }
    return undefined
  }

  /**
   * List all profiles.
   */
  listProfiles(): AgentProfile[] {
    return Array.from(this.profiles.values())
  }

  /**
   * Register or update a live provider for a resource.
   */
  registerProvider(provider: LiveProvider, connectionId?: string): void {
    this.providers.set(provider.providerId, provider)
    if (connectionId) {
      const providerIds = this.connectionProviders.get(connectionId) ?? new Set<string>()
      providerIds.add(provider.providerId)
      this.connectionProviders.set(connectionId, providerIds)
    }
    // Update agent share count
    const status = this.agentStatus.get(provider.key)
    if (status) {
      let count = 0
      this.providers.forEach((p: LiveProvider) => {
        if (p.key === provider.key) count++
      })
      status.shares = count
      status.updatedAt = new Date().toISOString()
    }
  }

  /**
   * Remove a live provider.
   */
  removeProvider(providerId: string): void {
    const provider = this.providers.get(providerId)
    if (provider) {
      this.providers.delete(providerId)
      const status = this.agentStatus.get(provider.key)
      if (status) {
        let count = 0
        this.providers.forEach((p: LiveProvider) => {
          if (p.key === provider.key) count++
        })
        status.shares = count
        status.updatedAt = new Date().toISOString()
      }
      for (const [connectionId, providerIds] of this.connectionProviders) {
        providerIds.delete(providerId)
        if (providerIds.size === 0) this.connectionProviders.delete(connectionId)
      }
    }
  }

  /**
   * Remove live providers published by a disconnected service connection.
   * Stable resources remain persisted by NetworkRegistry.
   */
  unregisterProviderConnection(connectionId: string): void {
    const providerIds = this.connectionProviders.get(connectionId)
    if (!providerIds) return
    this.connectionProviders.delete(connectionId)
    for (const providerId of [...providerIds]) this.removeProvider(providerId)
  }

  /**
   * Remove providers published by a connection whose resource is not in
   * `keepResourceIds`. Used by atomic share replacement so a republished
   * connection stops advertising providers for shares it dropped or whose
   * target changed. Providers for kept resources are refreshed by the caller
   * via {@link registerProvider}.
   */
  pruneConnectionProviders(connectionId: string, keepResourceIds: Set<string>): void {
    const providerIds = this.connectionProviders.get(connectionId)
    if (!providerIds) return
    for (const providerId of [...providerIds]) {
      const provider = this.providers.get(providerId)
      if (provider && !keepResourceIds.has(provider.resourceId)) {
        this.removeProvider(providerId)
      }
    }
  }

  /**
   * Remove the complete provider snapshot owned by a service connection.
   * Callers invoke this only after validating the replacement request in full.
   */
  clearConnectionProviders(connectionId: string): void {
    this.unregisterProviderConnection(connectionId)
  }

  /**
   * Get providers for a resource.
   */
  getProviders(resourceId: string): LiveProvider[] {
    const result: LiveProvider[] = []
    this.providers.forEach((p: LiveProvider) => {
      if (p.resourceId === resourceId) {
        result.push(p)
      }
    })
    return result
  }

  /**
   * Select a provider for a resource.
   * If specific provider requested, use that; otherwise select deterministically.
   */
  selectProvider(resourceId: string, preferredProviderId?: string): LiveProvider | undefined {
    const providers = this.getProviders(resourceId)
    if (providers.length === 0) return undefined

    if (preferredProviderId) {
      return providers.find(p => p.providerId === preferredProviderId)
    }

    // Deterministic selection: first by connected time, then by providerId
    const sorted = [...providers].sort((a, b) => {
      if (a.connectedAt !== b.connectedAt) {
        return a.connectedAt < b.connectedAt ? -1 : 1
      }
      return a.providerId < b.providerId ? -1 : 1
    })
    return sorted[0]
  }

  /**
   * Update connection status for a resource.
   */
  updateConnectionStatus(resourceId: string, status: ConnectionStatus): void {
    this.connectionStatus.set(resourceId, status)
  }

  /**
   * Get connection status for a resource.
   */
  getConnectionStatus(resourceId: string): ConnectionStatus | undefined {
    return this.connectionStatus.get(resourceId)
  }

  /**
   * List all agent statuses.
   */
  listAgentStatus(): AgentStatus[] {
    return Array.from(this.agentStatus.values())
  }

  /**
   * List all connection statuses.
   */
  listConnectionStatus(): ConnectionStatus[] {
    return Array.from(this.connectionStatus.values())
  }

  /**
   * Record the latest generation snapshot to deliver to a connected agent and
   * return the snapshot so the API layer can push it immediately. Subsequent
   * reads through {@link stagedGenerations} return the same snapshot until the
   * agent disconnects.
   */
  stageGeneration(key: string, snapshot: ResourceGenerationSnapshot): ResourceGenerationSnapshot {
    let byResource = this.agentResourceGenerations.get(key)
    if (!byResource) {
      byResource = new Map()
      this.agentResourceGenerations.set(key, byResource)
    }
    byResource.set(snapshot.resourceId, snapshot)
    return snapshot
  }

  /**
   * All resource generations currently staged for an agent, without clearing.
   * The streaming API reads this to deliver revocation updates; the stream
   * dedupes identical snapshots so agents only act on actual generation
   * changes. Staged entries are cleared when the agent profile is removed.
   */
  stagedGenerations(key: string): ResourceGenerationSnapshot[] {
    const byResource = this.agentResourceGenerations.get(key)
    return byResource ? Array.from(byResource.values()) : []
  }
}

/**
 * Network permission evaluator.
 * Separate from RPC permissions.
 */
export class NetworkPermissions {
  /**
   * Check if a profile key is authorized for a resource.
   */
  isAuthorized(
    key: string,
    resource: NetworkResource,
    isHubOwner: boolean,
    groupMembers: Set<string>,
  ): boolean {
    const policy = resource.policy

    // Disabled means not connectable, including by resource and Hub owners.
    if (policy.mode === 'disabled') return false

    // Hub owners and a profile using the resource owner's identity can access
    // every other policy mode.
    if (isHubOwner || key === resource.ownerKey) return true

    switch (policy.mode) {
      case 'hub':
        // All authenticated profiles on the Hub
        return key !== ''

      case 'group':
        // Members of a specific Hub group
        return groupMembers.has(key)

      case 'keys':
        // Explicit list of profile keys
        return policy.keys.includes(key)

      case 'private':
        return false

      default:
        return false
    }
  }

  /**
   * Validate a network policy.
   */
  validatePolicy(policy: NetworkPolicy): void {
    switch (policy.mode) {
      case 'group':
        if (!policy.group) throw new Error('group policy requires group name')
        break
      case 'keys':
        if (!policy.keys || policy.keys.length === 0) {
          throw new Error('keys policy requires at least one key')
        }
        break
    }
  }
}

function parseAddress(ip: string): bigint {
  if (ip.includes('.')) {
    // IPv4
    const parts = ip.split('.')
    return BigInt(
      (parseInt(parts[0]) << 24) |
        (parseInt(parts[1]) << 16) |
        (parseInt(parts[2]) << 8) |
        parseInt(parts[3]),
    )
  } else {
    // IPv6 - expand :: and parse as 128-bit number
    const parts = ip.split(':')

    // Find the :: compression
    const doubleColonIndex = parts.indexOf('')
    let fullHextets: string[]

    if (doubleColonIndex === -1) {
      // No compression, use as-is
      fullHextets = parts
    } else {
      // Expand :: - count parts before and after
      const before = parts.slice(0, doubleColonIndex)
      const after = parts.slice(doubleColonIndex + 1)
      const zerosNeeded = 8 - (before.length + after.length)

      fullHextets = [...before, ...Array(zerosNeeded).fill('0'), ...after]
    }

    // Parse as 128-bit number
    let result = 0n
    for (let i = 0; i < fullHextets.length && i < 8; i++) {
      const value = BigInt(parseInt(fullHextets[i] || '0', 16))
      result = (result << 16n) | value
    }
    return result
  }
}

function formatAddress(num: bigint): string {
  if (num <= 0xffffffffn) {
    // IPv4
    const n = Number(num)
    return `${(n >> 24) & 0xff}.${(n >> 16) & 0xff}.${(n >> 8) & 0xff}.${n & 0xff}`
  } else {
    // IPv6 - format as standard 8 hextets, then compress
    const hex = num.toString(16).padStart(32, '0')
    const parts: string[] = []
    for (let i = 0; i < 8; i++) {
      parts.push(hex.slice(i * 4, (i + 1) * 4))
    }
    // Compress the longest run of zeros
    let maxZeroStart = -1
    let maxZeroLength = 0
    let currentZeroStart = -1
    let currentZeroLength = 0

    for (let i = 0; i < parts.length; i++) {
      if (parts[i] === '0000') {
        if (currentZeroStart === -1) {
          currentZeroStart = i
        }
        currentZeroLength++
      } else {
        if (currentZeroLength > maxZeroLength) {
          maxZeroStart = currentZeroStart
          maxZeroLength = currentZeroLength
        }
        currentZeroStart = -1
        currentZeroLength = 0
      }
    }
    if (currentZeroLength > maxZeroLength) {
      maxZeroStart = currentZeroStart
      maxZeroLength = currentZeroLength
    }

    if (maxZeroLength > 1) {
      const before = parts.slice(0, maxZeroStart).map(p => p.replace(/^0+(?!$)/, '')).join(':')
      const after = parts
        .slice(maxZeroStart + maxZeroLength)
        .map(p => p.replace(/^0+(?!$)/, ''))
        .join(':')
      return `${before}::${after}`
    }

    return parts.map(p => p.replace(/^0+(?!$)/, '')).join(':')
  }
}

const REGISTRY_SCHEMA_VERSION = 1

function defaultRegistryData(): RegistryData {
  return {
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    hubNetworkId: '',
    hubKey: '',
    nextIPv4: parseAddress(OVERLAY_RANGES.ipv4.first).toString(),
    lastIPv4: parseAddress(OVERLAY_RANGES.ipv4.last).toString(),
    nextIPv6: parseAddress(OVERLAY_RANGES.ipv6.first).toString(),
    lastIPv6: parseAddress(OVERLAY_RANGES.ipv6.last).toString(),
    resources: {},
    allocations: {},
  }
}

function migrateRegistryData(data: Partial<RegistryData> | undefined): RegistryData {
  const defaults = defaultRegistryData()
  return {
    ...defaults,
    ...data,
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    resources: data?.resources ?? {},
    allocations: data?.allocations ?? {},
  }
}

function assertUniqueAllocations(allocations: Record<string, string[]>): void {
  const seen = new Map<string, string>()
  for (const [key, addresses] of Object.entries(allocations)) {
    if (addresses.length !== 2 || !addresses[0] || !addresses[1]) {
      throw new Error(`invalid overlay allocation for ${key}`)
    }
    for (const address of addresses) {
      const allocatedTo = seen.get(address)
      if (allocatedTo && allocatedTo !== key) {
        throw new Error(`duplicate overlay allocation: ${address}`)
      }
      seen.set(address, key)
    }
  }
}

export interface RegistryData {
  schemaVersion: number
  hubNetworkId: string
  hubKey: string
  nextIPv4: string // BigInt as string for JSON serialization
  lastIPv4: string // BigInt as string for JSON serialization
  nextIPv6: string // BigInt as string for JSON serialization
  lastIPv6: string // BigInt as string for JSON serialization
  resources: Record<string, NetworkResource>
  allocations: Record<string, string[]>
}
