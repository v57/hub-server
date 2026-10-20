import { type Channel } from 'channel/server'
import { LazyStates } from 'channel/more'
import type { State } from '../hub'
import { Security } from '../security'
import { NetworkAPI } from './api'
import type * as Wire from './wire'
import { HUB_NETWORK_WIRE_VERSION } from './wire'

export const appleAgentProtectedApi = {
  'hub/net/apple-agent/bind': 'Hub Network: Bind Apple Local Agent',
  'hub/net/apple-agent/renew': 'Hub Network: Renew Apple Local Agent',
  'hub/net/apple-agent/unbind': 'Hub Network: Unbind Apple Local Agent',
} as const

export function appleAgentAPIsEnabled(
  env: Record<string, string | undefined> = Bun.env,
): boolean {
  const enabled = env.HUB_NET_APPLE_AGENT_ENABLED?.trim().toLowerCase()
  if (enabled === 'false' || enabled === '0' || enabled === 'off') return false
  const version = env.HUB_NET_APPLE_AGENT_PROTOCOL_VERSION?.trim()
  return version === undefined || version === String(HUB_NETWORK_WIRE_VERSION)
}

/**
 * Network Hub integration.
 *
 * This module integrates Hub Network APIs into the Hub server.
 * It adds endpoints for:
 * - Network share registration
 * - Agent profile registration
 * - Resource and provider management
 * - Connection grants and rendezvous tickets
 * - Permission-filtered streams
 */

export const networkProtectedApi = {
  'network/shares/replace': 'Hub Network: Manage Shares',
  'network/shares/published': 'Hub Network: Manage Shares',
  'hub/net/bind': 'Hub Network: Bind Agent',
  'network/connection/grant': 'Hub Network: Connection Grant',
  'network/rendezvous/ticket': 'Hub Network: Rendezvous Ticket',
  'network/resource/update': 'Hub Network: Manage Resources',
  'network/resource/revoke': 'Hub Network: Manage Resources',
  'network/resource/list': 'Hub Network: View Resources',
  'network/resource/generations': 'Hub Network: View Status',
  'network/providers/list': 'Hub Network: View Resources',
  'network/agents/list': 'Hub Network: View Agents',
  'network/status/agents': 'Hub Network: View Status',
  'network/status/connections': 'Hub Network: View Status',
  'network/diagnostics': 'Hub Network: View Status',
  'hub/net/local-agent': 'Hub Network: View Local Agent',
  'hub/net/local-agent/rebind': 'Hub Network: Rebind Local Agent',
  'hub/net/node/set': 'Hub Network: Configure Node',
  'network/gateway/advertise': 'Hub Network: Provide Gateway',
  'network/gateway/remove': 'Hub Network: Provide Gateway',
  'network/gateway/list': 'Hub Network: Use Gateway',
  'network/gateway/grant': 'Hub Network: Use Gateway',
  'network/gateway/revocations': 'Hub Network: Use Gateway',
  'network/gateway/diagnostics': 'Hub Network: View Status',
} as const

/**
 * Export network API paths for ownership checks.
 * These should be added to the Security ownerApi set.
 */
export const networkOwnerApi = Object.keys(networkProtectedApi)

// In-memory cross-machine test completion mailbox used by the HUBTESTENV
// harness: clients post completion through the bootstrap tunnel, hosts poll
// the stream. No persistence; test-only surface.
const hubNetTestResults = new Map<string, HubNetTestCompletion>()

interface HubNetTestCompletion {
  key: string
  result: string
  completedAt: string
}

export function channelErrorMessage(error: unknown): string {
  if (error && typeof error === 'object') {
    const value = error as { code?: unknown; message?: unknown }
    if (typeof value.message === 'string') {
      return typeof value.code === 'string'
        ? `${value.code}: ${value.message}`
        : value.message
    }
  }
  return String(error)
}

export function registerNetworkAPIs(
  channel: Channel<any>,
  security: Security,
  networkAPI: NetworkAPI,
  appleAgentEnabled = appleAgentAPIsEnabled(),
): NetworkAPI {
  // Network shares replacement - atomically replace published shares
  channel.post('network/shares/replace', async ({ body, sender, state }) => {
    const publications = networkAPI.handleSharesReplace(body.shares, sender, state)
    return { shares: publications }
  })

  // Stream for published shares updates
  const publishedState = new LazyStates<State, Wire.LiveProvider[]>(state =>
    networkAPI.agents.providers
      .map(provider => provider)
      .filter(provider => provider.serviceKey === state.key || security.isOwner(state)),
  )
  channel.stream('network/shares/published', ({ state }) => publishedState.makeIterator(state))

  // Agent profile registration
  channel.post('hub/net/bind', async ({ body, sender, state, path }) => {
    return await networkAPI.bindAgent(body, sender, state, path)
  })

  const localAgentState = new LazyStates<State, Wire.LocalAgentBindingStatus>(
    () => networkAPI.localAgent.status(),
  ).dedupe('json')
  channel.stream('hub/net/local-agent', ({ state }) => {
    if (!security.isOwner(state)) throw 'Permissions required'
    return localAgentState.makeIterator(state)
  })
  channel.post('hub/net/local-agent/rebind', async ({ body, state, path }) => {
    security.requireOwner(state, path)
    await networkAPI.localAgent.authorizeRebind(body.key)
    localAgentState.setNeedsUpdate()
    return { success: true }
  })
  if (appleAgentEnabled) {
    channel.post('hub/net/apple-agent/bind', ({ body, state, path }) => {
      const status = networkAPI.bindAppleAppAgent(body, state, path)
      localAgentState.setNeedsUpdate()
      return { success: true, status, hubKey: networkAPI.registry.getIdentity().hubKey }
    })
    channel.post('hub/net/apple-agent/renew', ({ body, state, path }) => {
      const status = networkAPI.renewAppleAppAgent(body, state, path)
      localAgentState.setNeedsUpdate()
      return { success: true, status }
    })
    channel.post('hub/net/apple-agent/unbind', ({ body, state, path }) => {
      const status = networkAPI.unbindAppleAppAgent(body, state, path)
      localAgentState.setNeedsUpdate()
      return { success: true, status }
    })
  }
  // Connection grant issuance
  channel.post('network/connection/grant', async ({ body, state }) => {
    const grant = await networkAPI.issueConnectionGrant(
      body.callerWireGuardKey,
      body.resourceId,
      body.preferredProviderId,
      state,
    )
    return { grant }
  })

  // Rendezvous ticket issuance
  channel.post('network/rendezvous/ticket', async ({ body, state }) => {
    const ticket = await networkAPI.issueRendezvousTicket(
      body.nodeId,
      body.roles ?? ['rendezvous'],
      state,
    )
    return { ticket }
  })

  channel.post('network/gateway/advertise', ({ body, state }) => {
    try {
      return {
        status: networkAPI.advertiseGateway(body.capability, body.endpoint, state),
      }
    } catch (error) {
      throw channelErrorMessage(error)
    }
  })
  channel.post('network/gateway/remove', ({ body, state }) => {
    try {
      return {
        revocation: networkAPI.removeGateway(body?.reason ?? 'provider_disabled', state),
      }
    } catch (error) {
      throw channelErrorMessage(error)
    }
  })
  channel.post('network/gateway/grant', async ({ body, state }) => ({
    grant: await networkAPI.issueGatewayGrant(
      body.clientKey,
      body.clientWireGuardKey,
      body.gatewayKey,
      { ipv4: body.ipv4, ipv6: body.ipv6, dns: body.dns },
      state,
    ),
  }))
  const gatewayState = new LazyStates<State, Wire.GatewayStatus[]>(
    state => networkAPI.listGateways(state),
  ).dedupe('json')
  channel.stream('network/gateway/list', ({ state }) => gatewayState.makeIterator(state))
  const gatewayRevocations = new LazyStates<State, Wire.GatewayRevocation[]>(
    state => networkAPI.listGatewayRevocations(state),
  ).dedupe('json')
  channel.stream('network/gateway/revocations', ({ state }) => gatewayRevocations.makeIterator(state))
  const gatewayDiagnostics = new LazyStates<State, Wire.GatewayDiagnostic[]>(
    state => networkAPI.listGatewayDiagnostics(state),
  ).dedupe('json')
  channel.stream('network/gateway/diagnostics', ({ state }) => gatewayDiagnostics.makeIterator(state))

  // Resource policy update
  channel.post('network/resource/update', async ({ body, state }) => {
    networkAPI.updateResourcePolicy(body.resourceId, body.policy, state)
    return { success: true }
  })

  // Resource revocation
  channel.post('network/resource/revoke', async ({ body, state }) => {
    const newGeneration = networkAPI.revokeResource(body.resourceId, state)
    return { generation: newGeneration }
  })

  // List resources (permission-filtered)
  const resourcesState = new LazyStates<State, Wire.NetworkResource[]>(state => networkAPI.listResources(state))
  channel.stream('network/resource/list', ({ state }) => resourcesState.makeIterator(state))

  // Generation snapshots for the connected agent. Pulsed on revocation or
  // policy change so target agents terminate flows whose grant generation is
  // now stale. Deduped by JSON so an unchanged snapshot is not re-sent.
  const generationsState = new LazyStates<State, Wire.ResourceGenerationSnapshot[]>(state =>
    networkAPI.currentGenerations(state),
  ).dedupe('json')
  networkAPI.onGenerationChanged = () => generationsState.setNeedsUpdate()
  channel.stream('network/resource/generations', ({ state }) => generationsState.makeIterator(state))

  // Live providers for a resource. Each iterator retains its authenticated
  // state and requested resource while shared mutations pulse all subscribers.
  type ProviderStreamKey = { state: State; resourceId: string }
  const providersState = new LazyStates<ProviderStreamKey, Wire.LiveProvider[]>(
    ({ state, resourceId }) => networkAPI.listProviders(resourceId, state),
  ).dedupe('json')
  channel.stream('network/providers/list', ({ body, state }) =>
    providersState.makeIterator({ state, resourceId: body.resourceId }),
  )

  // List agents (permission-filtered)
  const agentsState = new LazyStates<State, Wire.AgentProfile[]>(state => networkAPI.listAgents(state))
  channel.stream('network/agents/list', ({ state }) => agentsState.makeIterator(state))
  channel.post('hub/net/test/complete', ({ body, state }) => {
    if (!state.key) throw 'unauthorized'
    const result = typeof body === 'string' ? body : String(body ?? '')
    const completion: HubNetTestCompletion = {
      key: state.key,
      result,
      completedAt: new Date().toISOString(),
    }
    hubNetTestResults.set(state.key, completion)
    return { success: true }
  })
  channel.stream('hub/net/test/results', ({ state }) => {
    if (!security.isOwner(state)) throw 'Permissions required'
    return (async function* () {
      for (const completion of hubNetTestResults.values()) {
        yield completion
      }
    })()
  })

  // Agent status stream
  const agentStatusState = new LazyStates<State, Wire.AgentStatus[]>(state => networkAPI.getAgentStatus(state))
  channel.stream('network/status/agents', ({ state }) => agentStatusState.makeIterator(state))

  // Connection status stream
  const connectionStatusState = new LazyStates<State, Wire.ConnectionStatus[]>(
    state => networkAPI.getConnectionStatus(state),
  ).dedupe('json')
  channel.stream('network/status/connections', ({ state }) => connectionStatusState.makeIterator(state))

  const diagnosticsState = new LazyStates<State, Wire.ConnectionStatus[]>(
    state => networkAPI.getDiagnostics(state),
  ).dedupe('json')
  channel.stream('network/diagnostics', ({ state }) => diagnosticsState.makeIterator(state))
  networkAPI.onStateChanged = () => {
    publishedState.setNeedsUpdate()
    resourcesState.setNeedsUpdate()
    providersState.setNeedsUpdate()
    agentsState.setNeedsUpdate()
    agentStatusState.setNeedsUpdate()
    connectionStatusState.setNeedsUpdate()
    diagnosticsState.setNeedsUpdate()
    localAgentState.setNeedsUpdate()
    gatewayState.setNeedsUpdate()
    gatewayRevocations.setNeedsUpdate()
    gatewayDiagnostics.setNeedsUpdate()
  }

  return networkAPI
}

export * from './wire'
