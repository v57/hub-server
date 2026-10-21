import type {
  NetworkShare,
  NetworkSharePublication,
  NetworkResource,
  LiveProvider,
  AgentProfile,
  ConnectionGrant,
  RendezvousTicket,
  NetworkPolicy,
  HubNetworkMessage,
  WireEnvelope,
  ResourceId,
  ResourceGenerationSnapshot,
  GatewayCapability,
  GatewayStatus,
  GatewayGrant,
  GatewayRevocation,
  GatewayDiagnostic,
  AppleAppAgentReadinessAssertion,
  AppleAppAgentUnbindRequest,
  AppleAppAgentBindRequest,
  AppleAppAgentRenewRequest,
  LocalAgentBindingStatus,
  DirectBootstrapResponse,
  RevokedDevice,
} from './wire'
import { networkError, HUB_NETWORK_WIRE_VERSION } from './wire'
import {
  CONNECTION_GRANT_MAX_LIFETIME_MS,
  RENDEZVOUS_TICKET_MAX_LIFETIME_MS,
  GATEWAY_GRANT_MAX_LIFETIME_MS,
  signatureInput,
  verifyEnvelope,
  validateAppleAppAgentReadiness,
  validateJoinAdmission,
} from './crypto'
import { randomUUIDv7 } from 'bun'
import { NetworkRegistry, AgentRegistry, NetworkPermissions } from './registry'
import { stableResourceId, canonicalAuthority, deviceAuthority } from './foundation'
import type { Sender } from 'channel/server'
import type { State } from '../hub'
import { publicKey, signChallenge } from '../keychain'
import { Security } from '../security'
import type { Grant } from '../grants'
import { createPublicKey } from 'crypto'
import { LocalAgentBindingStore } from './local-agent'
import type { AppleLocalAgentBinding } from './local-agent'

type ChallengeSigner = (challenge: Uint8Array) => Promise<string>

/**
 * Network permission APIs for hub-pro.
 *
 * These handle:
 * - Network share registration and attestation validation
 * - Policy management (hub, group, keys, private, disabled)
 * - Live provider tracking
 * - Connection grant issuance
 * - Rendezvous ticket issuance
 * - Permission-filtered streams
 */
export class NetworkAPI {
  registry: NetworkRegistry
  agents: AgentRegistry
  permissions: NetworkPermissions
  /**
   * Invoked whenever a resource generation changes (policy update or explicit
   * revocation). The Hub integration layer registers a callback that pulses the
   * `network/resource/generations` stream so connected agents can drain their
   * staged snapshots.
   */
  onGenerationChanged: ((resourceId: string) => void) | undefined
  onStateChanged: (() => void) | undefined
  private consumedAttestations = new Map<string, number>()
  private grantAgents = new Map<string, Set<string>>()
  private gateways = new Map<string, {
    status: GatewayStatus
    connectionId: string
    generation: number
  }>()
  private gatewayGenerations = new Map<string, number>()
  private gatewayRevocations = new Map<string, GatewayRevocation>()
  private gatewayGrantAgents = new Map<string, Set<string>>()
  /** Device of each connected agent key that bound from a device connection */
  private agentDevices = new Map<string, string>()
  /** Approves a pending device whose agent passed its bind proof (protocol.md section 10) */
  onBindApprove: ((state: State) => void) | undefined

  constructor(
    private security: Security,
    private challengeSigner: ChallengeSigner = signChallenge,
    readonly localAgent = new LocalAgentBindingStore(),
  ) {
    this.registry = new NetworkRegistry()
    this.agents = new AgentRegistry()
    this.permissions = new NetworkPermissions()
    this.localAgent.onAppleInvalidated = (binding, reason) => {
      this.onStateChanged?.()
    }
  }

  async load(): Promise<void> {
    await Promise.all([this.registry.load(), this.localAgent.load()])
    if (!this.registry.storage.corrupt) this.migratePolicies()
    // Set hub key from keychain
    const key = await publicKey()
    if (key) {
      this.registry.setHubKey(key)
    }
  }

  /**
   * Handle network share replacement.
   *
   * A service atomically replaces its complete published share set relative to
   * its previous registration on this connection. Resources whose stable
   * identity no longer appears in the new set, and providers previously
   * published by this connection, are removed so stale targets are no longer
   * authorized. Validation runs against the full request before any mutation,
   * so an invalid share leaves previously published providers untouched.
   */
  handleSharesReplace(
    shares: NetworkShare[],
    _sender: Sender,
    state: State,
  ): NetworkSharePublication[] {
    if (!state.key) {
      throw networkError('unauthorized', 'authentication required', false)
    }

    const { hubNetworkId } = this.registry.getIdentity()
    const ownerKey = state.key

    // Validate the entire request before mutating any state.
    const planned: Array<{
      resourceId: string
      resource: NetworkResource
      provider: LiveProvider
      publication: NetworkSharePublication
    }> = []
    const seenResourceIds = new Set<string>()

    for (const share of shares) {
      this.validateShare(share)
      const attestation = share.attestation
      const agentProfile = this.agents.getProfile(attestation.key)
      if (!agentProfile) {
        throw networkError('agent_unavailable', 'agent is not connected', false, {
          key: attestation.key,
        })
      }
      if (!this.verifyAttestation(attestation, share.name, share.protocol, share.target, ownerKey, agentProfile)) {
        throw networkError('invalid_attestation', 'service attestation is invalid or expired', false, {
          shareName: share.name,
        })
      }

      // The share's address is the service's device: only that device's agent may front it
      const agentDevice = this.agentDevices.get(attestation.key)
      if (state.device && agentDevice && agentDevice !== state.device) {
        throw networkError('share_device_mismatch', 'the agent runs on another device than the service', false, {
          shareName: share.name,
        })
      }

      const overlayAddress = agentProfile.overlayAddresses[0]
      if (!overlayAddress) {
        throw networkError('agent_unavailable', 'agent has no overlay address', false, {
          key: attestation.key,
        })
      }

      const resourceId = stableResourceId(ownerKey, share.name)
      if (seenResourceIds.has(resourceId)) {
        throw networkError('invalid_request', 'duplicate share name in replacement set', false, {
          shareName: share.name,
        })
      }
      seenResourceIds.add(resourceId)

      const existing = this.registry.getResource(resourceId)
      let policy: NetworkPolicy
      let generation: number
      if (existing) {
        if (existing.ownerKey !== ownerKey) {
          throw networkError('forbidden', 'resource owned by different key', false, { resourceId })
        }
        policy = existing.policy
        generation = existing.generation
      } else {
        policy = share.policy ?? { mode: 'private' }
        this.permissions.validatePolicy(policy)
        generation = 0
      }

      const authority = canonicalAuthority(hubNetworkId, ownerKey, share.name)
      const resource: NetworkResource = {
        version: HUB_NETWORK_WIRE_VERSION,
        resourceId,
        ownerKey,
        shareName: share.name,
        authority,
        policy,
        generation,
      }

      const providerId = randomUUIDv7()
      const provider: LiveProvider = {
        version: HUB_NETWORK_WIRE_VERSION,
        providerId,
        resourceId,
        serviceKey: ownerKey,
        key: attestation.key,
        protocol: share.protocol,
        overlayAddress,
        port: share.target.port,
        connectedAt: new Date().toISOString(),
      }

      const publication: NetworkSharePublication = {
        version: HUB_NETWORK_WIRE_VERSION,
        resourceId,
        authority,
        providerId,
        protocol: share.protocol,
        overlayAddress,
        port: share.target.port,
      }

      planned.push({ resourceId, resource, provider, publication })
    }

    // All validation passed. Remove providers previously published by this
    // connection whose resource is no longer in the new set, so the old target
    // is unauthorized after a dynamic port or share change.
    this.agents.clearConnectionProviders(state.id)

    // Apply the planned registrations atomically.
    const publications: NetworkSharePublication[] = []
    for (const [index, { resource, provider, publication }] of planned.entries()) {
      const isNew = !this.registry.getResource(resource.resourceId)
      this.registry.registerResource(resource)
      if (isNew) this.setPolicyGrants(resource, ownerKey)
      this.agents.registerProvider(provider, state.id)
      this.consumedAttestations.set(shares[index].attestation.attestationId, Date.parse(shares[index].attestation.expiresAt))
      publications.push(publication)
    }
    this.onStateChanged?.()

    return publications
  }

  /**
   * Handle agent profile registration.
   * Called by hub-net on connect.
   */
  async handleAgentRegister(
    profile: Omit<AgentProfile, 'key'>,
    sender: Sender,
    state: State,
  ): Promise<{
    success: true
    profile: AgentProfile
    hubKey: string
    hubNetworkId: string
  }> {
    if (!state.key) {
      throw networkError('unauthorized', 'authentication required', false)
    }
    if (profile.version !== HUB_NETWORK_WIRE_VERSION) {
      throw networkError('unsupported_version', 'unsupported agent profile version', false)
    }
    if (!profile.wireGuardKey) {
      throw networkError('invalid_request', 'WireGuard key is required', false)
    }
    try {
      await this.localAgent.register(state.key, state.id)
    } catch (error) {
      const code = error instanceof Error ? error.message : 'local_agent_unavailable'
      if (code === 'local_agent_rebind_required') {
        throw networkError(code, 'owner authorization required to replace bound local agent', false)
      }
      if (code === 'local_agent_proof_mismatch') {
        throw networkError(code, 'local proof agent does not match authenticated connection', false)
      }
      throw networkError('local_agent_unavailable', 'authenticated local hub-net proof unavailable', true)
    }

    return this.registerAuthenticatedProfile(profile, state)
  }

  async bindAgent(
    request: import('./wire').AgentBindRequest,
    sender: Sender,
    state: State,
    path = 'hub/net/bind',
  ) {
    const { bindingKind, admission, ...profile } = request
    if (bindingKind === 'machine') return this.handleAgentRegister(profile, sender, state)
    if (bindingKind === 'apple-app') return this.handleAppRegister(profile, state, path)
    if (bindingKind === 'join') return this.handleJoinRegister(profile, sender, state, admission)
    throw networkError('invalid_request', 'unsupported agent binding kind', false)
  }

  /**
   * Register an authenticated invitation joiner as a normal network profile.
   *
   * Joiners arrive through the inviter's direct bootstrap tunnel and are
   * authenticated by their own service key (the same key they signed the
   * direct bootstrap request with). Unlike the machine path they have no
   * local hub-net agent proof, and unlike apple-app they are not the Hub
   * owner; hub-pro assigns permanent overlay addresses from the sender
   * context and the wireGuardKey the joiner bound to.
   *
   * A key that was never admitted must present `admission`: the direct
   * bootstrap response signed by an agent that is currently bound to this
   * network, naming this key and WireGuard key. Admitted keys re-bind without
   * it (reconnects, agent restarts).
   */
  handleJoinRegister(
    profile: Omit<AgentProfile, 'key'>,
    sender: Sender,
    state: State,
    admission?: DirectBootstrapResponse,
  ): {
    success: true
    profile: AgentProfile
    hubKey: string
    hubNetworkId: string
    } {
    if (!state.key) {
      throw networkError('unauthorized', 'authentication required', false)
    }
    if (profile.version !== HUB_NETWORK_WIRE_VERSION) {
      throw networkError('unsupported_version', 'unsupported agent profile version', false)
    }
    if (!profile.wireGuardKey) {
      throw networkError('invalid_request', 'WireGuard key is required', false)
    }
    const inviter = admission && this.agents.getProfile(admission.inviterServiceKey)
    const admitted = !!admission && !!inviter && admission.inviterServiceKey !== state.key
      && validateJoinAdmission(admission, state.key, profile.wireGuardKey)
    // A fresh invitation for this key and WireGuard key lets a member rejoin with new tunnel keys
    // (the Hub app keeps its identity across joins); without one the bound WireGuard key stays.
    const existing = this.agents.getProfile(state.key)
    if (existing && existing.wireGuardKey !== profile.wireGuardKey && !admitted) {
      throw networkError('forbidden', 'profile WireGuard key is already bound', false)
    }
    if (!this.isMember(state) && !admitted) {
      throw networkError('forbidden', 'a valid invitation admission is required to join', false)
    }
    return this.registerAuthenticatedProfile(profile, state)
  }

  /**
   * Register an owner-controlled app-scoped profile without claiming the
   * machine-local hub-net role.
   */
  handleAppRegister(
    profile: Omit<AgentProfile, 'key'>,
    state: State,
    path = 'hub/net/bind',
  ): {
    success: true
    profile: AgentProfile
    hubKey: string
    hubNetworkId: string
    } {
    if (!this.security.isOwner(state)) {
      throw networkError('forbidden', `owner permission required for ${path}`, false)
    }
    return this.registerAuthenticatedProfile(profile, state)
  }

  bindAppleAppAgent(
    request: AppleAppAgentBindRequest,
    state: State,
    path = 'hub/net/apple-agent/bind',
  ): LocalAgentBindingStatus {
    if (request.version !== HUB_NETWORK_WIRE_VERSION) {
      throw networkError('unsupported_version', 'unsupported Apple app-agent version', false)
    }
    return this.updateAppleAppAgent(request.assertion, state, path, false)
  }

  renewAppleAppAgent(
    request: AppleAppAgentRenewRequest,
    state: State,
    path = 'hub/net/apple-agent/renew',
  ): LocalAgentBindingStatus {
    if (request.version !== HUB_NETWORK_WIRE_VERSION) {
      throw networkError('unsupported_version', 'unsupported Apple app-agent version', false)
    }
    return this.updateAppleAppAgent(request.assertion, state, path, true)
  }

  unbindAppleAppAgent(
    request: AppleAppAgentUnbindRequest,
    state: State,
    path = 'hub/net/apple-agent/unbind',
  ): LocalAgentBindingStatus {
    this.security.requireOwner(state, path)
    if (request.version !== HUB_NETWORK_WIRE_VERSION) {
      throw networkError('unsupported_version', 'unsupported Apple app-agent version', false)
    }
    const profile = this.authenticatedProfile(state)
    const { hubNetworkId } = this.registry.getIdentity()
    if (request.hubNetworkId !== hubNetworkId) {
      throw networkError('forbidden', 'Apple app-agent binding does not match registered profile or Hub', false)
    }
    try {
      this.localAgent.unbindApple(request, state.id)
    } catch {
      throw networkError('forbidden', 'Apple app-agent binding is not owned by this connection', false)
    }
    this.onStateChanged?.()
    return this.localAgent.status()
  }

  private updateAppleAppAgent(
    assertion: AppleAppAgentReadinessAssertion,
    state: State,
    path: string,
    renew: boolean,
  ): LocalAgentBindingStatus {
    this.security.requireOwner(state, path)
    const profile = this.authenticatedProfile(state)
    const { hubNetworkId } = this.registry.getIdentity()
    if (
      assertion.wireGuardKey !== profile.wireGuardKey
      || assertion.hubNetworkId !== hubNetworkId
    ) {
      throw networkError('forbidden', 'Apple readiness does not match registered profile, WireGuard key, or Hub', false)
    }
    if (!validateAppleAppAgentReadiness(assertion, profile.key, Date.now(), {
      hubNetworkId,
      tunnelInstanceId: assertion.tunnelInstanceId,
      generation: assertion.generation,
    })) {
      throw networkError('forbidden', 'invalid or expired Apple app-agent readiness assertion', false)
    }
    try {
      if (renew) this.localAgent.renewApple(assertion, state.id, profile.key)
      else this.localAgent.bindApple(assertion, state.id, profile.key)
    } catch (error) {
      throw networkError('forbidden', error instanceof Error ? error.message : 'invalid Apple app-agent binding', false)
    }
    this.onStateChanged?.()
    return this.localAgent.status()
  }

  private registerAuthenticatedProfile(
    profile: Omit<AgentProfile, 'key'>,
    state: State,
  ): {
    success: true
    profile: AgentProfile
    hubKey: string
    hubNetworkId: string
    } {
    if (!state.key) {
      throw networkError('unauthorized', 'authentication required', false)
    }
    if (profile.version !== HUB_NETWORK_WIRE_VERSION) {
      throw networkError('unsupported_version', 'unsupported agent profile version', false)
    }
    if (!profile.wireGuardKey) {
      throw networkError('invalid_request', 'WireGuard key is required', false)
    }

    // One agent per device. Its proof passed, so a pending device is approved and the member is the device.
    const deviceId = state.certificate?.deviceId
    if (deviceId) {
      // Another key takes over only while the old agent is offline (a reinstall), keeping the addresses
      const connected = [...this.agentDevices].some(([key, device]) => device === deviceId && key !== state.key)
      if (connected) throw networkError('device_endpoint_exists', 'this device already has a network endpoint', false)
      if (!state.device) this.onBindApprove?.(state)
    }
    const memberKey = state.device ? deviceMemberKey(state.device) : state.key
    if (state.device) {
      this.registry.moveMember(state.key, memberKey)
      this.agentDevices.set(state.key, state.device)
      if (this.registry.clearRevokedDevice(state.device)) this.onRevokedDevicesChanged?.()
    }
    const addresses = this.registry.allocateAddresses(memberKey)
    const registered: AgentProfile = {
      version: profile.version,
      wireGuardKey: profile.wireGuardKey,
      name: typeof profile.name === 'string' ? profile.name : undefined,
      platform: typeof profile.platform === 'string' ? profile.platform : undefined,
      key: state.key,
      member: memberKey,
      ...(state.device ? { device: state.device } : {}),
      overlayAddresses: [addresses.ipv4, addresses.ipv6],
      connectedAt: new Date().toISOString(),
    }
    this.agents.registerProfile(registered, state.id)
    this.registry.rememberMember(memberKey, {
      ...(memberKey !== state.key ? { key: state.key, device: state.device } : {}),
      wireGuardKey: registered.wireGuardKey,
      name: registered.name,
      platform: registered.platform,
      lastSeen: registered.connectedAt,
    })
    this.onStateChanged?.()
    const { hubKey, hubNetworkId } = this.registry.getIdentity()
    return {
      success: true,
      profile: registered,
      hubKey,
      hubNetworkId,
    }
  }

  /**
   * Issue a connection grant for a caller to access a resource.
   */
  async issueConnectionGrant(
    callerWireGuardKey: string,
    resourceId: ResourceId,
    preferredProviderId: string | undefined,
    state: State,
  ): Promise<ConnectionGrant> {
    if (!state.key) {
      throw networkError('unauthorized', 'authentication required', false)
    }

    // Get resource
    const resource = this.registry.getResource(resourceId)
    if (!resource) {
      throw networkError('resource_unavailable', 'resource does not exist', false)
    }

    const callerKey = state.key
    const callerProfile = this.agents.getProfile(callerKey)
    if (!callerProfile) {
      throw networkError('unauthorized', 'caller profile not registered', false)
    }
    if (callerProfile.wireGuardKey !== callerWireGuardKey) {
      throw networkError('forbidden', 'caller WireGuard key does not match the registered profile', false)
    }

    if (!this.canAccessShare(resource, state)) {
      throw networkError('forbidden', 'not authorized for this resource', false)
    }

    // Get provider
    const provider = this.agents.selectProvider(resourceId, preferredProviderId)
    if (!provider) {
      throw networkError('provider_unavailable', 'no live provider for resource', false)
    }

    // Get agent profile for provider
    const agentProfile = this.agents.getProfile(provider.key)
    if (!agentProfile) {
      throw networkError('provider_unavailable', 'agent not connected', false)
    }

    // Check generation
    const generation = resource.generation

    // Create grant
    const grantId = randomUUIDv7()
    const issuedAt = new Date().toISOString()
    const expiresAt = new Date(Date.now() + CONNECTION_GRANT_MAX_LIFETIME_MS).toISOString()

    const { hubNetworkId, hubKey } = this.registry.getIdentity()
    const destinationIsIPv6 = provider.overlayAddress.includes(':')
    const callerAddress = callerProfile.overlayAddresses.find(address =>
      address.includes(':') === destinationIsIPv6
    )
    if (!callerAddress) {
      throw networkError('provider_unavailable', 'caller has no compatible overlay address', false)
    }

    const grant: ConnectionGrant = {
      version: HUB_NETWORK_WIRE_VERSION,
      grantId,
      hubKey,
      hubNetworkId,
      callerKey,
      callerWireGuardKey,
      callerAddress,
      targetKey: agentProfile.key,
      targetWireGuardKey: agentProfile.wireGuardKey,
      resourceId,
      providerId: provider.providerId,
      protocol: provider.protocol,
      destinationAddress: provider.overlayAddress,
      destinationPort: provider.port,
      generation,
      issuedAt,
      expiresAt,
      signature: '', // Will be signed below
    }

    // Sign grant
    grant.signature = await this.challengeSigner(signatureInput('connection-grant', grant))
    const affectedAgents = this.grantAgents.get(resourceId) ?? new Set<string>()
    affectedAgents.add(callerProfile.key)
    affectedAgents.add(agentProfile.key)
    this.grantAgents.set(resourceId, affectedAgents)

    return grant
  }

  /**
   * Issue a rendezvous ticket.
   */
  async issueRendezvousTicket(
    nodeId: string,
    roles: string[],
    state: State,
  ): Promise<RendezvousTicket> {
    if (!state.key) {
      throw networkError('unauthorized', 'authentication required', false)
    }

    const { hubNetworkId, hubKey } = this.registry.getIdentity()

    // Verify profile is registered
    const profile = this.agents.getProfile(state.key)
    if (!profile) {
      throw networkError('unauthorized', 'agent profile not registered', false)
    }
    if (roles.length !== 1 || roles[0] !== 'rendezvous') {
      throw networkError('invalid_request', 'only the rendezvous node role is supported', false)
    }

    const ticketId = randomUUIDv7()
    const issuedAt = new Date().toISOString()
    const expiresAt = new Date(Date.now() + RENDEZVOUS_TICKET_MAX_LIFETIME_MS).toISOString()

    const ticket: RendezvousTicket = {
      version: HUB_NETWORK_WIRE_VERSION,
      ticketId,
      hubKey,
      hubNetworkId,
      key: state.key,
      nodeId,
      roles: roles as ['rendezvous'],
      sessionPurpose: 'peer-connect',
      issuedAt,
      expiresAt,
      signature: '',
    }

    ticket.signature = await this.challengeSigner(signatureInput('rendezvous-ticket', ticket))

    return ticket
  }

  advertiseGateway(capability: GatewayCapability, endpoint: string, state: State): GatewayStatus {
    const profile = this.authenticatedProfile(state)
    if (
      capability?.version !== HUB_NETWORK_WIRE_VERSION
      || capability.capability !== 'internet-gateway-v1'
      || typeof capability.ipv4 !== 'boolean'
      || typeof capability.ipv6 !== 'boolean'
      || typeof capability.dns !== 'boolean'
      || typeof capability.metered !== 'boolean'
      || (!capability.ipv4 && !capability.ipv6)
      || !Number.isFinite(Date.parse(capability.updatedAt))
      || !/^(?:[^:[\]\s]+:\d{1,5}|\[[0-9a-fA-F:]+\]:\d{1,5})$/.test(endpoint)
      || Number(endpoint.slice(endpoint.lastIndexOf(':') + 1)) < 1
      || Number(endpoint.slice(endpoint.lastIndexOf(':') + 1)) > 65535
    ) {
      throw networkError('invalid_request', 'invalid gateway capability', false)
    }
    const { hubNetworkId } = this.registry.getIdentity()
    const generation = this.gatewayGenerations.get(profile.key) ?? 0
    const status: GatewayStatus = {
      version: HUB_NETWORK_WIRE_VERSION,
      hubNetworkId,
      key: profile.key,
      wireGuardKey: profile.wireGuardKey,
      endpoint,
      capability: { ...capability },
      state: 'available',
      updatedAt: new Date().toISOString(),
    }
    this.gateways.set(profile.key, { status, connectionId: state.id, generation })
    this.gatewayRevocations.delete(profile.key)
    this.onStateChanged?.()
    return status
  }

  removeGateway(reason: string, state: State): GatewayRevocation {
    const profile = this.authenticatedProfile(state)
    const current = this.gateways.get(profile.key)
    if (!current || current.connectionId !== state.id) {
      throw networkError('gateway_unavailable', 'gateway is not advertised by this connection', false)
    }
    return this.revokeGateway(profile.key, reason || 'provider_disabled')
  }

  listGateways(state: State): GatewayStatus[] {
    if (!this.canUseGatewayAPI(state)) return []
    return [...this.gateways.values()].map(value => value.status)
  }

  listGatewayRevocations(state: State): GatewayRevocation[] {
    if (!state.key) return []
    const profile = this.agents.getProfile(state.key)
    if (!profile && !this.security.isOwner(state)) return []
    return [...this.gatewayRevocations.values()].filter(revocation =>
      this.security.isOwner(state)
      || revocation.gatewayKey === profile?.key
      || this.gatewayGrantAgents.get(revocation.gatewayKey)?.has(state.key!),
    )
  }

  listGatewayDiagnostics(state: State): GatewayDiagnostic[] {
    if (!this.canUseGatewayAPI(state)) return []
    return []
  }

  async issueGatewayGrant(
    clientKey: string,
    clientWireGuardKey: string,
    gatewayKey: string,
    requested: { ipv4: boolean; ipv6: boolean; dns: boolean },
    state: State,
  ): Promise<GatewayGrant> {
    const client = this.authenticatedProfile(state)
    if (client.key !== clientKey || client.wireGuardKey !== clientWireGuardKey) {
      throw networkError('gateway_not_authorized', 'client binding does not match authenticated profile', false)
    }
    const advertised = this.gateways.get(gatewayKey)
    if (!advertised || advertised.status.state !== 'available') {
      throw networkError('gateway_unavailable', 'gateway is unavailable', true)
    }
    if (
      typeof requested.ipv4 !== 'boolean'
      || typeof requested.ipv6 !== 'boolean'
      || typeof requested.dns !== 'boolean'
      || (!requested.ipv4 && !requested.ipv6)
      || (requested.ipv4 && !advertised.status.capability.ipv4)
      || (requested.ipv6 && !advertised.status.capability.ipv6)
      || (requested.dns && !advertised.status.capability.dns)
    ) {
      throw networkError('gateway_not_authorized', 'requested gateway capability is unavailable', false)
    }
    const issuedAt = new Date().toISOString()
    const { hubKey, hubNetworkId } = this.registry.getIdentity()
    const grant: GatewayGrant = {
      version: HUB_NETWORK_WIRE_VERSION,
      grantId: randomUUIDv7(),
      hubKey,
      hubNetworkId,
      clientKey,
      clientWireGuardKey,
      gatewayKey,
      gatewayWireGuardKey: advertised.status.wireGuardKey,
      ...requested,
      generation: advertised.generation,
      issuedAt,
      expiresAt: new Date(Date.now() + GATEWAY_GRANT_MAX_LIFETIME_MS).toISOString(),
      signature: '',
    }
    grant.signature = await this.challengeSigner(signatureInput('gateway-grant', grant))
    const agents = this.gatewayGrantAgents.get(gatewayKey) ?? new Set<string>()
    agents.add(client.key)
    agents.add(advertised.status.key)
    this.gatewayGrantAgents.set(gatewayKey, agents)
    return grant
  }

  private authenticatedProfile(state: State): AgentProfile {
    if (!state.key) throw networkError('unauthorized', 'authentication required', false)
    const profile = this.agents.getProfile(state.key)
    if (!profile || profile.key !== state.key) {
      throw networkError('unauthorized', 'agent profile not registered', false)
    }
    return profile
  }

  private canUseGatewayAPI(state: State): boolean {
    return !!state.key && (this.security.isOwner(state) || !!this.agents.getProfile(state.key))
  }

  private revokeGateway(key: string, reason: string): GatewayRevocation {
    const current = this.gateways.get(key)
    this.gateways.delete(key)
    const generation = (this.gatewayGenerations.get(key) ?? current?.generation ?? 0) + 1
    this.gatewayGenerations.set(key, generation)
    const revocation: GatewayRevocation = {
      version: HUB_NETWORK_WIRE_VERSION,
      hubNetworkId: this.registry.getIdentity().hubNetworkId,
      gatewayKey: key,
      generation,
      revokedAt: new Date().toISOString(),
      reason,
    }
    this.gatewayRevocations.set(key, revocation)
    this.onStateChanged?.()
    return revocation
  }

  /**
   * Update network resource policy.
   *
   * A policy change can only narrow or widen access, but the previous
   * generation of grants were issued under the old policy. Bumping the
   * generation invalidates those grants so callers must reauthorize against the
   * new policy, satisfying "revocation stops future authorization" for policy
   * and group membership changes. The new generation is propagated to affected
   * connected agents so they can terminate active flows.
   */
  updateResourcePolicy(
    resourceId: string,
    policy: NetworkPolicy,
    state: State,
  ): number {
    if (!state.key) {
      throw networkError('unauthorized', 'authentication required', false)
    }

    const resource = this.registry.getResource(resourceId)
    if (!resource) {
      throw networkError('resource_unavailable', 'resource does not exist', false)
    }

    // Only owner can change policy
    if (resource.ownerKey !== state.key && !this.security.isOwner(state)) {
      throw networkError('forbidden', 'only resource owner can change policy', false)
    }

    this.permissions.validatePolicy(policy)
    const unchanged = JSON.stringify(resource.policy) === JSON.stringify(policy)
    const generation = unchanged ? resource.generation : resource.generation + 1
    this.registry.updateResource(resourceId, policy, generation)
    if (!unchanged) this.setPolicyGrants(resource, state.key)
    if (!unchanged) this.propagateGeneration(resourceId)
    this.onStateChanged?.()

    return generation
  }

  /**
   * Revoke a resource (increment generation) and propagate the new generation
   * to connected agents so they terminate matching active flows and reject
   * grants issued against the previous generation.
   */
  revokeResource(resourceId: string, state: State): number {
    if (!state.key) {
      throw networkError('unauthorized', 'authentication required', false)
    }

    const resource = this.registry.getResource(resourceId)
    if (!resource) {
      throw networkError('resource_unavailable', 'resource does not exist', false)
    }

    // Only owner can revoke
    if (resource.ownerKey !== state.key && !this.security.isOwner(state)) {
      throw networkError('forbidden', 'only resource owner can revoke', false)
    }

    const newGeneration = this.registry.incrementGeneration(resourceId)
    this.propagateGeneration(resourceId)
    this.onStateChanged?.()
    return newGeneration
  }

  /**
   * Invalidate grants that depended on a changed Hub group. Authorization for
   * subsequent issuance is re-evaluated against the updated membership.
   */
  handleGroupMembershipChanged(group: string): void {
    const shares = new Set(
      this.security.grants.grants.flatMap(({ subject, object }) =>
        'group' in subject && subject.group === group && 'share' in object ? [object.share] : [],
      ),
    )
    for (const resource of Object.values(this.registry.data.resources)) {
      const byPolicy = resource.policy.mode === 'group' && resource.policy.group === group
      if (!byPolicy && !shares.has(resource.resourceId)) continue
      this.registry.incrementGeneration(resource.resourceId)
      this.propagateGeneration(resource.resourceId)
    }
    this.onStateChanged?.()
  }

  handleGroupRenamed(group: string, name: string): void {
    for (const resource of Object.values(this.registry.data.resources)) {
      if (resource.policy.mode !== 'group' || resource.policy.group !== group) continue
      // The group's grants were renamed with it, the stored policy follows
      const policy: NetworkPolicy = { mode: 'group', group: name }
      this.registry.updateResource(resource.resourceId, policy, resource.generation + 1)
      this.propagateGeneration(resource.resourceId)
    }
    this.onStateChanged?.()
  }

  /**
   * Stage the current resource generation snapshot for every agent that hosts
   * the resource as a provider. Callers discover revocation the next time they
   * request or renew a grant, which is rejected against the new generation.
   *
   * Target agents receive the snapshot through the `network/resource/generations`
   * stream and remove affected peer authorization and active flows. Staging is
   * scoped per agent so an unrelated agent never receives another resource's
   * generation.
   */
  private propagateGeneration(resourceId: string): void {
    const resource = this.registry.getResource(resourceId)
    if (!resource) return
    const updatedAt = new Date().toISOString()
    const snapshot: ResourceGenerationSnapshot = {
      version: HUB_NETWORK_WIRE_VERSION,
      resourceId: resource.resourceId,
      generation: resource.generation,
      policy: resource.policy,
      updatedAt,
    }
    const affectedAgents = new Set(this.grantAgents.get(resourceId) ?? [])
    for (const provider of this.agents.getProviders(resourceId)) affectedAgents.add(provider.key)
    for (const key of affectedAgents) this.agents.stageGeneration(key, snapshot)
    this.onGenerationChanged?.(resourceId)
  }

  /**
   * List resources filtered by permissions.
   */
  listResources(state: State): NetworkResource[] {
    return Object.values(this.registry.data.resources).filter(resource => this.canViewResource(resource, state))
  }

  /**
   * List agents filtered by permissions.
   */
  /**
   * Every member: connected profiles plus known members that are offline, so
   * the hub host's agent keeps their peers across restarts (a member can only
   * reconnect through that peer).
   */
  listMembers(): AgentProfile[] {
    const connected = this.agents.listProfiles()
    const keys = new Set(connected.map(profile => profile.key))
    const offline = this.registry.listMembers()
      .filter(({ key, member }) => !keys.has(member.key ?? key))
      .map(({ key, member, addresses }): AgentProfile => ({
        version: HUB_NETWORK_WIRE_VERSION,
        key: member.key ?? key,
        member: key,
        ...(member.device ? { device: member.device } : {}),
        wireGuardKey: member.wireGuardKey,
        name: member.name,
        platform: member.platform,
        overlayAddresses: addresses,
        connectedAt: member.lastSeen,
        online: false,
        ...this.deviceFields(member.device, member.name),
      }))
    const online = connected.map(profile => ({
      ...profile,
      online: true,
      ...this.deviceFields(this.agentDevices.get(profile.key), profile.name),
    }))
    return [...online, ...offline]
  }

  private deviceFields(device: string | undefined, name: string | undefined): Pick<AgentProfile, 'deviceAuthority'> {
    if (!device) return {}
    return { deviceAuthority: this.deviceAuthority(device, name) }
  }

  /** The device's DNS name, from its registry name */
  deviceAuthority(device: string, fallbackName?: string): string {
    const { hubNetworkId } = this.registry.getIdentity()
    return deviceAuthority(hubNetworkId, device, this.deviceLabel?.(device) ?? fallbackName ?? 'device')
  }

  /** `Device.overlay`: the device member's IPv4 overlay address and DNS name */
  deviceOverlay(device: string): { address: string; authority: string } | undefined {
    const addresses = this.registry.data.allocations[deviceMemberKey(device)]
    if (!addresses) return
    return { address: addresses[0], authority: this.deviceAuthority(device, this.registry.data.members[deviceMemberKey(device)]?.name) }
  }

  /** Device names for member DNS names, set by the hub */
  deviceLabel: ((device: string) => string | undefined) | undefined
  onRevokedDevicesChanged: (() => void) | undefined

  /** A member by its device or, for legacy agents, by its key */
  private isMember(state: State): boolean {
    if (state.key && this.registry.hasAllocation(state.key)) return true
    const device = state.device ?? state.certificate?.deviceId
    return !!device && this.registry.hasAllocation(deviceMemberKey(device))
  }

  /** `online` while the device's agent is bound, `offline` for a member that isn't, else undefined */
  deviceNetworkState(device: string): 'online' | 'offline' | undefined {
    if ([...this.agentDevices.values()].includes(device)) return 'online'
    return this.registry.data.members[deviceMemberKey(device)] ? 'offline' : undefined
  }

  /**
   * Removes the member of a removed or revoked device, and legacy members of its revoked keys, releasing their
   * addresses. Their WireGuard keys go to `network/devices/revoked` so every agent drops them as peers.
   */
  removeDevice(device: string, revokedKeys: string[] = []): void {
    const wireGuardKeys = new Set<string>()
    for (const key of [deviceMemberKey(device), ...revokedKeys]) {
      const member = this.registry.removeMember(key)
      if (member) wireGuardKeys.add(member.wireGuardKey)
    }
    for (const [key, agentDevice] of [...this.agentDevices]) {
      if (agentDevice !== device && !revokedKeys.includes(key)) continue
      const profile = this.agents.getProfile(key)
      if (profile) wireGuardKeys.add(profile.wireGuardKey)
      this.agents.unregisterProfile(key)
      this.agentDevices.delete(key)
    }
    for (const key of revokedKeys) {
      const profile = this.agents.getProfile(key)
      if (profile) wireGuardKeys.add(profile.wireGuardKey)
      this.agents.unregisterProfile(key)
    }
    if (wireGuardKeys.size) {
      this.registry.addRevokedDevice({ device, wireGuardKeys: [...wireGuardKeys], at: new Date().toISOString() })
      this.onRevokedDevicesChanged?.()
    }
    this.onStateChanged?.()
  }

  /** The full revoked list for owners and bound agents */
  revokedDevices(state: State): RevokedDevice[] {
    if (!this.security.isOwner(state) && !(state.key && this.agents.getProfile(state.key))) return []
    return this.registry.data.revokedDevices
  }

  listAgents(state: State): AgentProfile[] {
    // The owner and the hub host's own agent see every member: the agent keeps
    // a WireGuard peer per member and enforces their port grants.
    const isHubOwner = this.security.isOwner(state)
    const isLocalAgent = !!state.key && this.localAgent.binding('machine')?.key === state.key
    if (isHubOwner || isLocalAgent) {
      return this.listMembers()
    }

    const visibleKeys = new Set(this.listVisibleProviders(state).map(provider => provider.key))
    if (state.key && this.agents.getProfile(state.key)) visibleKeys.add(state.key)

    // A caller only learns about agents serving resources it can see. Tunnel
    // keys remain available through signed grants, not broad discovery.
    return this.agents.listProfiles().filter(profile => visibleKeys.has(profile.key)).map(p => ({
      ...p,
      wireGuardKey: '',
    }))
  }

  /**
   * List live providers for a resource.
   */
  listProviders(resourceId: string, state: State): LiveProvider[] {
    const resource = this.registry.getResource(resourceId)
    if (!resource) {
      throw networkError('resource_unavailable', 'resource does not exist', false)
    }

    if (!this.canViewResource(resource, state)) {
      throw networkError('forbidden', 'not authorized to view providers', false)
    }

    return this.agents.getProviders(resourceId)
  }

  /**
   * List every provider whose resource is visible to the caller.
   */
  listVisibleProviders(state: State): LiveProvider[] {
    const visibleResources = new Set(this.listResources(state).map(resource => resource.resourceId))
    return this.agents.providers
      .map(provider => provider)
      .filter(provider => visibleResources.has(provider.resourceId))
  }

  /**
   * Get agent status for all agents.
   */
  getAgentStatus(state: State): import('./wire').AgentStatus[] {
    const isHubOwner = this.security.isOwner(state)
    if (isHubOwner) {
      return this.agents.listAgentStatus()
    }

    const visibleKeys = new Set(this.listAgents(state).map(profile => profile.key))
    return this.agents.listAgentStatus().filter(status => visibleKeys.has(status.key)).map(s => ({
      ...s,
      addresses: [],
    }))
  }

  /**
   * Connection state is resource-scoped and follows the same visibility rules
   * as discovery. In particular, a failed private connection must not reveal
   * that the resource or provider exists.
   */
  getConnectionStatus(state: State): import('./wire').ConnectionStatus[] {
    const visibleResources = new Set(this.listResources(state).map(resource => resource.resourceId))
    return this.agents.listConnectionStatus().filter(status => visibleResources.has(status.resourceId))
  }

  /**
   * Diagnostics are bounded error-bearing connection states. This avoids a
   * second unversioned diagnostic model while preventing successful connection
   * metadata from being exposed through the failure stream.
   */
  getDiagnostics(state: State): import('./wire').ConnectionStatus[] {
    return this.getConnectionStatus(state).filter(status => status.phase === 'failed' && status.error)
  }

  private canViewResource(resource: NetworkResource, state: State): boolean {
    if (!state.key) return false
    if (resource.ownerKey === state.key || this.security.isOwner(state)) return true

    if (!this.agents.getProfile(state.key)) return false
    return this.canAccessShare(resource, state)
  }

  /**
   * Share access is a grant (protocol.md section 9): owners and the share's own service always, unless the share
   * is disabled; anyone else needs a `{ share }` grant for their key, device, groups or everyone.
   */
  private canAccessShare(resource: NetworkResource, state: State): boolean {
    if (resource.policy.mode === 'disabled' || !state.key) return false
    if (this.security.isOwner(state) || resource.ownerKey === state.key) return true
    return this.security.grants.allowsShare(this.security.caller(state), resource.resourceId)
  }

  /** Grants a share policy stands for: hub → everyone, group → the group, keys → each key, private → none */
  private setPolicyGrants(resource: NetworkResource, by: string): void {
    this.applyingPolicy = true
    try {
      this.security.grants.removeWhere(({ object }) => 'share' in object && object.share === resource.resourceId)
      const object = { share: resource.resourceId }
      const policy = resource.policy
      if (policy.mode === 'hub') this.security.grants.add({ everyone: true }, object, by)
      if (policy.mode === 'group') this.security.grants.add({ group: policy.group }, object, by)
      if (policy.mode === 'keys') for (const key of policy.keys) this.security.grants.add({ key }, object, by)
    } finally {
      this.applyingPolicy = false
    }
  }
  private applyingPolicy = false

  /** Share grants added or removed outside a policy update end flows of the old generation */
  handleGrantsChanged(changed: Grant[]): void {
    if (this.applyingPolicy) return
    const shares = new Set(changed.flatMap(({ object }) => ('share' in object ? [object.share] : [])))
    for (const resourceId of shares) {
      if (!this.registry.getResource(resourceId)) continue
      this.registry.incrementGeneration(resourceId)
      this.propagateGeneration(resourceId)
    }
    if (shares.size) this.onStateChanged?.()
  }

  /** Turns stored share policies into grants once */
  private migratePolicies(): void {
    const grants = this.security.grants
    if (grants.storage.corrupt || grants.migrated.includes('network')) return
    for (const resource of Object.values(this.registry.data.resources)) this.setPolicyGrants(resource, 'migration')
    grants.markMigrated('network')
  }

  /**
   * Current staged generation snapshots for the agent associated with the
   * authenticated connection. The stream re-evaluates this on every generation
   * change and dedupes identical snapshots, so agents receive the latest
   * generation per resource and can terminate flows whose grant generation is
   * older than the snapshot. Snapshots are scoped to the agent and cleared on
   * disconnect.
   */
  currentGenerations(state: State): ResourceGenerationSnapshot[] {
    if (!state.key) return []
    const profile = this.agents.getProfile(state.key)
    if (!profile) return []
    return this.agents.stagedGenerations(profile.key)
  }

  /**
   * Handle disconnection - cleanup agent profile and providers.
   */
  handleDisconnect(state: State): void {
    for (const [key, gateway] of this.gateways) {
      if (gateway.connectionId === state.id) this.revokeGateway(key, 'provider_disconnected')
    }
    this.localAgent.disconnect(state.id)
    this.agents.unregisterProviderConnection(state.id)
    const removedKeys = this.agents.unregisterConnection(state.id)
    for (const key of removedKeys) this.agentDevices.delete(key)
    if (state.key && removedKeys.has(state.key)) {
      for (const [resourceId, keys] of this.grantAgents) {
        keys.delete(state.key)
        if (keys.size === 0) this.grantAgents.delete(resourceId)
      }
    }
    this.onStateChanged?.()
  }

  /**
   * Verify a service attestation.
   */
  private verifyAttestation(
    attestation: import('./wire').AgentAttestation,
    shareName: string,
    protocol: import('./wire').Protocol,
    target: import('./wire').LocalTarget,
    serviceKey: string,
    agentProfile: AgentProfile,
  ): boolean {
    if (attestation.version !== HUB_NETWORK_WIRE_VERSION) return false
    const now = Date.now()
    const issuedAt = Date.parse(attestation.issuedAt)
    const expiresAt = Date.parse(attestation.expiresAt)
    if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)) return false
    if (issuedAt > now + 30_000 || expiresAt <= now || expiresAt <= issuedAt) return false
    if (expiresAt - issuedAt > 10 * 60 * 1000) return false
    this.pruneConsumedAttestations(now)
    if (this.consumedAttestations.has(attestation.attestationId)) return false

    // Verify fields match
    if (attestation.serviceKey !== serviceKey) return false
    if (attestation.key !== agentProfile.key) return false
    if (attestation.shareName !== shareName) return false
    if (attestation.protocol !== protocol) return false
    if (attestation.target.host !== target.host) return false
    if (attestation.target.port !== target.port) return false

    try {
      const publicKey = createPublicKey({
        key: Buffer.from(agentProfile.key, 'base64'),
        format: 'der',
        type: 'spki',
      })
      return verifyEnvelope('agent-attestation', attestation, publicKey)
    } catch {
      return false
    }
  }

  private validateShare(share: NetworkShare): void {
    if (
      share?.version !== HUB_NETWORK_WIRE_VERSION
      || (share.protocol !== 'tcp' && share.protocol !== 'udp')
      || typeof share.name !== 'string'
      || typeof share.target?.host !== 'string'
      || !share.target.host
      || !Number.isInteger(share.target.port)
      || share.target.port < 1
      || share.target.port > 65535
      || !share.attestation
    ) {
      throw networkError('invalid_request', 'invalid network share', false)
    }
    try {
      stableResourceId('', share.name)
      if (share.policy) this.permissions.validatePolicy(share.policy)
    } catch {
      throw networkError('invalid_request', 'invalid network share', false)
    }
  }

  private pruneConsumedAttestations(now: number): void {
    for (const [id, expiresAt] of this.consumedAttestations) {
      if (expiresAt <= now) this.consumedAttestations.delete(id)
    }
  }
}

const deviceMemberKey = (device: string) => `device:${device}`

/**
 * Create network message envelopes.
 */
export function createMessage<TType extends HubNetworkMessage['type'], TPayload>(
  type: TType,
  payload: TPayload,
): WireEnvelope<TType, TPayload> {
  return {
    version: HUB_NETWORK_WIRE_VERSION,
    type,
    payload: payload as any,
  }
}
