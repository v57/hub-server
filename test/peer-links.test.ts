import { beforeEach, describe, expect, test } from 'bun:test'
import { createPublicKey, sign } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { NetworkAPI, hostRoute } from '../src/network/api'
import { signEnvelope, verifyEnvelope } from '../src/network/crypto'
import { HUB_NETWORK_WIRE_VERSION, type AgentAttestation, type AgentBindRequest, type AppleAppAgentReadinessAssertion, type NetworkPolicy } from '../src/network/wire'
import { Security } from '../src/security'
import type { State } from '../src/hub'
import { makeKey, type TestKey } from './helpers'

function state(key: TestKey): State {
  return { id: crypto.randomUUID(), key: key.key, services: new Set(), apps: new Set() }
}

const bind = (wireGuardKey: string): AgentBindRequest => ({
  version: HUB_NETWORK_WIRE_VERSION,
  bindingKind: 'apple-app',
  wireGuardKey,
  overlayAddresses: [],
  connectedAt: new Date().toISOString(),
})

describe('Peer links', () => {
  let security: Security
  let api: NetworkAPI
  const hub = makeKey()
  beforeEach(async () => {
    process.chdir(mkdtempSync(join(tmpdir(), 'hub-server-links-')))
    security = new Security()
    api = new NetworkAPI(security, async input => sign(null, input, hub.privateKey).toString('base64'))
    await api.registry.load()
    api.registry.setHubKey(hub.key)
  })
  const owner = () => {
    const key = makeKey()
    security.addOwner(key.key)
    return key
  }

  /** The hub's machine: an owner bound as the Apple app agent */
  const hubMachine = async (device?: string) => {
    const machine = owner()
    const machineState = { ...state(machine), ...(device ? { device } : {}) }
    await api.bindAgent(bind('wg-machine'), {} as never, machineState)
    const now = Date.now()
    const assertion: AppleAppAgentReadinessAssertion = {
      version: HUB_NETWORK_WIRE_VERSION,
      signatureDomain: 'hub-network/apple-app-agent-readiness/v1',
      hubNetworkId: api.registry.getIdentity().hubNetworkId,
      wireGuardKey: 'wg-machine',
      tunnelInstanceId: 't1',
      capabilities: ['invitation-bootstrap-v1'],
      generation: 1,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 20_000).toISOString(),
      signature: '',
    }
    assertion.signature = signEnvelope('apple-app-agent-readiness', assertion, machine.privateKey)
    api.bindAppleAppAgent({ version: HUB_NETWORK_WIRE_VERSION, assertion }, machineState)
    return { machine, machineState }
  }

  test('members get a signed hub link to the hub\'s machine', async () => {
    const { machine, machineState } = await hubMachine()
    const phone = owner()
    const phoneState = state(phone)
    await api.bindAgent(bind('wg-phone'), {} as never, phoneState)
    api.coordinator = () => 'wss://v57.dev:1964'

    const links = await api.links(phoneState)
    expect(links).toMatchObject({ coordinator: 'wss://v57.dev:1964', hubHost: false, hubKey: hub.key })
    const grant = links.grants[0]!
    expect(grant).toMatchObject({
      purpose: 'hub',
      a: { key: phone.key, wireGuardKey: 'wg-phone' },
      b: { key: machine.key, wireGuardKey: 'wg-machine' },
      aToB: [{ protocol: 'tcp', port: 1997 }],
    })
    expect(grant.aViaB).toEqual(grant.b.addresses.map(hostRoute))
    expect(grant.bViaA).toEqual(grant.a.addresses.map(hostRoute))
    expect(verifyEnvelope('peer-link', grant, createPublicKey({ key: Buffer.from(hub.key, 'base64'), format: 'der', type: 'spki' }))).toBeTrue()
    // The same sides get the same grant until half its life has passed
    expect((await api.links(phoneState)).grants[0]!.grantId).toBe(grant.grantId)

    // The machine itself accepts links and gets none of its own
    expect(await api.links(machineState)).toMatchObject({ hubHost: true, grants: [] })
    // Without a registered profile there's nothing to link
    await expect(api.links(state(makeKey()))).rejects.toMatchObject({ code: 'unauthorized' })
  })

  test('the hub link opens the ports of the machine\'s shares the member may open', async () => {
    const { machine } = await hubMachine()
    const service = makeKey()
    const serviceState = state(service)
    const share = (name: string, port: number, policy: NetworkPolicy) => {
      const now = Date.now()
      const attestation: AgentAttestation = {
        version: HUB_NETWORK_WIRE_VERSION,
        attestationId: crypto.randomUUID(),
        serviceKey: service.key,
        key: machine.key,
        shareName: name,
        protocol: 'tcp',
        target: { host: '127.0.0.1', port },
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 60_000).toISOString(),
        signature: '',
      }
      attestation.signature = signEnvelope('agent-attestation', attestation, machine.privateKey)
      return { version: HUB_NETWORK_WIRE_VERSION, name, protocol: 'tcp' as const, target: attestation.target, policy, attestation }
    }
    api.handleSharesReplace([share('web', 8080, { mode: 'hub' }), share('admin', 9000, { mode: 'private' })], {} as never, serviceState)

    // A member that isn't an owner opens the hub's port and the share everyone may open, not the private one
    const phone = makeKey()
    const phoneState = state(phone)
    ;(api as unknown as { registerAuthenticatedProfile(profile: unknown, state: State): unknown })
      .registerAuthenticatedProfile(bind('wg-phone'), phoneState)
    const grant = (await api.links(phoneState)).grants[0]!
    expect(grant.aToB).toEqual([{ protocol: 'tcp', port: 1997 }, { protocol: 'tcp', port: 8080 }])
    // An owner opens both, in a grant of its own
    const ownerPhone = owner()
    const ownerState = state(ownerPhone)
    await api.bindAgent(bind('wg-owner'), {} as never, ownerState)
    expect((await api.links(ownerState)).grants[0]!.aToB.map(({ port }) => port)).toEqual([1997, 8080, 9000])

    // Once the service stops sharing, the member's next grant closes the port again
    api.handleSharesReplace([], {} as never, serviceState)
    const closed = (await api.links(phoneState)).grants[0]!
    expect(closed.aToB).toEqual([{ protocol: 'tcp', port: 1997 }])
    expect(closed.grantId).not.toBe(grant.grantId)
  })

  test('the hub link opens the machine\'s SSH port for owners and callers granted network/ssh', async () => {
    await hubMachine('mac')
    api.deviceSSHPort = device => (device === 'mac' ? 22 : undefined)
    const member = async (wireGuardKey: string, key = makeKey()) => {
      const memberState = state(key)
      ;(api as unknown as { registerAuthenticatedProfile(profile: unknown, state: State): unknown })
        .registerAuthenticatedProfile(bind(wireGuardKey), memberState)
      return { key, memberState }
    }
    const ports = async (memberState: State) => (await api.links(memberState)).grants[0]!.aToB.map(({ port }) => port)

    // An owner reaches the SSH server, a member without a grant only the hub
    const { memberState: ownerState } = await member('wg-owner', owner())
    expect(await ports(ownerState)).toEqual([22, 1997])
    const { key: phone, memberState: phoneState } = await member('wg-phone')
    expect(await ports(phoneState)).toEqual([1997])
    // An owner's grant on network/ssh opens it for that member
    security.grants.add({ key: phone.key }, { path: 'network/ssh' }, 'test')
    expect(await ports(phoneState)).toEqual([22, 1997])

    // Once the machine stops reporting SSH, the port closes again
    api.deviceSSHPort = () => undefined
    expect(await ports(ownerState)).toEqual([1997])
  })

  test('a hub machine that isn\'t a device opens no SSH port', async () => {
    await hubMachine()
    api.deviceSSHPort = () => 22
    const ownerPhone = owner()
    const ownerState = state(ownerPhone)
    await api.bindAgent(bind('wg-owner'), {} as never, ownerState)
    expect((await api.links(ownerState)).grants[0]!.aToB).toEqual([{ protocol: 'tcp', port: 1997 }])
  })
})
