import { beforeEach, describe, expect, test } from 'bun:test'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { NetworkAPI } from '../src/network/api'
import { signEnvelope } from '../src/network/crypto'
import { deviceAuthority } from '../src/network/foundation'
import { HUB_NETWORK_WIRE_VERSION, type AgentAttestation, type AgentBindRequest } from '../src/network/wire'
import { Security } from '../src/security'
import type { State } from '../src/hub'
import type { Certificate } from '../src/devices'
import { makeKey, type TestKey } from './helpers'

const deviceA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
const deviceB = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

/** A connection of `key`, attached to `device` or with a pending certificate from it */
function state(key: TestKey, device?: string, attached = true): State {
  const certificate = device ? ({ deviceId: device, service: key.key, instance: 'agent' } as Certificate) : undefined
  return {
    id: crypto.randomUUID(),
    key: key.key,
    services: new Set(),
    apps: new Set(),
    certificate,
    device: attached ? device : undefined,
  }
}

const bind = (wireGuardKey: string): AgentBindRequest => ({
  version: HUB_NETWORK_WIRE_VERSION,
  bindingKind: 'apple-app',
  wireGuardKey,
  overlayAddresses: [],
  connectedAt: new Date().toISOString(),
  name: 'Mac Studio',
})

describe('Hub Network members by device', () => {
  let security: Security
  let api: NetworkAPI
  beforeEach(async () => {
    process.chdir(mkdtempSync(join(tmpdir(), 'hub-server-network-')))
    security = new Security()
    api = new NetworkAPI(security)
    await api.registry.load()
  })
  const owner = () => {
    const key = makeKey()
    security.addOwner(key.key)
    return key
  }

  test('a device-attached agent is stored as device:<id> with a device name', async () => {
    const agent = owner()
    const result = await api.bindAgent(bind('wg-a'), {} as never, state(agent, deviceA))
    expect(result.profile.key).toBe(agent.key)
    expect(api.registry.hasAllocation(`device:${deviceA}`)).toBe(true)
    expect(api.registry.hasAllocation(agent.key)).toBe(false)
    expect(api.registry.data.members[`device:${deviceA}`]).toMatchObject({ key: agent.key, device: deviceA, wireGuardKey: 'wg-a' })
    expect(result.profile).toMatchObject({ key: agent.key, member: `device:${deviceA}`, device: deviceA })
    const member = api.listMembers().find(profile => profile.key === agent.key)!
    expect(member).toMatchObject({ member: `device:${deviceA}`, device: deviceA, online: true })
    const authority = deviceAuthority(api.registry.getIdentity().hubNetworkId, deviceA, 'Mac Studio')
    expect(member.deviceAuthority).toBe(authority)
    expect(member.deviceAuthority).toMatch(/^mac-studio-[a-z2-7]{16}\.v1-[a-z2-7]{16}\.hub\.invalid$/)
    expect(api.deviceNetworkState(deviceA)).toBe('online')
    expect(api.deviceOverlay(deviceA)).toEqual({ address: result.profile.overlayAddresses[0], authority })
    // Offline members keep their member key and device
    api.agents.unregisterProfile(agent.key)
    expect(api.listMembers()[0]).toMatchObject({ key: agent.key, member: `device:${deviceA}`, device: deviceA, online: false })
  })

  test('a legacy agent keeps its key as member and its addresses when its device appears', async () => {
    const agent = owner()
    const legacy = await api.bindAgent(bind('wg-a'), {} as never, state(agent))
    expect(api.registry.hasAllocation(agent.key)).toBe(true)
    expect(legacy.profile.member).toBe(agent.key)
    expect(legacy.profile.device).toBeUndefined()
    const attached = await api.bindAgent(bind('wg-a'), {} as never, state(agent, deviceA))
    expect(attached.profile.overlayAddresses).toEqual(legacy.profile.overlayAddresses)
    expect(api.registry.hasAllocation(agent.key)).toBe(false)
    expect(api.registry.hasAllocation(`device:${deviceA}`)).toBe(true)
  })

  test('a second agent key on a device is refused while the first is online, and takes over once it is offline', async () => {
    const first = owner()
    const second = owner()
    const firstState = state(first, deviceA)
    const bound = await api.bindAgent(bind('wg-a'), {} as never, firstState)
    const againState = state(first, deviceA)
    const again = await api.bindAgent(bind('wg-a'), {} as never, againState)
    expect(again.profile.key).toBe(first.key)
    await expect(api.bindAgent(bind('wg-b'), {} as never, state(second, deviceA))).rejects.toMatchObject({
      code: 'device_endpoint_exists',
    })
    // A reinstall: the old agent is gone, the new key keeps the addresses with its own WireGuard key
    api.handleDisconnect(firstState)
    api.handleDisconnect(againState)
    const replaced = await api.bindAgent(bind('wg-b'), {} as never, state(second, deviceA))
    expect(replaced.profile.overlayAddresses).toEqual(bound.profile.overlayAddresses)
    expect(api.registry.data.members[`device:${deviceA}`]).toMatchObject({ key: second.key, wireGuardKey: 'wg-b' })
    // Now the first key is the one refused
    await expect(api.bindAgent(bind('wg-a'), {} as never, state(first, deviceA))).rejects.toMatchObject({
      code: 'device_endpoint_exists',
    })
  })

  test('a bind with a pending certificate approves the device first', async () => {
    const agent = owner()
    const pending = state(agent, deviceA, false)
    const approved: string[] = []
    api.onBindApprove = s => {
      approved.push(s.certificate!.deviceId)
      s.device = s.certificate!.deviceId
    }
    await api.bindAgent(bind('wg-a'), {} as never, pending)
    expect(approved).toEqual([deviceA])
    expect(api.registry.hasAllocation(`device:${deviceA}`)).toBe(true)
  })

  test('removing a device drops its member, releases its addresses and lists its WireGuard key as revoked', async () => {
    const agent = owner()
    const lost = owner()
    await api.bindAgent(bind('wg-a'), {} as never, state(agent, deviceA))
    await api.bindAgent(bind('wg-lost'), {} as never, state(lost))
    let pushed = 0
    api.onRevokedDevicesChanged = () => pushed++
    api.removeDevice(deviceA, [lost.key])
    expect(api.registry.hasAllocation(`device:${deviceA}`)).toBe(false)
    expect(api.registry.hasAllocation(lost.key)).toBe(false)
    expect(api.registry.data.released).toHaveLength(2)
    expect(api.listMembers()).toEqual([])
    expect(api.deviceNetworkState(deviceA)).toBeUndefined()
    expect(pushed).toBe(1)
    const revoked = api.revokedDevices(state(owner()))
    expect(revoked).toHaveLength(1)
    expect(revoked[0].device).toBe(deviceA)
    expect(revoked[0].wireGuardKeys.sort()).toEqual(['wg-a', 'wg-lost'])
    expect(api.revokedDevices(state(makeKey()))).toEqual([])
  })

  test('a removed device that binds again leaves the revoked list', async () => {
    const agent = owner()
    await api.bindAgent(bind('wg-a'), {} as never, state(agent, deviceA))
    api.removeDevice(deviceA)
    expect(api.registry.data.revokedDevices).toHaveLength(1)
    await api.bindAgent(bind('wg-a2'), {} as never, state(agent, deviceA))
    expect(api.registry.data.revokedDevices).toEqual([])
  })

  test('released addresses are reused a day later once the range runs out', () => {
    const registry = api.registry
    const first = registry.allocateAddresses('one')
    registry.removeMember('one')
    registry.data.nextIPv4 = (BigInt(registry.data.lastIPv4) + 1n).toString()
    expect(() => registry.allocateAddresses('two')).toThrow('overlay address exhausted')
    registry.data.released[0].at = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString()
    expect(registry.allocateAddresses('two')).toEqual(first)
  })

  test('a share fronted by an agent on another device is refused', async () => {
    const agent = owner()
    const service = makeKey()
    await api.bindAgent(bind('wg-a'), {} as never, state(agent, deviceA))
    const now = Date.now()
    const share = (serviceState: State) => {
      const attestation: AgentAttestation = {
        version: HUB_NETWORK_WIRE_VERSION,
        attestationId: crypto.randomUUID(),
        serviceKey: service.key,
        key: agent.key,
        shareName: 'files',
        protocol: 'tcp',
        target: { host: '127.0.0.1', port: 9000 },
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 60_000).toISOString(),
        signature: '',
      }
      attestation.signature = signEnvelope('agent-attestation', attestation, agent.privateKey)
      return () =>
        api.handleSharesReplace(
          [{ version: HUB_NETWORK_WIRE_VERSION, name: 'files', protocol: 'tcp', target: attestation.target, attestation }],
          {} as never,
          serviceState,
        )
    }
    expect(share(state(service, deviceB))).toThrow(expect.objectContaining({ code: 'share_device_mismatch' }))
    expect(share(state(service, deviceA))()[0]).toMatchObject({ protocol: 'tcp', port: 9000 })
  })

  test('a member finds the device sharing its internet and gets a grant for it, also once its profile is dropped', async () => {
    const mac = owner()
    await api.bindAgent(bind('wg-mac'), {} as never, state(mac, deviceA))
    api.advertiseGateway({
      version: HUB_NETWORK_WIRE_VERSION, capability: 'internet-gateway-v1', ipv4: true, ipv6: false, dns: true, metered: false,
      updatedAt: new Date().toISOString(),
    }, '192.168.0.10:51820', state(mac, deviceA))
    const air = makeKey()
    api.registry.allocateAddresses(`device:${deviceB}`)
    await api.bindAgent({ ...bind('wg-air'), bindingKind: 'join' }, {} as never, state(air, deviceB))
    const grant = (caller: State, key: string, wireGuardKey: string) =>
      api.issueGatewayGrant(key, wireGuardKey, mac.key, { ipv4: true, ipv6: false, dns: true }, caller)
    for (const dropped of [false, true]) {
      if (dropped) api.agents.unregisterProfile(air.key)
      const caller = state(air, deviceB)
      expect(api.listGateways(caller).map(gateway => gateway.key)).toEqual([mac.key])
      expect(api.listAgents(caller).some(profile => profile.key === mac.key)).toBe(true)
      expect((await grant(caller, air.key, 'wg-air')).clientWireGuardKey).toBe('wg-air')
      await expect(grant(caller, air.key, 'wg-other')).rejects.toMatchObject({ code: 'gateway_not_authorized' })
    }
    // Another key on that device isn't its member, nor is a stranger
    for (const other of [state(makeKey(), deviceB), state(makeKey())]) {
      expect(api.listGateways(other)).toEqual([])
      expect(api.listAgents(other).some(profile => profile.key === mac.key)).toBe(false)
      await expect(grant(other, other.key!, 'wg-air')).rejects.toMatchObject({ code: 'unauthorized' })
    }
  })
})
