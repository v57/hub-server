import { beforeEach, describe, expect, test } from 'bun:test'
import { createPublicKey, sign } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { NetworkAPI, hostRoute } from '../src/network/api'
import { signEnvelope, verifyEnvelope } from '../src/network/crypto'
import { HUB_NETWORK_WIRE_VERSION, type AgentBindRequest, type AppleAppAgentReadinessAssertion } from '../src/network/wire'
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

  test('members get a signed hub link to the hub\'s machine', async () => {
    // The hub's machine: an owner bound as the Apple app agent
    const machine = owner()
    const machineState = state(machine)
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
})
