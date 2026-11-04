import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { Hub, security } from '../src/hub'
import { deviceId } from '../src/devices'
import { HUB_NETWORK_WIRE_VERSION } from '../src/network/wire'
import { certificate, connect, first, freePort, makeKey, token, until, type Client, type TestKey } from './helpers'

describe('Hub Network on the hub', () => {
  const port = freePort()
  const owner = makeKey()
  let hub: Hub
  let owners: Client
  const clients: Client[] = []
  const client = (key: TestKey, device?: TestKey) => {
    const c = connect(port, () => ({
      auth: token(key, security.hubKey, security.nonces),
      v: '1',
      ...(device ? { device: certificate(device, key, { deviceName: 'Agent Box' }) } : {}),
    }))
    clients.push(c)
    return c
  }
  const bind = (c: Client, wireGuardKey: string) =>
    c.sender.send('hub/net/bind', {
      version: HUB_NETWORK_WIRE_VERSION,
      bindingKind: 'apple-app',
      wireGuardKey,
      overlayAddresses: [],
      connectedAt: new Date().toISOString(),
    })

  beforeAll(async () => {
    security.addOwner(owner.key)
    hub = new Hub(port)
    hub.devices.gate.interval = 0
    await hub.ready
    owners = client(owner)
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test("the node is v57's coordinator until an owner sets another", async () => {
    expect(await first(owners, 'hub/net/node')).toBe('wss://v57.dev:1964')
    await owners.sender.send('hub/net/node/set', 'node.example:443')
    expect(await until(owners, 'hub/net/node', value => value === 'node.example:443')).toBe('node.example:443')
    await owners.sender.send('hub/net/node/set', null)
    expect(await until(owners, 'hub/net/node', value => value === 'wss://v57.dev:1964')).toBe('wss://v57.dev:1964')
  })

  test('revoking a device removes its member and tells the other agents', async () => {
    const lostDevice = makeKey()
    const otherDevice = makeKey()
    const lostId = deviceId(lostDevice.key)
    security.addOwner(lostDevice.key)
    security.addOwner(otherDevice.key)
    const lost = client(makeKey(), lostDevice)
    const other = client(makeKey(), otherDevice)
    await bind(lost, 'wg-lost')
    await bind(other, 'wg-other')
    expect(hub.networkAPI!.registry.hasAllocation(`device:${lostId}`)).toBe(true)
    const devices = await until<any[]>(owners, 'hub/devices', list => list.some(d => d.id === lostId && d.network === 'online'))
    const listed = devices.find(d => d.id === lostId)
    expect(listed.overlay.address).toMatch(/^100\./)
    // Both agents ask for the same name, and the second gets a suffix
    expect(listed.overlay.authority).toMatch(/^agent-box(-2)?-[a-z2-7]{16}\.v1-[a-z2-7]{16}\.hub\.invalid$/)

    await owners.sender.send('hub/device/revoke', { id: lostId })
    const revoked = await until<any[]>(other, 'network/devices/revoked', list => list.length > 0)
    expect(revoked).toEqual([{ device: lostId, wireGuardKeys: ['wg-lost'], at: expect.any(String) }])
    expect(hub.networkAPI!.registry.hasAllocation(`device:${lostId}`)).toBe(false)
    const members = await until<any[]>(other, 'network/agents/list', list => !list.some(p => p.wireGuardKey === 'wg-lost'))
    expect(members.some(p => p.wireGuardKey === 'wg-other')).toBe(true)
  })

  test('test routes are owner-only', async () => {
    const user = client(makeKey())
    await expect(user.sender.send('hub/net/test/complete', 'ok')).rejects.toThrow('permissions required')
  })
})
