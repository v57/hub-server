import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { Hub, security } from '../src/hub'
import { deviceId } from '../src/devices'
import { certificate, connect, first, freePort, makeKey, token, type Client, type TestKey } from './helpers'

describe('one-shot reads of hub streams', () => {
  const port = freePort()
  const owner = makeKey()
  let owners: Client
  const clients: Client[] = []
  const client = (key: TestKey, device?: TestKey) => {
    const c = connect(port, () => ({
      auth: token(key, security.hubKey),
      v: '1',
      ...(device ? { device: certificate(device, key) } : {}),
    }))
    clients.push(c)
    return c
  }
  beforeAll(async () => {
    security.addOwner(owner.key)
    const hub = new Hub(port)
    await hub.ready
    owners = client(owner)
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('the first value after a change made with no subscribers is current', async () => {
    const device = makeKey()
    const id = deviceId(device.key)
    security.addOwner(device.key)
    await client(makeKey(), device).sender.send('hub/info')
    await Bun.sleep(200)
    expect((await first<any[]>(owners, 'hub/devices')).find(d => d.id === id)).toMatchObject({ approved: true })
    await Bun.sleep(200)
    await owners.sender.send('hub/device/revoke', { id })
    expect((await first<any[]>(owners, 'hub/devices')).find(d => d.id === id)).toMatchObject({ revoked: true, approved: false })
    const grant = await owners.sender.send('hub/grant/add', { subject: { everyone: true }, object: { path: 'x' } })
    expect((await first<any[]>(owners, 'hub/grants')).some(g => g.id === grant.id)).toBe(true)
    await owners.sender.send('hub/group/create', { name: 'Anna', person: true })
    expect((await first<any[]>(owners, 'hub/groups')).find(g => g.id === 'Anna')).toMatchObject({ person: true })
    await owners.sender.send('hub/security/mode/set', { requireV1: true })
    expect(await first(owners, 'hub/security/mode')).toMatchObject({ requireV1: true })
    await owners.sender.send('hub/security/mode/set', { requireV1: false })
  })
})
