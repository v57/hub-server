import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { sign } from 'node:crypto'
import { Hub, security } from '../src/hub'
import { deviceId } from '../src/devices'
import { certificate, connect, freePort, makeKey, token, until, type Client, type TestKey } from './helpers'

describe('device reporter, data and selection', () => {
  const port = freePort()
  const owner = makeKey()
  const device = makeKey()
  const id = deviceId(device.key)
  let hub: Hub
  let owners: Client
  const clients: Client[] = []
  const client = (key: TestKey, withDevice?: TestKey, instance = 'test') => {
    const c = connect(port, () => ({
      auth: token(key, security.hubKey),
      v: '1',
      ...(withDevice ? { device: certificate(withDevice, key, { instance, deviceName: 'Studio' }) } : {}),
    }))
    clients.push(c)
    return c
  }
  const listed = (check: (device: any) => boolean) =>
    until<any[]>(owners, 'hub/devices', list => check(list.find(d => d.id === id))).then(list => list.find(d => d.id === id))

  beforeAll(async () => {
    security.addOwner(owner.key)
    security.addOwner(device.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    await hub.ready
    owners = client(owner)
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('the first reporter of a device describes it, others are refused, the next takes over', async () => {
    const first = client(makeKey(), device, 'hub-app')
    const second = client(makeKey(), device, 'launcher')
    await first.sender.send('hub/service/update', { reporter: true })
    await second.sender.send('hub/service/update', { reporter: true })
    await first.sender.send('hub/device/describe', { os: '27.0', arch: 'arm64', capabilities: { cpu: { cores: 24 } } })
    expect(await listed(d => d?.os === '27.0')).toMatchObject({ os: '27.0', arch: 'arm64', capabilities: { cpu: { cores: 24 } } })
    await expect(second.sender.send('hub/device/describe', { os: 'x' })).rejects.toThrow('not the device reporter')
    first.sender.stop()
    await until(owners, 'hub/devices', () => hub.devices.reporter(id) !== undefined && hub.devices.reporter(id)?.instance === 'launcher')
    await second.sender.send('hub/device/describe', { os: '27.1' })
    expect((await listed(d => d?.os === '27.1')).os).toBe('27.1')
  })

  test('connections without a device are never reporters', async () => {
    const plain = client(makeKey())
    await plain.sender.send('hub/service/update', { reporter: true })
    await expect(plain.sender.send('hub/device/data', { cpu: 0.5 })).rejects.toThrow('not the device reporter')
  })

  test('the ssh host key must be signed by the device', async () => {
    const reporter = hub.devices.reporter(id)!
    const hostKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test'
    const signature = sign(null, Buffer.from(`ssh1:${hostKey}`), device.privateKey).toString('base64')
    const r = client(makeKey(), device, 'ssh-reporter')
    await r.sender.send('hub/service/update', { reporter: true })
    // Not the reporter while another one is connected
    await expect(r.sender.send('hub/device/describe', {})).rejects.toThrow('not the device reporter')
    const current = Array.from(hub.connections).find(c => c.state === reporter)!
    const bad = { ssh: { port: 22, hostKey, hostKeySignature: Buffer.alloc(64).toString('base64') } }
    expect(() => hub.devices.describeSelf(current.state, { capabilities: bad })).toThrow('invalid ssh host key signature')
    const ecdsa = 'ecdsa-sha2-nistp256 AAAAE2VjZHNh'
    const ecdsaSignature = sign(null, Buffer.from(`ssh1:${ecdsa}`), device.privateKey).toString('base64')
    const badList = { ssh: { port: 22, hostKey, hostKeySignature: signature, hostKeys: [{ hostKey: ecdsa, hostKeySignature: signature }] } }
    expect(() => hub.devices.describeSelf(current.state, { capabilities: badList })).toThrow('invalid ssh host key signature')
    hub.devices.describeSelf(current.state, {
      capabilities: { ssh: { port: 22, hostKey, hostKeySignature: signature, hostKeys: [{ hostKey: ecdsa, hostKeySignature: ecdsaSignature }] } },
    })
    expect((await listed(d => !!d?.capabilities?.ssh)).capabilities.ssh.hostKey).toBe(hostKey)
  })

  test('live data goes to hub/devices/data subscribers', async () => {
    const reporter = hub.devices.reporter(id)!
    hub.devices.reportData(reporter, { cpu: 0.25, charging: true })
    expect(await until(owners, 'hub/devices/data', (data: any) => data.cpu === 0.25, { id })).toEqual({ cpu: 0.25, charging: true })
    await expect(until(owners, 'hub/devices/data', () => true, { id: 'missing' })).rejects.toThrow('device not found')
    const user = client(makeKey())
    await expect(until(user, 'hub/devices/data', () => true, { id })).rejects.toThrow('permissions required')
  })

  test('a grant opens hub/devices to a non-owner', async () => {
    const viewer = makeKey()
    security.call.allow(viewer.key, ['hub/devices'])
    const list = await until<any[]>(client(viewer), 'hub/devices', list => list.length > 0)
    expect(list.some(d => d.id === id)).toBe(true)
  })

  test('context.device picks a provider on that device', async () => {
    const other = makeKey()
    security.addOwner(other.key)
    const here = client(makeKey(), device, 'build-here')
    const there = client(makeKey(), other, 'build-there')
    here.channel.post('build/run', () => 'here')
    there.channel.post('build/run', () => 'there')
    await here.sender.send('hub/service/update', { services: [{ path: 'build/run' }] })
    await there.sender.send('hub/service/update', { services: [{ path: 'build/run' }] })
    const call = (device: string) => owners.sender.send('build/run', undefined, { context: { device } })
    expect(await call(id)).toBe('here')
    expect(await call(deviceId(other.key))).toBe('there')
    await expect(call('unknown-device')).rejects.toThrow('api not found')
  })
})
