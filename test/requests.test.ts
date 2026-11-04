import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { createHash, randomBytes } from 'node:crypto'
import { Hub, security } from '../src/hub'
import { RequestGate, deviceId, maxPendingDevices, requestSource, safetyCode } from '../src/devices'
import { certificate, connect, first, freePort, makeKey, token, until, waitFor, type Client, type TestKey } from './helpers'

/** The code as it was: 20 bits of the key's hash, so keys could be made offline until one matched */
function codeOfKeyAlone(key: string): string {
  const hash = createHash('sha256').update(Buffer.from(key, 'base64')).digest('hex')
  return (parseInt(hash.slice(0, 8), 16) % 1000000).toString().padStart(6, '0')
}

/** Two keys that share a code under `code`: what grinding gets offline, here by the birthday bound */
function grind(code: (key: string) => string): [TestKey, TestKey] {
  const seen = new Map<string, TestKey>()
  while (true) {
    const key = makeKey()
    const twin = seen.get(code(key.key))
    if (twin) return [twin, key]
    seen.set(code(key.key), key)
  }
}

describe('safety codes on the hub', () => {
  const port = freePort()
  const owner = makeKey()
  let hub: Hub
  const clients: Client[] = []
  const v1 = (key: TestKey, device?: TestKey, fields?: Record<string, unknown>) => () => ({
    auth: token(key, security.hubKey, security.nonces),
    v: '1',
    ...(device ? { device: certificate(device, key, fields) } : {}),
  })
  const client = (headers?: () => Record<string, string>) => {
    const c = connect(port, headers)
    clients.push(c)
    return c
  }
  let owners: Client
  const pending = (id: string, timeout = 6000) =>
    until<any[]>(owners, 'hub/devices/pending', list => list.some(d => d.id === id), undefined, timeout).then(list => list.find(d => d.id === id))

  beforeAll(async () => {
    security.addOwner(owner.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    hub.devices.gate.interval = 100
    await hub.ready
    owners = client(v1(owner))
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('grinding keys against a fixed value no longer predicts the code', async () => {
    const fixed = randomBytes(32).toString('base64url')
    // Offline the attack still works for the code it was made for
    const [oldA, oldB] = grind(codeOfKeyAlone)
    expect(codeOfKeyAlone(oldA.key)).toBe(codeOfKeyAlone(oldB.key))
    const offline = (key: string) => safetyCode(security.hubKey!, key, fixed)
    const [a, b] = grind(offline)
    expect(offline(a.key)).toBe(offline(b.key))
    // A hub picks its own value once it has the key, so the twins come apart
    client(v1(makeKey(), a, { deviceName: 'Twin' }))
    client(v1(makeKey(), b, { deviceName: 'Twin' }))
    const [first_, second] = await Promise.all([pending(deviceId(a.key)), pending(deviceId(b.key))])
    expect(first_.codeValue).not.toBe(fixed)
    expect(second.codeValue).not.toBe(fixed)
    expect(first_.codeValue).not.toBe(second.codeValue)
    expect(first_.safetyCode).toBe(safetyCode(security.hubKey!, a.key, first_.codeValue))
    expect(second.safetyCode).toBe(safetyCode(security.hubKey!, b.key, second.codeValue))
    // One in a million each; a real twin here would be a bug in what the code covers
    expect(first_.safetyCode).not.toBe(second.safetyCode)
    expect(first_.safetyCode).not.toBe(offline(a.key))
  })

  test('the device gets the value and computes the code the owner sees', async () => {
    const device = makeKey()
    const id = deviceId(device.key)
    const asking = client(v1(makeKey(), device, { deviceName: 'New Phone' }))
    const request = await until<any>(asking, 'hub/device/request', r => r.status === 'pending')
    expect(request).toMatchObject({ id, name: 'New Phone' })
    const row = await pending(id)
    expect(safetyCode(security.hubKey!, device.key, request.codeValue)).toBe(row.safetyCode)
    // Approval reaches it on the same stream, with its final name
    const approved = until<any>(asking, 'hub/device/request', r => r.status === 'approved')
    await owners.sender.send('hub/device/approve', { id })
    expect(await approved).toMatchObject({ id, name: 'New Phone', codeValue: request.codeValue })
  })

  test('a request sent again with the same key keeps its value', async () => {
    const device = makeKey()
    const id = deviceId(device.key)
    const a = client(v1(makeKey(), device))
    const { codeValue } = await until<any>(a, 'hub/device/request', r => r.status === 'pending')
    a.sender.stop()
    const b = client(v1(makeKey(), device))
    expect((await until<any>(b, 'hub/device/request', r => r.status === 'pending')).codeValue).toBe(codeValue)
    expect((await pending(id)).codeValue).toBe(codeValue)
  })

  test('a connection without a certificate has no request', async () => {
    await expect(first(client(v1(makeKey())), 'hub/device/request')).rejects.toThrow('no device certificate')
    await expect(first(client(), 'hub/device/request')).rejects.toThrow('unauthorized')
  })

  test('new requests are limited across the hub, however many addresses they come from', async () => {
    hub.devices.gate.interval = 400
    const before = hub.devices.registry.pendingIds().length
    const started = Date.now()
    const devices = Array.from({ length: 6 }, () => makeKey())
    devices.forEach((device, index) => {
      const key = makeKey()
      const certificateHeader = certificate(device, key)
      // Each as if from another address: the channel server sets this header, so test the gate behind it
      hub.devices.gate.ask(`198.51.100.${index}`, {
        deviceId: deviceId(device.key),
        certificate: { device: device.key, deviceId: deviceId(device.key), service: key.key, instance: certificateHeader.slice(0, 8), iat: 0, exp: 0 },
        state: {} as any,
      })
    })
    expect(hub.devices.registry.pendingIds().length).toBeLessThanOrEqual(before + 1)
    await waitFor(() => hub.devices.registry.pendingIds().length >= before + 3, 5000)
    expect(Date.now() - started).toBeGreaterThanOrEqual(2 * 400 - 20)
    await waitFor(() => hub.devices.registry.pendingIds().length >= before + 6, 5000)
    expect(Date.now() - started).toBeGreaterThanOrEqual(5 * 400 - 20)
    hub.devices.gate.interval = 100
  })

  test('a device approved while waiting needs no turn', async () => {
    hub.devices.gate.interval = 60000
    await Bun.sleep(150)
    const blocker = makeKey()
    const first_ = client(v1(makeKey(), blocker))
    await first_.sender.send('hub/info')
    const device = makeKey()
    const id = deviceId(device.key)
    const waiting = client(v1(makeKey(), device))
    await waiting.sender.send('hub/info')
    expect((await until<any>(waiting, 'hub/device/request', () => true)).status).toBe('waiting')
    expect(hub.devices.registry.device(id)).toBeUndefined()
    hub.devices.approveConnection(Array.from(hub.connections, c => c.state).find(s => s.certificate?.deviceId === id)!)
    expect(hub.devices.registry.device(id)?.approved).toBe(true)
    expect(hub.devices.gate.has(id)).toBe(false)
    hub.devices.gate.interval = 100
  })
})

describe('RequestGate', () => {
  const made = () => {
    const admitted: string[] = []
    const gate = new RequestGate<{ deviceId: string }>(request => admitted.push(request.deviceId))
    return { admitted, gate }
  }

  test('sources take turns, so one flooding address does not push others out', async () => {
    const { admitted, gate } = made()
    gate.interval = 30
    for (let i = 0; i < 8; i++) gate.ask('flood', { deviceId: `flood${i}` })
    gate.ask('real', { deviceId: 'real' })
    await waitFor(() => admitted.includes('real'), 1000)
    // The first went at once, with nothing waiting; then the two sources in turn
    expect(admitted).toEqual(['flood0', 'flood1', 'real'])
  })

  test('what waits is bounded per source and in all', async () => {
    const { admitted, gate } = made()
    gate.interval = 3600_000
    for (let i = 0; i < 100; i++) gate.ask('one', { deviceId: `one${i}` })
    for (let i = 0; i < 10_000; i++) gate.ask(`source${i}`, { deviceId: `source${i}` })
    let waiting = 0
    for (const requests of (gate as any).waiting.values()) waiting += requests.length
    // The first was admitted at once. Then one source of 8, and the rest of 4,096 sources with one each
    expect(admitted).toEqual(['one0'])
    expect(waiting).toBe(8 + 4095)
    gate.forget(() => true)
  })

  test('a request asked twice waits once', () => {
    const { admitted, gate } = made()
    gate.interval = 3600_000
    gate.ask('a', { deviceId: 'first' })
    gate.ask('a', { deviceId: 'twice' })
    gate.ask('b', { deviceId: 'twice' })
    expect(admitted).toEqual(['first'])
    expect((gate as any).waiting.size).toBe(1)
    gate.forget(() => true)
  })

  test('source addresses', () => {
    expect(requestSource(undefined)).toBe('unknown')
    expect(requestSource('192.0.2.1')).toBe('192.0.2.1')
    expect(requestSource('::ffff:192.0.2.1')).toBe('192.0.2.1')
    expect(requestSource('2001:db8:1:2:3:4:5:6')).toBe('2001:db8:1:2::/64')
    expect(requestSource('2001:db8:1:2:ffff::1')).toBe('2001:db8:1:2::/64')
    expect(requestSource('2001:DB8:0001:0002::1')).toBe('2001:db8:1:2::/64')
    expect(requestSource('fe80::1%en0')).toBe('fe80:0:0:0::/64')
    expect(requestSource('::1')).toBe('0:0:0:0::/64')
  })
})

describe('the pending list', () => {
  test('stays bounded, pushing out the oldest offline request', async () => {
    const port = freePort()
    const hub = new Hub(port)
    hub.devices.gate.interval = 0
    await hub.ready
    const { registry } = hub.devices
    const now = Date.now()
    for (const id of registry.pendingIds()) delete registry.data.devices[id]
    for (let i = 0; i < maxPendingDevices; i++) {
      registry.data.devices[`old${i}`] = {
        key: `key${i}`,
        name: `old${i}`,
        approved: false,
        createdAt: new Date(now - 10_000_000 + i).toISOString(),
        lastSeen: '',
        revoked: null,
      }
    }
    const device = makeKey()
    const c = connect(port, () => ({ auth: token(device, security.hubKey, security.nonces), v: '1', device: certificate(device, device) }))
    await c.sender.send('hub/info')
    await waitFor(() => registry.device(deviceId(device.key)))
    expect(registry.pendingIds().length).toBeLessThanOrEqual(maxPendingDevices)
    expect(registry.device('old0')).toBeUndefined()
    expect(registry.device('old1')).toBeDefined()
    c.sender.stop()
    for (const id of registry.pendingIds()) delete registry.data.devices[id]
  })
})
