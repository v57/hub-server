import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import vectors from './fixtures/device-vectors.json'
import { Hub, security } from '../src/hub'
import { DeviceRegistry, deviceId, newCodeValue } from '../src/devices'
import { cleanName, freeName, normalizeName } from '../src/names'
import { certificate, connect, first, freePort, makeKey, token, until, type Client, type TestKey } from './helpers'

describe('name vectors', () => {
  const { names } = vectors
  test('normalized', () => {
    for (const { input, normalized } of names.normalized) expect(normalizeName(input)).toBe(normalized)
  })
  test('the same name, and not', () => {
    for (const group of names.same) expect(new Set(group.map(normalizeName)).size).toBe(1)
    for (const [a, b] of names.different) expect(normalizeName(a!)).not.toBe(normalizeName(b!))
  })
  test('every lookalike', () => {
    for (const { letter, others } of names.lookalikes) {
      for (const other of others) expect(normalizeName(`q${other}q`)).toBe(normalizeName(`q${letter}q`))
    }
  })
  test('clean', () => {
    for (const { input, clean } of names.clean) expect(cleanName(input)).toBe(clean)
  })
  test('unique', () => {
    for (const { held, asked, name } of names.unique) {
      const taken = new Set(held.map(normalizeName))
      expect(freeName(asked, normalized => taken.has(normalized))).toBe(name)
    }
  })
})

describe('names on the hub', () => {
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
  const nameOf = (id: string) => hub.devices.registry.device(id)?.name
  /** A device asking for `name`, approved */
  async function joined(name: string) {
    const device = makeKey()
    const id = deviceId(device.key)
    const c = client(v1(makeKey(), device, { deviceName: name }))
    await until<any>(c, 'hub/device/request', r => r.status === 'pending')
    await owners.sender.send('hub/device/approve', { id })
    return { device, id, client: c }
  }

  beforeAll(async () => {
    security.addOwner(owner.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    hub.devices.gate.interval = 0
    await hub.ready
    owners = client(v1(owner))
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('the second device asking for a name gets a suffix on approval', async () => {
    const a = await joined('Alex')
    const b = await joined('Alex')
    expect(nameOf(a.id)).toBe('Alex')
    expect(nameOf(b.id)).toBe('Alex-2')
    const c = await joined('Alex')
    expect(nameOf(c.id)).toBe('Alex-3')
  })

  test('lookalikes count as the same name, and the name stays as written', async () => {
    await joined('Sam')
    const cyrillic = await joined('Sаm')
    expect(nameOf(cyrillic.id)).toBe('Sаm-2')
    const spaced = await joined('S A M')
    expect(nameOf(spaced.id)).toBe('S A M-3')
    const invisible = await joined('S​am')
    expect(nameOf(invisible.id)).toBe('S​am-4')
    const original = await joined('Jo Bloggs')
    expect(nameOf(original.id)).toBe('Jo Bloggs')
  })

  test('a pending request holds no name, and a request can not reserve one', async () => {
    const early = makeKey()
    const earlyId = deviceId(early.key)
    const asking = client(v1(makeKey(), early, { deviceName: 'Robin' }))
    await until<any>(asking, 'hub/device/request', r => r.status === 'pending')
    // It came first but isn't approved, so Robin goes to the one approved first
    const robin = await joined('Robin')
    expect(nameOf(robin.id)).toBe('Robin')
    const pending = await until<any[]>(owners, 'hub/devices/pending', list => list.some(d => d.id === earlyId))
    expect(pending.find(d => d.id === earlyId).name).toBe('Robin')
    await owners.sender.send('hub/device/approve', { id: earlyId })
    expect(nameOf(earlyId)).toBe('Robin-2')
    const request = await until<any>(asking, 'hub/device/request', r => r.status === 'approved')
    expect(request.name).toBe('Robin-2')
  })

  test('hub/profile/update names no device, and an anonymous caller can not use it', async () => {
    const device = makeKey()
    const id = deviceId(device.key)
    const asking = client(v1(makeKey(), device, { deviceName: 'Quiet' }))
    await until<any>(asking, 'hub/device/request', r => r.status === 'pending')
    await asking.sender.send('hub/profile/update', { name: 'Robin' })
    expect(nameOf(id)).toBe('Quiet')
    const connections = await first<any[]>(owners, 'hub/connections')
    expect(connections.some(c => c.name === 'Robin')).toBe(false)
    await expect(client().sender.send('hub/profile/update', { name: 'Robin' })).rejects.toThrow('unauthorized')
    // A service with a key keeps its label
    const service = client(v1(makeKey()))
    await service.sender.send('hub/profile/update', { name: 'S3 Backup' })
    await until<any[]>(owners, 'hub/connections', list => list.some(c => c.name === 'S3 Backup'))
  })

  test('an approved device asking again keeps its name, and a new name has to be free', async () => {
    const taken = await joined('Taken')
    const second = await joined('Taken')
    expect(nameOf(second.id)).toBe('Taken-2')
    // Reconnecting with the same suggestion doesn't move it, or free it
    const again = client(v1(makeKey(), second.device, { deviceName: 'Taken' }))
    await again.sender.send('hub/info')
    expect(nameOf(second.id)).toBe('Taken-2')
    const lookalike = client(v1(makeKey(), second.device, { deviceName: 'TAKEN' }))
    await lookalike.sender.send('hub/info')
    expect(nameOf(second.id)).toBe('TAKEN-2')
    const free = client(v1(makeKey(), second.device, { deviceName: 'Fresh' }))
    await free.sender.send('hub/info')
    expect(nameOf(second.id)).toBe('Fresh')
    expect(nameOf(taken.id)).toBe('Taken')
  })

  test('owner-set names win', async () => {
    const asked = await joined('Morgan')
    const other = await joined('Dana')
    // The device that only asked for it moves aside
    expect(await owners.sender.send('hub/device/rename', { id: other.id, name: 'MORGAN' })).toMatchObject({ name: 'MORGAN' })
    expect(nameOf(asked.id)).toBe('Morgan-2')
    // Its suggestions no longer apply
    const again = client(v1(makeKey(), other.device, { deviceName: 'Dana' }))
    await again.sender.send('hub/info')
    expect(nameOf(other.id)).toBe('MORGAN')
    // Another owner-set name isn't moved
    await expect(owners.sender.send('hub/device/rename', { id: asked.id, name: 'morgan' })).rejects.toThrow('name taken')
    expect(nameOf(asked.id)).toBe('Morgan-2')
    // Its own name, written another way, is fine
    expect(await owners.sender.send('hub/device/rename', { id: other.id, name: 'Morgan' })).toMatchObject({ name: 'Morgan' })
  })

  test('a device asking for an owner-set name gets a suffix', async () => {
    const set = await joined('Casey')
    await owners.sender.send('hub/device/rename', { id: set.id, name: 'Blake' })
    const asking = await joined('Blake')
    expect(nameOf(asking.id)).toBe('Blake-2')
  })

  test('removing a device frees its name', async () => {
    const a = await joined('Riley')
    await owners.sender.send('hub/device/remove', { id: a.id })
    const b = await joined('Riley')
    expect(nameOf(b.id)).toBe('Riley')
    await owners.sender.send('hub/device/revoke', { id: b.id })
    const c = await joined('Riley')
    expect(nameOf(c.id)).toBe('Riley')
  })

  test('a caller and a hub network profile see the final name', async () => {
    const a = await joined('Pat')
    const b = await joined('Pat')
    const caller = await until<any[]>(owners, 'hub/devices', list => list.some(d => d.id === b.id && d.name === 'Pat-2'))
    expect(caller.find(d => d.id === a.id).name).toBe('Pat')
    expect(hub.networkAPI!.deviceLabel!(b.id)).toBe('Pat-2')
  })
})

describe('stores from before names were unique', () => {
  const stored = (name: string, createdAt: string, extra: Record<string, unknown> = {}) => ({
    key: name,
    name,
    approved: true,
    createdAt,
    lastSeen: createdAt,
    revoked: null,
    ...extra,
  })
  async function load(devices: Record<string, unknown>) {
    const path = join(mkdtempSync(join(tmpdir(), 'hub-names-')), 'devices.json')
    writeFileSync(path, JSON.stringify({ schema: 1, devices, services: {}, revokedKeys: [] }))
    const registry = await new DeviceRegistry(path).load()
    return { registry, path }
  }

  test('of duplicates the later one is renamed, owner-set names stay', async () => {
    const { registry, path } = await load({
      newest: stored('Alex', '2026-03-01T00:00:00Z'),
      oldest: stored('Alex', '2026-01-01T00:00:00Z'),
      middle: stored('ALEX', '2026-02-01T00:00:00Z'),
      lookalike: stored('Аlex', '2026-04-01T00:00:00Z'),
      setA: stored('Sam', '2026-01-01T00:00:00Z', { nameByOwner: true }),
      setB: stored('Sam', '2026-02-01T00:00:00Z', { nameByOwner: true }),
      asked: stored('sam', '2025-01-01T00:00:00Z'),
      pending: stored('Alex', '2026-05-01T00:00:00Z', { approved: false }),
      gone: stored('Alex', '2025-01-01T00:00:00Z', { revoked: '2026-01-01T00:00:00Z', approved: false }),
    })
    expect(registry.device('oldest')!.name).toBe('Alex')
    expect(registry.device('middle')!.name).toBe('ALEX-2')
    expect(registry.device('newest')!.name).toBe('Alex-3')
    expect(registry.device('lookalike')!.name).toBe('Аlex-4')
    expect(registry.device('setA')!.name).toBe('Sam')
    expect(registry.device('setB')!.name).toBe('Sam')
    expect(registry.device('asked')!.name).toBe('sam-2')
    expect(registry.device('pending')!.name).toBe('Alex')
    expect(registry.device('gone')!.name).toBe('Alex')
    // Written back, with what it asked for
    const written = JSON.parse(readFileSync(path, 'utf8'))
    expect(written.devices.newest.name).toBe('Alex-3')
    expect(written.devices.newest.askedName).toBe('Alex')
  })

  test('every device gets a value it keeps', async () => {
    const value = newCodeValue()
    const { registry, path } = await load({ a: stored('A', '2026-01-01T00:00:00Z', { codeValue: value }), b: stored('B', '2026-01-01T00:00:00Z') })
    expect(registry.device('a')!.codeValue).toBe(value)
    expect(registry.device('b')!.codeValue).toBeString()
    const second = await new DeviceRegistry(path).load()
    expect(second.device('b')!.codeValue).toBe(registry.device('b')!.codeValue)
  })

  test('a store with too many pending requests keeps the newest', async () => {
    const devices: Record<string, unknown> = {}
    for (let i = 0; i < 300; i++) devices[`p${i}`] = stored(`p${i}`, new Date(1_800_000_000_000 + i * 1000).toISOString(), { approved: false })
    const { registry } = await load(devices)
    expect(registry.pendingIds()).toHaveLength(256)
    expect(registry.device('p0')).toBeUndefined()
    expect(registry.device('p299')).toBeDefined()
  })
})
