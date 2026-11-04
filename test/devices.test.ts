import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import vectors from './fixtures/device-vectors.json'
import { Hub, security } from '../src/hub'
import { deviceId, safetyCode, verifyCertificate, type Certificate } from '../src/devices'
import { certificate, connect, first, freePort, makeKey, token, until, waitFor, type Client, type TestKey } from './helpers'

const { keys } = vectors

describe('device vectors', () => {
  test('device id and safety code', () => {
    expect(deviceId(keys.device.publicKey)).toBe(keys.device.deviceId)
    expect(safetyCode(keys.device.publicKey)).toBe(keys.device.safetyCode)
  })
  test('the certificate payload is the base64url of its JSON', () => {
    expect(Buffer.from(vectors.certificate.json).toString('base64url')).toBe(vectors.certificate.payload)
    expect(vectors.certificate.header).toBe(`${vectors.certificate.payload}.${vectors.certificate.signature}`)
  })
  test('the certificate verifies for its service key', () => {
    const result = verifyCertificate(vectors.certificate.header, keys.service.publicKey, keys.hub.publicKey, 1792500010)
    expect(result).toEqual({
      device: keys.device.publicKey,
      deviceId: keys.device.deviceId,
      service: keys.service.publicKey,
      instance: 's3-local/Backup Disk',
      deviceName: 'Mac Studio',
      platform: 'macos',
      parent: undefined,
      iat: 1792500000,
      exp: 1793104800,
    })
  })
  test('the child certificate declares its parent', () => {
    const result = verifyCertificate(vectors.childCertificate.header, keys.service.publicKey, undefined, 1792500010)
    expect((result as Certificate).parent).toBe('Mac Studio')
    expect((result as Certificate).platform).toBe('linux')
  })
  test('another service key is refused', () => {
    expect(verifyCertificate(vectors.certificate.header, keys.device.publicKey, undefined, 1792500010)).toBe(
      'certificate is for another service key',
    )
  })
  test('a changed payload is refused', () => {
    const json = vectors.certificate.json.replace('Backup Disk', 'Other Disk')
    const header = `${Buffer.from(json).toString('base64url')}.${vectors.certificate.signature}`
    expect(verifyCertificate(header, keys.service.publicKey, undefined, 1792500010)).toBe('invalid certificate signature')
  })
  test('times are checked with 30 s of skew', () => {
    const verifyAt = (now: number) => verifyCertificate(vectors.certificate.header, keys.service.publicKey, undefined, now)
    expect(typeof verifyAt(1792500000 - 30)).toBe('object')
    expect(verifyAt(1792500000 - 31)).toBe('certificate issued in the future')
    expect(typeof verifyAt(1793104800 + 29)).toBe('object')
    expect(verifyAt(1793104800 + 30)).toBe('certificate expired')
  })
  test('fields are checked', () => {
    const device = makeKey()
    const service = makeKey()
    const check = (fields: Record<string, unknown>, hub?: string) =>
      verifyCertificate(certificate(device, service, fields), service.key, hub)
    expect(check({ exp: Math.floor(Date.now() / 1000) + 604801 })).toBe('certificate lifetime too long')
    expect(check({ instance: '' })).toBe('invalid instance')
    expect(check({ instance: 'x'.repeat(129) })).toBe('invalid instance')
    expect(check({ deviceName: 'x'.repeat(65) })).toBe('invalid device name or parent')
    expect(check({ v: 2 })).toBe('unsupported certificate version')
    expect(check({ hub: 'other' }, 'mine')).toBe('certificate is for another hub')
    expect(typeof check({ hub: 'mine' }, 'mine')).toBe('object')
    expect((check({ platform: 'beos' }) as Certificate).platform).toBe('other')
    expect(verifyCertificate('abc', service.key, undefined)).toBe('malformed certificate')
  })
})

describe('devices on the hub', () => {
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
  const listed = (id: string, check: (device: any) => boolean = d => !!d) =>
    until<any[]>(owners, 'hub/devices', list => check(list.find(d => d.id === id))).then(list => list.find(d => d.id === id))
  const pendingHas = (id: string, has: boolean) =>
    until<any[]>(owners, 'hub/devices/pending', list => list.some(d => d.id === id) === has).then(list => list.find(d => d.id === id))

  /** A service that echoes the caller it gets */
  async function echoService(key: TestKey, device: TestKey, path: string, fields?: Record<string, unknown>) {
    security.host.allow(key.key, [path])
    const service = client(v1(key, device, fields))
    service.channel.post(path, ({ context }) => context.hub.caller)
    await service.sender.send('hub/service/update', { services: [{ path, public: true }] })
    return service
  }

  beforeAll(async () => {
    security.addOwner(owner.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    await hub.ready
    owners = client(v1(owner))
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('the hub enrols its own device', async () => {
    const own = await listed(hub.devices.selfId!)
    expect(own).toMatchObject({ approved: true, online: true })
    expect(own.services[0]).toMatchObject({ key: security.hubKey, instance: 'hub-server' })
  })

  test('a new device is pending until approved, then its connections are device connections', async () => {
    const device = makeKey()
    const service = makeKey()
    const id = deviceId(device.key)
    const caller = client(v1(service, device, { deviceName: 'Phone', platform: 'ios', instance: 'app' }))
    expect(await caller.sender.send('hub/info')).toMatchObject({ protocol: 2 })
    expect(await pendingHas(id, true)).toMatchObject({
      key: device.key,
      name: 'Phone',
      platform: 'ios',
      safetyCode: safetyCode(device.key),
    })
    const echo = await echoService(makeKey(), makeKey(), 'devices/echo1')
    expect(await caller.sender.send('devices/echo1')).toEqual({ key: service.key, groups: [], owner: false })

    const approved = await owners.sender.send('hub/device/approve', { id })
    expect(approved).toMatchObject({ id, approved: true, online: true, name: 'Phone' })
    expect(approved.services).toEqual([{ key: service.key, instance: 'app', online: true, paths: [] }])
    await pendingHas(id, false)
    expect(await caller.sender.send('devices/echo1')).toEqual({
      key: service.key,
      device: { id, name: 'Phone' },
      groups: [],
      owner: false,
    })
    void echo
  })

  test('an owner key with a certificate approves its device at once', async () => {
    const device = makeKey()
    const id = deviceId(device.key)
    const c = client(v1(owner, device, { deviceName: 'Mac Studio' }))
    await c.sender.send('hub/info')
    expect(await listed(id)).toMatchObject({ approved: true, online: true })
  })

  test('a certificate works on a v0 connect too', async () => {
    const device = makeKey()
    const service = makeKey()
    security.addOwner(device.key)
    security.setMode({ requireV1: false })
    try {
      const c = client(() => ({ auth: token(service), v: '0', device: certificate(device, service, { deviceName: 'Old SDK' }) }))
      await c.sender.send('hub/info')
      expect(await listed(deviceId(device.key), d => d?.online)).toMatchObject({ name: 'Old SDK', approved: true })
    } finally {
      security.setMode({ requireV1: true })
    }
  })

  test('an owner device makes every service on it an owner', async () => {
    const device = makeKey()
    security.addOwner(device.key)
    const service = makeKey()
    await echoService(makeKey(), makeKey(), 'devices/echo2')
    const c = client(v1(service, device, { deviceName: 'Laptop' }))
    expect(await c.sender.send('devices/echo2')).toEqual({
      key: service.key,
      device: { id: deviceId(device.key), name: 'Laptop' },
      groups: ['owners'],
      owner: true,
    })
    expect(await c.sender.send('hub/key')).toBe(security.hubKey)
  })

  test('hub/api/services lists the device and instance of each provider', async () => {
    const device = makeKey()
    const key = makeKey()
    await owners.sender.send('hub/info')
    security.addOwner(device.key)
    await echoService(key, device, 'devices/echo3', { deviceName: 'Disk Box', instance: 's3-local/Backup Disk' })
    const providers = await first(client(v1(makeKey())), 'hub/api/services', 'devices/echo3')
    expect(providers).toHaveLength(1)
    expect(providers[0]).toMatchObject({
      key: key.key,
      device: { id: deviceId(device.key), name: 'Disk Box' },
      instance: 's3-local/Backup Disk',
      online: true,
    })
    expect(typeof providers[0].id).toBe('string')
    const entry = await listed(deviceId(device.key), d => d?.services[0]?.paths.length)
    expect(entry.services[0]).toMatchObject({ key: key.key, paths: ['devices/echo3'], online: true })
  })

  test('rename keeps the owner name over the device suggestion', async () => {
    const device = makeKey()
    const id = deviceId(device.key)
    security.addOwner(device.key)
    const service = makeKey()
    const c = client(v1(service, device, { deviceName: 'iPhone' }))
    await c.sender.send('hub/info')
    expect(await owners.sender.send('hub/device/rename', { id, name: 'Work Phone' })).toMatchObject({ name: 'Work Phone' })
    const again = client(v1(makeKey(), device, { deviceName: 'iPhone' }))
    await again.sender.send('hub/info')
    expect((await listed(id)).name).toBe('Work Phone')
    await expect(owners.sender.send('hub/device/rename', { id: 'nope', name: 'x' })).rejects.toThrow('device not found')
  })

  test('a service key moving to another device records the previous one', async () => {
    const first = makeKey()
    const second = makeKey()
    const service = makeKey()
    security.addOwner(first.key)
    security.addOwner(second.key)
    const a = client(v1(service, first))
    await a.sender.send('hub/info')
    a.sender.stop()
    const b = client(v1(service, second))
    await b.sender.send('hub/info')
    expect(hub.devices.registry.data.services[service.key]).toMatchObject({
      device: deviceId(second.key),
      previousDevice: deviceId(first.key),
    })
  })

  test('removing a device closes its connections and lets it enrol again as pending', async () => {
    const device = makeKey()
    const id = deviceId(device.key)
    const service = makeKey()
    const c = client(v1(service, device))
    await c.sender.send('hub/info')
    await owners.sender.send('hub/device/approve', { id })
    let closed = false
    c.sender.onStateChange?.(state => {
      if (state !== 'connected') closed = true
    })
    await owners.sender.send('hub/device/remove', { id })
    await waitFor(() => closed)
    await until<any[]>(owners, 'hub/devices', list => !list.some(d => d.id === id))
    const again = client(v1(service, device))
    await again.sender.send('hub/info')
    await pendingHas(id, true)
  })

  test('revoking a device closes it, revokes its keys and ignores its certificates', async () => {
    const device = makeKey()
    const id = deviceId(device.key)
    const lost = makeKey()
    const kept = makeKey()
    security.addOwner(device.key)
    security.call.allow(lost.key, ['devices/echo1'])
    const a = client(v1(lost, device))
    const b = client(v1(kept, device))
    await Promise.all([a.sender.send('hub/info'), b.sender.send('hub/info')])
    await owners.sender.send('hub/device/revoke', { id, keepServices: [kept.key] })
    expect(await listed(id, d => d?.revoked)).toMatchObject({ revoked: true, approved: false })
    expect(hub.devices.registry.isKeyRevoked(lost.key)).toBe(true)
    expect(hub.devices.registry.isKeyRevoked(kept.key)).toBe(false)
    expect(security.call.allows(lost.key, 'devices/echo1')).toBe(false)
    expect(security.isOwner({ device: id })).toBe(false)
    // The revoked key can't connect, the kept one connects as a plain key
    await expect(client(v1(lost)).sender.send('hub/info')).rejects.toThrow('disconnected')
    const plain = client(v1(kept, device))
    expect(await plain.sender.send('devices/echo1')).toEqual({ key: kept.key, groups: [], owner: false })
    await expect(owners.sender.send('hub/device/approve', { id })).rejects.toThrow('device revoked')
  })

  test('device APIs are owner-only', async () => {
    const user = client(v1(makeKey()))
    await expect(user.sender.send('hub/device/approve', { id: 'x' })).rejects.toThrow('permissions required')
    await expect(first(user, 'hub/devices')).rejects.toThrow('permissions required')
    await expect(first(user, 'hub/devices/pending')).rejects.toThrow('permissions required')
  })
})
