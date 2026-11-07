import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { createPrivateKey, createPublicKey, verify } from 'node:crypto'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import vectors from './fixtures/device-vectors.json'
import { Hub, security, forwardedContext } from '../src/hub'
import { HubSettings } from '../src/settings'
import { builtinAccess, Security } from '../src/security'
import type { TokenNonces } from '../src/nonces'
import { connect, freePort, makeKey, token, waitFor, type Client } from './helpers'

const acceptingNonces = { isValid: () => true, consume: () => true } as unknown as TokenNonces
const verifyToken = (security: Security, header: string, version?: string, hubKey?: string) =>
  security.keys.verify(header, security.whitelist, { version, hubKey, nonces: acceptingNonces })

describe('auth token vectors', () => {
  const { auth, keys } = vectors
  const atExpiry = <T>(action: () => T): T => {
    const now = Date.now
    Date.now = () => (auth.expiry - 60) * 1000
    try {
      return action()
    } finally {
      Date.now = now
    }
  }
  test('v0 signs the expiry', () => {
    const s = new Security()
    expect(atExpiry(() => verifyToken(s, auth.v0.header, '0'))).toBe(keys.service.publicKey)
    expect(atExpiry(() => verifyToken(s, auth.v0.header))).toBe(keys.service.publicKey)
  })
  test('v1 signs hub1:<hub key>:<nonce>:<expiry>', () => {
    const s = new Security()
    expect(atExpiry(() => verifyToken(s, auth.v1.header, '1', keys.hub.publicKey))).toBe(keys.service.publicKey)
    const key = createPublicKey({ key: Buffer.from(keys.service.publicKey, 'base64'), format: 'der', type: 'spki' })
    expect(verify(null, Buffer.from(auth.v1.signedData), key, Buffer.from(auth.v1.signature, 'base64'))).toBe(true)
  })
  test('a v1 token for another hub is refused', () => {
    const s = new Security()
    expect(() => atExpiry(() => verifyToken(s, auth.v1.header, '1', keys.device.publicKey))).toThrow('invalid signature')
  })
  test('a v0 token sent as v1 is refused', () => {
    const s = new Security()
    expect(() => atExpiry(() => verifyToken(s, auth.v0.header, '1', keys.hub.publicKey))).toThrow('invalid key')
  })
  test('other versions are refused', () => {
    const s = new Security()
    expect(() => atExpiry(() => verifyToken(s, auth.v0.header, '2'))).toThrow('unsupported version')
  })
  test('requireV1 refuses v0 tokens but not anonymous connections', () => {
    const s = new Security()
    const options = { version: '0', requireV1: true }
    expect(() => atExpiry(() => s.keys.verify(auth.v0.header, s.whitelist, options))).toThrow('unsupported version')
    expect(s.keys.verify(undefined, s.whitelist, options)).toBeUndefined()
  })
  test('the hub key file loads as its public key', () => {
    const der = Buffer.from(keys.hub.keyFile, 'base64')
    const privateKey = createPrivateKey({ key: der.subarray(0, 48), format: 'der', type: 'pkcs8' })
    expect(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64')).toBe(keys.hub.publicKey)
  })
})

describe('security mode migration', () => {
  const dir = () => mkdtempSync(join(tmpdir(), 'hub-server-mode-'))
  test('a first start is default-deny', async () => {
    const path = join(dir(), 'hub.json')
    const settings = await new HubSettings(path).load()
    expect(settings.data.security.mode).toBe('default-deny')
    expect((await Bun.file(path).json()).security.mode).toBe('default-deny')
  })
  test('a hub that ran before without hub.json stays default-allow', async () => {
    const directory = dir()
    writeFileSync(join(directory, 'auth'), 'key')
    const settings = await new HubSettings(join(directory, 'hub.json')).load()
    expect(settings.data.security.mode).toBe('default-allow')
  })
  test('an existing hub.json without a mode is default-allow', async () => {
    const path = join(dir(), 'hub.json')
    writeFileSync(path, JSON.stringify({ merge: [], pendingLimit: 3 }))
    const settings = await new HubSettings(path).load()
    expect(settings.data.security.mode).toBe('default-allow')
    expect(settings.data.pendingLimit).toBe(3)
    expect((await Bun.file(path).json()).security.mode).toBe('default-allow')
  })
  test('a stored mode is kept, and an owner\'s refuseV0', async () => {
    const path = join(dir(), 'hub.json')
    writeFileSync(path, JSON.stringify({ security: { mode: 'default-deny', requireV1: true, refuseV0: true } }))
    const settings = await new HubSettings(path).load()
    expect(settings.data.security).toEqual({ mode: 'default-deny', requireV1: true, refuseV0: true })
  })
  test('a stored requireV1 alone, before or since auth v2, keeps v0 accepted (Hub 1.0 apps)', async () => {
    for (const requireV1 of [false, true]) {
      const path = join(dir(), 'hub.json')
      writeFileSync(path, JSON.stringify({ security: { mode: 'default-allow', requireV1 } }))
      const settings = await new HubSettings(path).load()
      expect(settings.data.security.requireV1).toBe(false)
    }
  })
  test('an owner turning requireV1 on is kept, and off again', async () => {
    const path = join(dir(), 'hub.json')
    const settings = await new HubSettings(path).load()
    expect(settings.data.security.requireV1).toBe(false)
    settings.setSecurity({ requireV1: true })
    await settings.storage.write()
    const again = await new HubSettings(path).load()
    expect(again.data.security.requireV1).toBe(true)
    again.setSecurity({ requireV1: false })
    await again.storage.write()
    expect((await new HubSettings(path).load()).data.security.requireV1).toBe(false)
  })
  test('a corrupt hub.json is default-deny', async () => {
    const path = join(dir(), 'hub.json')
    writeFileSync(path, '{')
    const settings = await new HubSettings(path).load()
    expect(settings.storage.corrupt).toBe(true)
    expect(settings.data.security.mode).toBe('default-deny')
  })
})

describe('built-in API classification', () => {
  test.each([
    ['hub/info', 'public'],
    ['hub/profile/update', 'auth'],
    ['hub/device/request', 'auth'],
    ['hub/service/update', 'public'],
    ['hub/api', 'public'],
    ['hub/status', 'public'],
    ['hub/status/badges', 'public'],
    ['hub/proxy/join', 'public'],
    ['hub/api/services', 'auth'],
    ['hub/device/describe', 'reporter'],
    ['hub/device/data', 'reporter'],
    ['hub/devices', 'grant'],
    ['hub/devices/data', 'grant'],
    ['hub/connections', 'owner'],
    ['hub/key', 'owner'],
    ['hub/merge/add', 'owner'],
    ['hub/proxy', 'owner'],
    ['hub/group/list', 'owner'],
    ['hub/group/update', 'owner'],
    ['hub/whitelist/status', 'owner'],
    ['hub/net/list', 'owner'],
    ['hub/net/node/set', 'owner'],
    ['hub/net/test/complete', 'owner'],
    ['hub/net/test/results', 'owner'],
    ['hub/security/mode/set', 'owner'],
    ['hub/grants', 'owner'],
    ['hub/device/revoke', 'owner'],
    ['hub/devices/pending', 'owner'],
    ['hub/anything/new', 'owner'],
    ['network/resource/list', 'own'],
    ['s3/read', undefined],
  ])('%s is %s', (path, access) => {
    expect(builtinAccess(path)).toBe(access as any)
  })

  test('approved devices read the directory, keys alone and owner-only paths need more', () => {
    const security = new Security()
    const device = { key: 'k', device: { id: 'd', name: 'iPhone' }, groups: [], owner: false }
    const keyOnly = { key: 'k', groups: [], owner: false }
    expect(security.allowsBuiltin(device, 'hub/devices')).toBe(true)
    expect(security.allowsBuiltin(device, 'hub/devices/data')).toBe(true)
    expect(security.allowsBuiltin(keyOnly, 'hub/devices')).toBe(false)
    expect(security.allowsBuiltin(device, 'hub/devices/pending')).toBe(false)
    expect(security.allowsBuiltin(device, 'hub/device/revoke')).toBe(false)
  })
})

describe('forwarded context', () => {
  test('replaces a client-supplied hub and keeps the rest', () => {
    const caller = { key: 'k', groups: [], owner: false }
    expect(forwardedContext({ hub: { caller: { owner: true } }, service: 'x' }, caller)).toEqual({
      service: 'x',
      hub: { caller, hubKey: security.hubKey },
    })
  })
  test('matches the caller vector', () => {
    const { caller } = vectors
    const context = caller.context.hub.caller
    expect(Object.keys(context)).toEqual(['key', 'device', 'groups', 'owner'])
    expect(JSON.stringify(forwardedContext({}, context as any).hub.caller)).toBe(JSON.stringify(context))
  })
})

describe('hub', () => {
  const port = freePort()
  const owner = makeKey()
  const user = makeKey()
  const service = makeKey()
  let hub: Hub
  const clients: Client[] = []
  const received: any[] = []
  const v1 = (key: typeof owner) => () => ({ auth: token(key, security.hubKey, security.nonces), v: '1' })
  const client = (headers?: () => Record<string, string>) => {
    const c = connect(port, headers)
    clients.push(c)
    return c
  }

  beforeAll(async () => {
    security.addOwner(owner.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    hub.devices.gate.interval = 0
    await hub.ready
    security.host.allow(service.key, ['test/open', 'test/closed', 'test/stream'])
    const provider = client(v1(service))
    provider.channel
      .post('test/open', ({ context }) => {
        received.push(context)
        return 'open'
      })
      .post('test/closed', () => 'closed')
      .stream('test/stream', async function* ({ context }) {
        yield context.hub.caller.key ?? 'anonymous'
      })
    await provider.sender.send('hub/service/update', {
      services: [{ path: 'test/open', public: true }, { path: 'test/closed' }, { path: 'test/stream' }],
    })
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('hub/info is public and returns the hub key', async () => {
    const info = await client().sender.send('hub/info')
    expect(info).toEqual({ key: security.hubKey, protocol: 2, pro: true, mode: 'default-deny', challenge: expect.any(String) })
  })
  test('a v1 token bound to this hub connects', async () => {
    expect(await client(v1(user)).sender.send('hub/info')).toMatchObject({ key: security.hubKey })
  })
  test('default-deny allows public paths to anyone', async () => {
    expect(await client().sender.send('test/open')).toBe('open')
  })
  test('default-deny refuses other paths without a grant', async () => {
    await expect(client(v1(user)).sender.send('test/closed')).rejects.toThrow('permissions required')
  })
  test('a call list entry grants the path', async () => {
    const granted = makeKey()
    security.call.allow(granted.key, ['test/closed'])
    expect(await client(v1(granted)).sender.send('test/closed')).toBe('closed')
  })
  test('owners call everything', async () => {
    expect(await client(v1(owner)).sender.send('test/closed')).toBe('closed')
  })
  test('services get the caller in context.hub and never the client value', async () => {
    received.length = 0
    await client(v1(user)).sender.send('test/open', undefined, {
      context: { hub: { caller: { key: owner.key, owner: true } }, other: 1 },
    })
    expect(received[0]).toEqual({
      other: 1,
      hub: { caller: { key: user.key, groups: [], owner: false }, hubKey: security.hubKey },
    })
  })
  test('anonymous callers have no key', async () => {
    received.length = 0
    await client().sender.send('test/open')
    expect(received[0].hub.caller).toEqual({ groups: [], owner: false })
  })
  test('owners are marked in context', async () => {
    received.length = 0
    await client(v1(owner)).sender.send('test/open')
    expect(received[0].hub.caller).toEqual({ key: owner.key, groups: ['owners'], owner: true })
  })
  test('streams get the caller too', async () => {
    const values: string[] = []
    for await (const value of client(v1(owner)).sender.values('test/stream')) values.push(value)
    expect(values).toEqual([owner.key])
  })
  test('hub/api lists only callable paths', async () => {
    const api: string[] = await client(v1(user)).sender.send('hub/api')
    expect(api).toContain('test/open')
    expect(api).toContain('hub/info')
    expect(api).not.toContain('test/closed')
    expect(api).not.toContain('hub/connections')
    const all: string[] = await client(v1(owner)).sender.send('hub/api')
    expect(all).toContain('test/closed')
    expect(all).toContain('hub/connections')
  })
  test('owner built-ins refuse other callers', async () => {
    await expect(client(v1(user)).sender.send('hub/key')).rejects.toThrow('permissions required')
    await expect(client().sender.send('hub/proxy', { name: 'x', path: 'y' })).rejects.toThrow('permissions required')
    expect(await client(v1(owner)).sender.send('hub/key')).toBe(security.hubKey)
  })
  test('owner streams refuse other callers', async () => {
    const values = async (c: Client, path: string) => {
      for await (const value of c.sender.values(path)) return value
    }
    await expect(values(client(v1(user)), 'hub/connections')).rejects.toThrow('permissions required')
    await expect(values(client(), 'hub/group/list')).rejects.toThrow('permissions required')
    expect(await values(client(v1(owner)), 'hub/security/mode')).toEqual({ mode: 'default-deny', requireV1: true })
  })
  test('auth built-ins need a key', async () => {
    const values = async (c: Client) => {
      for await (const value of c.sender.values('hub/api/services', 'test/open')) return value
    }
    await expect(values(client())).rejects.toThrow('unauthorized')
    expect(await values(client(v1(user)))).toHaveLength(1)
  })
  test('default-allow opens unrestricted paths again', async () => {
    const owners = client(v1(owner))
    await owners.sender.send('hub/security/mode/set', { mode: 'default-allow' })
    try {
      expect(await client().sender.send('test/closed')).toBe('closed')
      expect(await client().sender.send('hub/info')).toMatchObject({ mode: 'default-allow' })
    } finally {
      await owners.sender.send('hub/security/mode/set', { mode: 'default-deny' })
    }
  })
  test('requireV1 refuses new v0 connections', async () => {
    const v0 = client(() => ({ auth: token(user), v: '0' }))
    await expect(v0.sender.send('hub/info')).rejects.toThrow('disconnected')
    expect(await client(v1(user)).sender.send('hub/info')).toMatchObject({ key: security.hubKey })
  })
  test('a merged hub learns this hub key and binds its token to it', async () => {
    const connection = hub.merger
    const address = `ws://localhost:${port}`
    connection.connect(address, hub, false)
    const merge = connection.connections.get(address)!
    await waitFor(() => merge.hubKey)
    expect(merge.hubKey).toBe(security.hubKey)
    connection.disconnect(address)
  })
  test('a request through a merged hub carries via and the claimed caller', async () => {
    // A second hub merges into the first and offers merged/echo from its own service
    const childPort = freePort()
    const child = new Hub(childPort)
    await child.ready
    const hubKey = security.hubKey!
    security.host.allow(hubKey, ['merged/echo'])
    security.host.allow(service.key, ['merged/echo'])
    security.call.allow(hubKey, ['merged/echo'])
    const provider = connect(childPort, () => ({ auth: token(service, hubKey, security.nonces), v: '1' }))
    clients.push(provider)
    provider.channel.post('merged/echo', ({ context }) => context)
    await provider.sender.send('hub/service/update', { services: [{ path: 'merged/echo' }] })
    const address = `ws://localhost:${port}`
    child.merger.connect(address, child, false)
    try {
      await waitFor(() => hub.services.get('merged/echo')?.services.length)
      const context = await client(v1(owner)).sender.send('merged/echo')
      expect(context.hub.hubKey).toBe(hubKey)
      expect(context.hub.caller).toMatchObject({ owner: false, via: hubKey })
      expect(context.hub.caller.claimed).toEqual({ key: owner.key, groups: ['owners'], owner: true })
    } finally {
      child.merger.disconnect(address)
    }
  })
})
