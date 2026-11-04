import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { Hub, pendingWait, security } from '../src/hub'
import { connect, freePort, makeKey, token, waitFor, type Client, type TestKey } from './helpers'

/** The rejection of a call, with its code */
const failure = (promise: Promise<unknown>) =>
  promise.then(
    () => ({ message: 'ok', code: undefined }),
    (error: any) => ({ message: String(error), code: error?.code }),
  )

describe('service features', () => {
  const port = freePort()
  const owner = makeKey()
  let hub: Hub
  const clients: Client[] = []
  const client = (key: TestKey) => {
    const c = connect(port, () => ({ auth: token(key, security.hubKey, security.nonces), v: '1' }))
    clients.push(c)
    return c
  }
  let owners: Client

  beforeAll(async () => {
    security.addOwner(owner.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    hub.devices.gate.interval = 0
    await hub.ready
    owners = client(owner)
  })
  afterAll(() => {
    clients.forEach(c => c.sender.stop())
    pendingWait.timeout = 30_000
  })

  /** An approved provider of `paths` */
  async function provider(paths: Record<string, (body: any) => any>) {
    const key = makeKey()
    security.host.allow(key.key, Object.keys(paths))
    const c = client(key)
    for (const [path, handler] of Object.entries(paths)) c.channel.post(path, ({ body }) => handler(body))
    await c.sender.send('hub/service/update', { services: Object.keys(paths).map(path => ({ path })) })
    return { key, client: c }
  }

  describe('error codes', () => {
    test('call errors keep their messages and gain codes', async () => {
      await provider({ 'codes/a': () => 'a' })
      expect(await failure(client(makeKey()).sender.send('codes/a'))).toEqual({ message: 'permissions required', code: 'forbidden' })
      expect(await failure(owners.sender.send('codes/missing'))).toEqual({ message: 'api not found', code: 'not_found' })
      expect(await failure(client(makeKey()).sender.send('hub/connections'))).toEqual({ message: 'permissions required', code: 'forbidden' })
      const anonymous = connect(port)
      clients.push(anonymous)
      expect(await failure(anonymous.sender.send('hub/grant/check', { path: 'codes/a' }))).toEqual({ message: 'unauthorized', code: 'unauthorized' })
    })
    test('a service error passes through with its code and info', async () => {
      await provider({ 'codes/fail': () => { throw { message: 'post not found', code: 404, info: { id: 'p1' } } } })
      const error: any = await owners.sender.send('codes/fail').catch(error => error)
      expect([error.message, error.code, error.info]).toEqual(['post not found', 404, { id: 'p1' }])
    })
    test('a call that waits too long fails with unavailable', async () => {
      const { client: c } = await provider({ 'codes/wait': () => 'x' })
      await c.sender.send('hub/service/update', { draining: true })
      pendingWait.timeout = 100
      try {
        expect(await failure(owners.sender.send('codes/wait'))).toEqual({ message: 'api not available', code: 'unavailable' })
      } finally {
        pendingWait.timeout = 30_000
      }
    })
  })

  describe('draining', () => {
    test('a draining provider finishes its running call and takes no new ones', async () => {
      let release!: () => void
      const slow = new Promise<void>(resolve => (release = resolve))
      const first = await provider({ 'drain/a': async () => (await slow, 'first') })
      const running = owners.sender.send('drain/a')
      await waitFor(() => hub.services.get('drain/a')!.status.running === 1)
      const second = await provider({ 'drain/a': () => 'second' })
      await first.client.sender.send('hub/service/update', { draining: true })
      expect(hub.services.get('drain/a')!.status).toMatchObject({ services: 1, draining: 1, running: 1 })
      for (let i = 0; i < 4; i += 1) expect(await owners.sender.send('drain/a')).toBe('second')
      release()
      expect(await running).toBe('first')
      // Undrained, it takes calls again
      await first.client.sender.send('hub/service/update', { draining: false })
      second.client.sender.stop()
      await waitFor(() => hub.services.get('drain/a')!.services.length === 1)
      expect(await owners.sender.send('drain/a')).toBe('first')
    })
    test('calls wait while the only provider drains and run on its replacement', async () => {
      const old = await provider({ 'drain/b': () => 'old' })
      await old.client.sender.send('hub/service/update', { draining: true })
      expect(hub.api.has('drain/b')).toBe(false)
      const call = owners.sender.send('drain/b')
      await waitFor(() => hub.services.get('drain/b')!.pending.length === 1)
      old.client.sender.stop()
      await provider({ 'drain/b': () => 'new' })
      expect(await call).toBe('new')
      expect(hub.api.has('drain/b')).toBe(true)
    })
    test('paths registered while draining start drained', async () => {
      const { client: c, key } = await provider({ 'drain/c': () => 'c' })
      security.host.allow(key.key, ['drain/d'])
      c.channel.post('drain/d', () => 'd')
      await c.sender.send('hub/service/update', { draining: true })
      await c.sender.send('hub/service/update', { services: [{ path: 'drain/c' }, { path: 'drain/d' }] })
      expect(hub.services.get('drain/d')!.status).toMatchObject({ services: 0, draining: 1 })
      await c.sender.send('hub/service/update', { draining: false })
      expect(await owners.sender.send('drain/d')).toBe('d')
    })
    test('disconnecting while draining cancels what still runs', async () => {
      const { client: c } = await provider({ 'drain/e': () => new Promise(() => {}) })
      const call = failure(owners.sender.send('drain/e'))
      await waitFor(() => hub.services.get('drain/e')!.status.running === 1)
      await c.sender.send('hub/service/update', { draining: true })
      c.sender.stop()
      expect((await call).message).toBe('cancelled')
      expect(hub.services.get('drain/e')!.status).toMatchObject({ running: 0 })
    })
  })

  describe('streams', () => {
    test('a caller leaving a stream cancels it at the provider while the provider waits', async () => {
      const key = makeKey()
      security.host.allow(key.key, ['feed/live'])
      const c = client(key)
      let cancelled = false
      let sent = false
      c.channel.stream('feed/live', () => ({
        next: () => (sent ? new Promise(() => {}) : ((sent = true), Promise.resolve({ value: 'first', done: false }))),
        return: async () => ((cancelled = true), { value: undefined, done: true }),
      }))
      await c.sender.send('hub/service/update', { services: [{ path: 'feed/live' }] })
      for await (const value of owners.sender.values('feed/live')) {
        expect(value).toBe('first')
        break
      }
      await waitFor(() => cancelled)
      await waitFor(() => hub.services.get('feed/live')!.status.running === 0)
    })
    test('a provider that disconnects ends its streams with unavailable, so callers can resubscribe', async () => {
      const key = makeKey()
      security.host.allow(key.key, ['feed/ticks'])
      const c = client(key)
      let sent = false
      c.channel.stream('feed/ticks', () => ({
        next: () => (sent ? new Promise(() => {}) : ((sent = true), Promise.resolve({ value: 'tick', done: false }))),
      }))
      await c.sender.send('hub/service/update', { services: [{ path: 'feed/ticks' }] })
      const iterator = owners.sender.values('feed/ticks')[Symbol.asyncIterator]()
      expect((await iterator.next()).value).toBe('tick')
      const pending = failure(iterator.next())
      c.sender.stop()
      expect(await pending).toEqual({ message: 'service disconnected', code: 'unavailable' })
      await waitFor(() => (hub.services.get('feed/ticks')?.status.running ?? 0) === 0)
    })
  })

  describe('hub/grant/check', () => {
    const user = makeKey()
    let service: Client
    beforeAll(async () => {
      service = (await provider({ 'posts/create': () => 'ok' })).client
    })
    const check = (path: string, caller: any = { key: user.key }, from = service) =>
      from.sender.send('hub/grant/check', { path, caller })

    test('answers whether a permission under its own paths is granted', async () => {
      expect(await check('posts/moderate')).toEqual({ allowed: false })
      const grant = await owners.sender.send('hub/grant/add', { subject: { key: user.key }, object: { path: 'posts/moderate' } })
      expect(await check('posts/moderate')).toEqual({ allowed: true })
      expect(await check('posts/moderate', { key: makeKey().key })).toEqual({ allowed: false })
      await owners.sender.send('hub/grant/remove', { id: grant.id })
      expect(await check('posts/moderate')).toEqual({ allowed: false })
    })
    test('counts prefix, group and device grants and owners', async () => {
      await owners.sender.send('hub/group/create', 'moderators')
      await owners.sender.send('hub/group/update/users', { group: 'moderators', add: [user.key] })
      const grant = await owners.sender.send('hub/grant/add', { subject: { group: 'moderators' }, object: { prefix: 'posts/admin/' } })
      expect(await check('posts/admin/ban')).toEqual({ allowed: true })
      await owners.sender.send('hub/grant/remove', { id: grant.id })
      const device = await owners.sender.send('hub/grant/add', { subject: { device: 'dev1' }, object: { path: 'posts/pin' } })
      expect(await check('posts/pin', { device: { id: 'dev1', name: 'Phone' } })).toEqual({ allowed: true })
      await owners.sender.send('hub/grant/remove', { id: device.id })
      expect(await check('posts/anything', { key: owner.key })).toEqual({ allowed: true })
      // A caller through a merged hub is never an owner
      expect(await check('posts/anything', { key: owner.key, via: 'other-hub' })).toEqual({ allowed: false })
    })
    test('a service may not ask about paths outside its own', async () => {
      expect(await failure(check('billing/refund'))).toEqual({ message: 'permissions required', code: 'forbidden' })
      expect(await failure(check('posts/x', { key: user.key }, client(makeKey())))).toEqual({ message: 'permissions required', code: 'forbidden' })
      expect(await check('billing/refund', { key: user.key }, owners)).toEqual({ allowed: false })
      expect(await failure(check(''))).toEqual({ message: 'invalid path', code: 'invalid_input' })
    })
    test('a locked-down hub grants nothing but to owners', async () => {
      const grant = await owners.sender.send('hub/grant/add', { subject: { key: user.key }, object: { path: 'posts/moderate' } })
      security.lockdown = true
      try {
        expect(await check('posts/moderate')).toEqual({ allowed: false })
        expect(await check('posts/moderate', { key: owner.key })).toEqual({ allowed: true })
      } finally {
        security.lockdown = false
        await owners.sender.send('hub/grant/remove', { id: grant.id })
      }
    })
  })
})
