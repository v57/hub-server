import { afterAll, afterEach, beforeAll, describe, expect, test } from 'bun:test'
import { Hub, pendingWait, security } from '../src/hub'
import { settings } from '../src/settings'
import { connect, freePort, makeKey, token, waitFor, type Client, type TestKey } from './helpers'

const failure = (promise: Promise<unknown>) => promise.then(() => 'ok', error => String(error))

describe('calls waiting for a provider', () => {
  const port = freePort()
  const owner = makeKey()
  let hub: Hub
  const clients: Client[] = []
  const client = (key: TestKey) => {
    const c = connect(port, () => ({ auth: token(key, security.hubKey, security.nonces), v: '1' }))
    clients.push(c)
    return c
  }
  let caller: Client
  const pending = (path: string) => hub.services.get(path)?.pending.length ?? 0

  /** A provider of `path` answering `handler`; hosting stays unapproved unless `approved` */
  async function provider(path: string, handler: (body: any) => any = body => body, approved = true, limit?: number) {
    const key = makeKey()
    if (approved) security.host.allow(key.key, [path])
    const c = client(key)
    c.channel.post(path, ({ body }) => handler(body))
    await c.sender.send('hub/service/update', { services: [{ path, ...(limit ? { limit } : {}) }] })
    return { key, client: c }
  }

  beforeAll(async () => {
    security.addOwner(owner.key)
    hub = new Hub(port)
    hub.devices.gate.interval = 0
    await hub.ready
    caller = client(owner)
  })
  afterEach(() => {
    pendingWait.timeout = 30_000
    settings.data.pendingLimit = 0
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('a call made before hosting is approved runs once it is, and so do later calls', async () => {
    const { key } = await provider('pending/approve', body => `echo ${body}`, false)
    const calls = [1, 2, 3, 4, 5].map(n => caller.sender.send('pending/approve', n))
    await waitFor(() => pending('pending/approve') === 5)
    await caller.sender.send('hub/host/update', { key: key.key, allow: ['pending/approve'] })
    expect(await Promise.all(calls)).toEqual(['echo 1', 'echo 2', 'echo 3', 'echo 4', 'echo 5'])
    expect(pending('pending/approve')).toBe(0)
    expect(await caller.sender.send('pending/approve', 6)).toBe('echo 6')
  })

  test('a call made while no provider is connected runs when one registers', async () => {
    const first = await provider('pending/late')
    first.client.sender.stop()
    await waitFor(() => hub.services.get('pending/late')?.services.length === 0)
    const calls = ['a', 'b', 'c'].map(body => caller.sender.send('pending/late', body))
    await waitFor(() => pending('pending/late') === 3)
    await provider('pending/late', body => body.toUpperCase())
    expect(await Promise.all(calls)).toEqual(['A', 'B', 'C'])
  })

  test('waiting calls respect the provider limit and run in order', async () => {
    let running = 0
    let most = 0
    const order: number[] = []
    const release: (() => void)[] = []
    await provider(
      'pending/limit',
      async (n: number) => {
        running += 1
        most = Math.max(most, running)
        order.push(n)
        await new Promise<void>(resolve => release.push(resolve))
        running -= 1
        return n
      },
      true,
      1,
    )
    const calls = [1, 2, 3, 4].map(n => caller.sender.send('pending/limit', n))
    for (let i = 0; i < 4; i++) {
      await waitFor(() => release.length > i)
      await Bun.sleep(30)
      expect(running).toBe(1)
      release[i]()
    }
    expect(await Promise.all(calls)).toEqual([1, 2, 3, 4])
    expect(order).toEqual([1, 2, 3, 4])
    expect(most).toBe(1)
    // An idle provider serves a new call at once
    const late = caller.sender.send('pending/limit', 5)
    await waitFor(() => release.length === 5)
    release[4]()
    expect(await late).toBe(5)
  })

  test('a waiting call fails with api not available after the timeout', async () => {
    pendingWait.timeout = 200
    await provider('pending/timeout', body => body, false)
    const start = Date.now()
    expect(await failure(caller.sender.send('pending/timeout', 1))).toContain('api not available')
    expect(Date.now() - start).toBeGreaterThanOrEqual(190)
    expect(pending('pending/timeout')).toBe(0)
  })

  test('pendingLimit fails the oldest waiting calls instead of dropping them', async () => {
    settings.data.pendingLimit = 2
    const { key } = await provider('pending/evict', body => body, false)
    const calls = [1, 2, 3].map(n => failure(caller.sender.send('pending/evict', n)))
    await waitFor(() => pending('pending/evict') === 2)
    expect(await calls[0]).toContain('api not available')
    await caller.sender.send('hub/host/update', { key: key.key, allow: ['pending/evict'] })
    expect(await Promise.all(calls.slice(1))).toEqual(['ok', 'ok'])
  })
})
