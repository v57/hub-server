import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { Hub, security } from '../src/hub'
import { connect, first, freePort, makeKey, token, waitFor, type Client, type TestKey } from './helpers'

// The Hub app's load balancer picker showed Round-robin again after Random was saved: hub/status kept the old
// balancer until something else changed it.
describe('load balancer', () => {
  const port = freePort()
  const owner = makeKey()
  let hub: Hub
  const clients: Client[] = []
  const client = (key: TestKey) => {
    const c = connect(port, () => ({ auth: token(key, security.hubKey, security.nonces), v: '1' }))
    clients.push(c)
    return c
  }

  beforeAll(async () => {
    security.addOwner(owner.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    await hub.ready
    const service = makeKey()
    security.host.allow(service.key, ['picks/read'])
    const c = client(service)
    c.channel.post('picks/read', () => 'ok')
    await c.sender.send('hub/service/update', { services: [{ path: 'picks/read' }] })
    await waitFor(() => hub.services.get('picks/read'))
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('an open hub/status stream names the new balancer once it is set', async () => {
    const owners = client(owner)
    const balancer = (status: any) => status.services.find((s: any) => s.name === 'picks/read')?.balancer
    const stream = owners.sender.values('hub/status')[Symbol.asyncIterator]()
    // The next value, kept across waits that time out (a dropped next() would swallow the value it gets)
    // (the last one fails when the test's connections stop)
    let pending = stream.next()
    pending.catch(() => {})
    const next = async (ms: number) => {
      const value = await Promise.race([pending, new Promise<'timeout'>(resolve => setTimeout(() => resolve('timeout'), ms))])
      if (value === 'timeout') return undefined
      pending = stream.next()
      pending.catch(() => {})
      return value.value
    }
    let status = await next(2000)
    expect(balancer(status)).toBe('counter')
    // Updates from connecting (the owner's own connection) come and go first, so they can't carry the change
    for (let value = await next(500); value; value = await next(500)) status = value
    await owners.sender.send('hub/balancer/set', { path: 'picks/read', type: 'random' })
    for (let value = await next(2000); value; value = balancer(status) === 'random' ? undefined : await next(2000)) status = value
    expect(balancer(status)).toBe('random')
    expect(balancer(await first(owners, 'hub/status'))).toBe('random')
  })
})
