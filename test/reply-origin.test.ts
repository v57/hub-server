import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { Hub, security } from '../src/hub'
import { connect, freePort, makeKey, token, waitFor, type Client, type TestKey } from './helpers'

// Security audit C1: the hub forwards calls and streams to services over the services' connections. Request ids are
// one counter for the whole hub, so an anonymous connection spraying responses used to answer them.
describe('forwarded calls', () => {
  const port = freePort()
  const owner = makeKey()
  let hub: Hub
  const clients: Client[] = []
  const client = (key: TestKey) => {
    const c = connect(port, () => ({ auth: token(key, security.hubKey, security.nonces), v: '1' }))
    clients.push(c)
    return c
  }
  let release!: () => void
  const answered = new Promise<void>(resolve => (release = resolve))

  beforeAll(async () => {
    security.addOwner(owner.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    await hub.ready
    const service = makeKey()
    security.host.allow(service.key, ['origin/read', 'origin/values'])
    const c = client(service)
    c.channel.post('origin/read', async () => (await answered, 'real'))
    c.channel.stream('origin/values', async function* () {
      await answered
      yield 'real'
    })
    await c.sender.send('hub/service/update', { services: [{ path: 'origin/read' }, { path: 'origin/values' }] })
    await waitFor(() => hub.services.get('origin/read') && hub.services.get('origin/values'))
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('only the service answers a call or stream the hub forwarded to it', async () => {
    const owners = client(owner)
    const call = owners.sender.send('origin/read')
    const values: any[] = []
    const reading = (async () => {
      for await (const value of owners.sender.values('origin/values')) values.push(value)
    })()
    await waitFor(() => hub.services.get('origin/read')!.status.running === 1)
    const attacker = new WebSocket(`ws://localhost:${port}`)
    await new Promise(resolve => (attacker.onopen = resolve))
    const ids = Array.from({ length: 1024 }, (_, id) => id)
    attacker.send(JSON.stringify(ids.map(id => ({ id, body: 'forged' }))))
    attacker.send(JSON.stringify(ids.map(id => ({ id, done: true }))))
    await Bun.sleep(100)
    release()
    expect(await call).toBe('real')
    await reading
    expect(values).toEqual(['real'])
    attacker.close()
  })
})
