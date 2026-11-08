import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { Hub, security } from '../src/hub'
import { describedFields, limits } from '../src/api-descriptions'
import { connect, freePort, makeKey, token, until, type Client, type TestKey } from './helpers'

describe('API descriptions (protocol.md section 15)', () => {
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
  afterAll(() => clients.forEach(c => c.sender.stop()))

  /** A provider of `headers`, approved for hosting unless `approved` is false */
  async function provider(headers: any[], approved = true) {
    const key = makeKey()
    const paths = [...new Set(headers.map(h => h.path))]
    if (approved) security.host.allow(key.key, paths)
    const c = client(key)
    for (const path of paths) c.channel.post(path, () => path)
    await c.sender.send('hub/service/update', { services: headers })
    return c
  }
  const list = async (c: Client = owners): Promise<any[]> => c.sender.send('hub/api/list')
  const entries = async (path: string, c?: Client) => (await list(c)).filter(entry => entry.path === path)

  const input = { type: 'string', description: 'File path' }
  test('lists what the provider said, per kind, sorted, with built-ins bare', async () => {
    await provider([
      { path: 'docs/read', kind: 'post', title: 'Read', description: 'Reads a file.', inputSchema: input, outputSchema: { type: 'string' }, annotations: { readOnlyHint: true, other: 1 } },
      { path: 'docs/list', kind: 'stream', description: 'Files, then changes.' },
      { path: 'docs/list', kind: 'post', description: 'Files once.' },
      { path: 'docs/plain' },
    ])
    expect(await entries('docs/read')).toEqual([
      { path: 'docs/read', kind: 'post', title: 'Read', description: 'Reads a file.', inputSchema: input, outputSchema: { type: 'string' }, annotations: { readOnlyHint: true } },
    ])
    expect(await entries('docs/list')).toEqual([
      { path: 'docs/list', kind: 'post', description: 'Files once.' },
      { path: 'docs/list', kind: 'stream', description: 'Files, then changes.' },
    ])
    expect(await entries('docs/plain')).toEqual([{ path: 'docs/plain' }])
    expect(await entries('hub/api/list')).toEqual([
      { path: 'hub/api/list', kind: 'post' },
      { path: 'hub/api/list', kind: 'stream' },
    ])
    const paths = (await list()).map(entry => entry.path)
    expect(paths).toEqual([...paths].sort())
  })

  test('the caller sees only what it may call, and anonymous callers only public paths', async () => {
    await provider([{ path: 'docs/secret', kind: 'post', description: 'Owners only.' }])
    await provider([{ path: 'docs/open', kind: 'post', public: true, description: 'Anyone.' }])
    const stranger = client(makeKey())
    const anonymous = connect(port)
    clients.push(anonymous)
    const seen = (await list(stranger)).map(entry => entry.path)
    expect(seen).toContain('docs/open')
    expect(seen).not.toContain('docs/secret')
    expect(seen).not.toContain('hub/connections')
    expect((await list(anonymous)).map(entry => entry.path)).toContain('docs/open')
    expect(await entries('docs/secret')).toEqual([{ path: 'docs/secret', kind: 'post', description: 'Owners only.' }])
  })

  test('an unapproved provider describes nothing, and the first approved one wins', async () => {
    await provider([{ path: 'docs/shared', kind: 'post', description: 'First.' }])
    await provider([{ path: 'docs/shared', kind: 'post', description: 'Second.' }])
    await provider([{ path: 'docs/shared', kind: 'post', description: 'Pending key.' }], false)
    expect(await entries('docs/shared')).toEqual([{ path: 'docs/shared', kind: 'post', description: 'First.' }])
  })

  test('a services update replaces the descriptions, the stream follows, and they leave with the connection', async () => {
    const c = await provider([{ path: 'docs/live', kind: 'post', description: 'Before.' }])
    const has = (description: string | undefined) => (value: any[]) =>
      value.some(entry => entry.path === 'docs/live' && entry.description === description)
    await until(owners, 'hub/api/list', has('Before.'))
    await c.sender.send('hub/service/update', { services: [{ path: 'docs/live', kind: 'post', description: 'After.' }] })
    await until(owners, 'hub/api/list', has('After.'))
    await c.sender.send('hub/service/update', { services: [{ path: 'docs/live', kind: 'post' }] })
    expect(await entries('docs/live')).toEqual([{ path: 'docs/live', kind: 'post' }])
    c.sender.stop()
    await until(owners, 'hub/api/list', (value: any[]) => !value.some(entry => entry.path === 'docs/live'))
  })

  test('malformed or oversized fields are left out without refusing the update', async () => {
    await provider([
      { path: 'docs/odd', kind: 'post', title: 'x'.repeat(limits.title + 1), description: 42, inputSchema: [1], outputSchema: { type: 'string', description: 'y'.repeat(limits.schema) } },
      { path: 'docs/odd', kind: 'sideways', description: 'no such kind' },
    ])
    expect(await entries('docs/odd')).toEqual([{ path: 'docs/odd', kind: 'post' }])
    expect(describedFields({ annotations: { readOnlyHint: 'yes', destructiveHint: false } })).toEqual({ annotations: { destructiveHint: false } })
  })
})
