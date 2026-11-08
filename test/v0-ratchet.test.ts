import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Hub, security } from '../src/hub'
import { V1Keys } from '../src/security'
import { HubSettings, settings } from '../src/settings'
import { connect, freePort, makeKey, token, type Client, type TestKey } from './helpers'

// The v0 transition (security decisions 1.0, Hub 1): the Hub 1.0 App Store app speaks only v0, so v0 is accepted
// until the transition ends, except from a key that has used v1 here, and never once an owner refused it.
describe('v0 transition', () => {
  const port = freePort()
  const owner = makeKey()
  let hub: Hub
  const clients: Client[] = []
  const v1 = (key: TestKey) => {
    const c = connect(port, () => ({ auth: token(key, security.hubKey, security.nonces), v: '1' }))
    clients.push(c)
    return c
  }
  /** Whether a connection with the 1.0 app's headers (a v0 token, no `v`) opens */
  const v0Opens = (key: TestKey, expiresIn = 60) =>
    new Promise<boolean>(resolve => {
      const ws = new WebSocket(`ws://localhost:${port}`, { headers: { auth: token(key, undefined, undefined, expiresIn) } } as any)
      ws.onopen = () => {
        ws.close()
        resolve(true)
      }
      ws.onerror = () => resolve(false)
    })
  const mode = async () => {
    for await (const value of v1(owner).sender.values('hub/security/mode')) return value
  }

  // Other files share the hub's security and may have refused v0
  let requireV1 = false
  beforeAll(async () => {
    requireV1 = security.requireV1
    security.setMode({ requireV1: false })
    security.addOwner(owner.key)
    hub = new Hub(port)
    await hub.ready
  })
  afterAll(() => {
    clients.forEach(c => c.sender.stop())
    security.setMode({ requireV1 })
  })

  test('a new hub takes v0 until the key uses v1, and refuses it from that key for good', async () => {
    expect(await mode()).toEqual({ mode: security.effectiveMode, requireV1: false })
    const app = makeKey()
    security.addOwner(app.key)
    expect(await v0Opens(app)).toBe(true)
    expect(await v1(app).sender.send('hub/info')).toMatchObject({ key: security.hubKey })
    expect(await v0Opens(app)).toBe(false)
    // Stored, so a restart keeps it
    await security.v1Keys.storage.write()
    const stored = new V1Keys()
    await stored.storage.load()
    expect(stored.has(app.key)).toBe(true)
    expect(stored.has(makeKey().key)).toBe(false)
  })

  test('a key that holds a grant is recorded, one the hub doesn\'t know is not', async () => {
    const granted = makeKey()
    security.call.allow(granted.key, ['ratchet/read'])
    await v1(granted).sender.send('hub/info')
    expect(await v0Opens(granted)).toBe(false)
    const stranger = makeKey()
    const before = security.v1Keys.ids.size
    await v1(stranger).sender.send('hub/info')
    expect(security.v1Keys.ids.size).toBe(before)
    expect(await v0Opens(stranger)).toBe(true)
  })

  test('a v0 token lives a minute, as a v1 token does', async () => {
    const app = makeKey()
    expect(await v0Opens(app, 60)).toBe(true)
    expect(await v0Opens(app, 5 * 60)).toBe(false)
  })

  test('an owner refusing v0 refuses it from every key', async () => {
    const owners = v1(owner)
    await owners.sender.send('hub/security/mode/set', { requireV1: true })
    try {
      expect(await v0Opens(makeKey())).toBe(false)
      expect(await mode()).toMatchObject({ requireV1: true })
    } finally {
      await owners.sender.send('hub/security/mode/set', { requireV1: false })
    }
    expect(await v0Opens(makeKey())).toBe(true)
  })

  test('the transition end refuses v0 from every key, and an owner taking it back keeps it', async () => {
    const app = makeKey()
    settings.data.security.v0Until = new Date(Date.now() + 3_600_000).toISOString()
    try {
      expect(await v0Opens(app)).toBe(true)
      expect(await mode()).toMatchObject({ requireV1: false, v0Until: settings.data.security.v0Until })
      settings.data.security.v0Until = new Date(Date.now() - 1000).toISOString()
      expect(await v0Opens(app)).toBe(false)
      expect(security.refusesV0()).toBe(true)
      await v1(owner).sender.send('hub/security/mode/set', { requireV1: false })
      expect(settings.data.security.v0Until).toBeNull()
      expect(await v0Opens(app)).toBe(true)
    } finally {
      delete settings.data.security.v0Until
    }
  })

  test('a corrupt v1-keys.json refuses v0 from every key', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'v1-keys-'))
    const keys = new V1Keys()
    keys.storage.path = join(dir, 'v1-keys.json')
    writeFileSync(keys.storage.path, '{')
    await keys.storage.load()
    expect(keys.has(makeKey().key)).toBe(true)
  })
})

describe('the stored transition end', () => {
  const path = () => join(mkdtempSync(join(tmpdir(), 'hub-json-')), 'hub.json')
  test('is kept as stored, and an invalid one is dropped', async () => {
    for (const [v0Until, kept] of [
      ['2027-03-01T00:00:00.000Z', '2027-03-01T00:00:00.000Z'],
      [null, null],
      ['2027-03-01T03:00:00+03:00', '2027-03-01T03:00:00+03:00'],
      ['soon', undefined],
      ['2027-03-01', undefined],
      [5, undefined],
    ] as const) {
      const file = path()
      writeFileSync(file, JSON.stringify({ security: { mode: 'default-allow', requireV1: false, v0Until } }))
      const stored = await new HubSettings(file).load()
      expect(stored.data.security.v0Until).toBe(kept as any)
    }
  })
  test('ends v0 for everyone once passed', async () => {
    const file = path()
    writeFileSync(file, JSON.stringify({ security: { mode: 'default-deny', v0Until: '2027-03-01T00:00:00.000Z' } }))
    const stored = await new HubSettings(file).load()
    expect(stored.refusesV0(Date.parse('2027-02-28T23:59:59Z'))).toBe(false)
    expect(stored.refusesV0(Date.parse('2027-03-01T00:00:00Z'))).toBe(true)
    expect(stored.data.security.requireV1).toBe(false)
  })
})
