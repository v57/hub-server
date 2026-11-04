import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { mkdtempSync } from 'node:fs'
import { networkInterfaces, tmpdir } from 'node:os'
import { join } from 'node:path'
import { Hub, localAddress, security } from '../src/hub'
import { ownersGroup } from '../src/security'
import { settings } from '../src/settings'
import { connect, freePort, makeKey, token, waitFor, type Client, type TestKey } from './helpers'

const failure = (promise: Promise<unknown>) => promise.then(() => 'ok', error => String(error))
const lanAddress = () =>
  Object.values(networkInterfaces())
    .flat()
    .find(address => address && address.family === 'IPv4' && !address.internal)?.address

test('local mode listens on 127.0.0.1 and keeps the port', () => {
  expect(localAddress(1997)).toBe('127.0.0.1:1997')
  expect(localAddress('0.0.0.0:2000')).toBe('127.0.0.1:2000')
  expect(localAddress('192.168.1.5:2001')).toBe('127.0.0.1:2001')
})

describe('a hub in local mode', () => {
  const port = freePort()
  const launcher = makeKey()
  let hub: Hub
  const clients: Client[] = []
  const client = (key?: TestKey) => {
    const c = connect(port, () => (key ? { auth: token(key, security.hubKey, security.nonces), v: '1' } : {}))
    clients.push(c)
    return c
  }

  beforeAll(async () => {
    // A stored default-deny hub with no owners, which would otherwise make a pairing code
    security.setMode({ mode: 'default-deny' })
    for (const member of Array.from(security.members.members(ownersGroup))) security.members.remove(ownersGroup, member)
    security.launcher = launcher.key
    hub = new Hub(port, { local: true })
    await hub.ready
  })
  afterAll(() => {
    clients.forEach(c => c.sender.stop())
    hub.server?.stop(true)
    security.local = false
    security.launcher = undefined
    security.setMode({ mode: 'default-deny' })
  })

  test('binds 127.0.0.1 only', async () => {
    expect(hub.server?.hostname).toBe('127.0.0.1')
    expect(await client(undefined).sender.send('hub/info')).toMatchObject({ pro: true })
    const lan = lanAddress()
    if (!lan) return
    const refused = await fetch(`http://${lan}:${port}`).then(() => 'answered', () => 'refused')
    expect(refused).toBe('refused')
  })

  test('runs default-allow without storing it', async () => {
    expect(await client(undefined).sender.send('hub/info')).toMatchObject({ mode: 'default-allow' })
    expect(security.allowsCall({ key: makeKey().key }, 'some/service')).toBe(true)
    expect(settings.data.security.mode).toBe('default-deny')
    expect((await Bun.file('data/hub.json').json()).security.mode).toBe('default-deny')
  })

  test('the launcher has launcher/* by a grant and is no owner', async () => {
    expect(await failure(client(launcher).sender.send('hub/key'))).toContain('permissions required')
    expect(security.caller(launcher.key)).toMatchObject({ owner: false, groups: [] })
    expect(security.members.members(ownersGroup).size).toBe(0)
    expect(security.granted(security.caller(launcher.key), 'launcher/app/start')).toBe(true)
    expect(security.granted(security.caller(makeKey().key), 'launcher/app/start')).toBe(false)
    expect(security.granted(security.caller(launcher.key), 'other/path')).toBe(false)
  })

  test('a local hub without owners pairs, so someone can approve what connects', async () => {
    const code = await hub.startPairing()
    expect(code).toBeDefined()
    expect(await Bun.file('data/pairing-code').text()).toBe(code!)
    const owner = makeKey()
    expect(await client(owner).sender.send('hub/pair', { code })).toMatchObject({ owner: true })
    expect(await client(owner).sender.send('hub/key')).toBe(security.hubKey)
  }, 15_000)
})

describe('hub-server --local', () => {
  async function run(args: string[], env: Record<string, string> = {}) {
    const cwd = mkdtempSync(join(tmpdir(), 'hub-server-local-'))
    const port = freePort()
    const proc = Bun.spawn(['bun', join(import.meta.dir, '..', 'index.ts'), '-p', `${port}`, ...args], {
      cwd,
      env: { ...process.env, HUB_DEVICE_KEY: join(cwd, 'device.key'), HUBLISTEN: '', HUBOWNER: '', ...env },
      stdout: 'pipe',
      stderr: 'pipe',
    })
    try {
      const info = await waitFor(async () => {
        const c = connect(port)
        const result = await Promise.race([c.sender.send('hub/info').catch(() => undefined), Bun.sleep(300)])
        c.sender.stop()
        return result as any
      }, 10_000)
      // The code comes after the hub listens; a local hub gets the same time to make one
      const pairingCode = await waitFor(() => Bun.file(join(cwd, 'data/pairing-code')).exists(), 2000).catch(() => false)
      return { info, pairingCode }
    } finally {
      proc.kill()
      await proc.exited
    }
  }

  test('a fresh hub pairs, also a local one', async () => {
    expect(await run([])).toMatchObject({ info: { mode: 'default-deny' }, pairingCode: true })
    expect(await run(['--local'])).toMatchObject({ info: { mode: 'default-allow' }, pairingCode: true })
    expect(await run([], { HUB_MODE: 'local' })).toMatchObject({ info: { mode: 'default-allow' }, pairingCode: true })
  }, 30_000)
})
