import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from 'bun:test'
import { mkdtempSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Hub, security } from '../src/hub'
import { deviceId } from '../src/devices'
import {
  Pairing,
  formatPairingCode,
  generatePairingCode,
  normalizePairingCode,
  pairingAlphabet,
  pairingLifetime,
  pairingMaxAttempts,
} from '../src/pairing'
import { deviceMember, keyMember, ownersGroup } from '../src/security'
import { certificate, connect, freePort, makeKey, token, waitFor, type Client, type TestKey } from './helpers'

// scrypt takes hundreds of ms per code and much longer on a loaded machine; the checks are lower bounds only
setDefaultTimeout(60_000)

const directory = () => mkdtempSync(join(tmpdir(), 'hub-server-pairing-'))
const fast_ = (dir: string) => new Pairing(dir, { minDuration: 0 })
const fast = () => fast_(directory())
const mode = (path: string) => statSync(path).mode & 0o777
const exists = (path: string) => Bun.file(path).exists()
const now = () => Math.floor(Date.now() / 1000)
/** A wrong code that is still well-formed */
const wrong = (code: string) => (code[0] === 'A' ? 'B' : 'A') + code.slice(1)
const failure = (promise: Promise<unknown>) => promise.then(() => 'ok', error => String(error))

describe('pairing codes', () => {
  test('6 symbols of Crockford base32 without I L O U, shown XXX-XXX', () => {
    expect(pairingAlphabet).toBe('0123456789ABCDEFGHJKMNPQRSTVWXYZ')
    for (let i = 0; i < 200; i++) {
      const code = generatePairingCode()
      expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{6}$/)
      expect(formatPairingCode(code)).toBe(`${code.slice(0, 3)}-${code.slice(3)}`)
    }
  })
  test('input ignores case, spaces and dashes', () => {
    expect(normalizePairingCode('k7q-2mx')).toBe('K7Q2MX')
    expect(normalizePairingCode(' K7Q 2MX ')).toBe('K7Q2MX')
    expect(normalizePairingCode('k-7-q-2-m-x')).toBe('K7Q2MX')
    expect(normalizePairingCode('K7Q-2M')).toBeUndefined()
    expect(normalizePairingCode('I7Q-2MX')).toBeUndefined()
    expect(normalizePairingCode(123456)).toBeUndefined()
  })
})

describe('pairing store', () => {
  test('stores only the scrypt hash in pairing.json and the plain code in pairing-code, both 0600', async () => {
    const pairing = fast()
    const code = await pairing.create()
    expect(code).toMatch(/^[0-9A-Z]{3}-[0-9A-Z]{3}$/)
    const stored = await Bun.file(pairing.path).json()
    expect(Object.keys(stored).sort()).toEqual(['attempts', 'expires', 'hash', 'salt'])
    expect(stored.attempts).toBe(0)
    expect(Math.abs(stored.expires - (now() + pairingLifetime))).toBeLessThanOrEqual(2)
    expect(JSON.stringify(stored)).not.toContain(code.replace('-', ''))
    expect(await Bun.file(pairing.codePath).text()).toBe(code)
    expect(mode(pairing.path)).toBe(0o600)
    expect(mode(pairing.codePath)).toBe(0o600)
  })

  test('the right code succeeds once, in any case and without the dash, and deletes both files', async () => {
    const pairing = fast()
    const code = await pairing.create()
    await pairing.verify(code.replace('-', ' ').toLowerCase())
    expect(await exists(pairing.path)).toBe(false)
    expect(await exists(pairing.codePath)).toBe(false)
    expect(await failure(pairing.verify(code))).toBe('no pairing code')
  })

  test('a wrong code is counted in pairing.json', async () => {
    const pairing = fast()
    const code = await pairing.create()
    expect(await failure(pairing.verify(wrong(code)))).toBe('invalid pairing code')
    expect(await failure(pairing.verify('not a code'))).toBe('invalid pairing code')
    expect((await Bun.file(pairing.path).json()).attempts).toBe(2)
    // A restart keeps the count
    const restarted = await new Pairing(pairing.directory, { minDuration: 0 }).load()
    expect(await failure(restarted.verify(wrong(code)))).toBe('invalid pairing code')
    expect((await Bun.file(pairing.path).json()).attempts).toBe(3)
    await restarted.verify(code)
  })

  test(`${pairingMaxAttempts} wrong codes invalidate the code`, async () => {
    const pairing = fast()
    const code = await pairing.create()
    for (let i = 0; i < pairingMaxAttempts; i++) {
      expect(await failure(pairing.verify(wrong(code)))).toBe('invalid pairing code')
    }
    expect(await exists(pairing.path)).toBe(false)
    expect(await exists(pairing.codePath)).toBe(false)
    expect(await failure(pairing.verify(code))).toBe('no pairing code')
  })

  test('without a code every attempt fails with no pairing code', async () => {
    const pairing = await fast().load()
    expect(await failure(pairing.verify('K7Q-2MX'))).toBe('no pairing code')
  })

  test('an expired code is refused and deleted', async () => {
    const pairing = fast()
    const code = await pairing.create()
    const stored = await Bun.file(pairing.path).json()
    await Bun.write(pairing.path, JSON.stringify({ ...stored, expires: now() - 1 }))
    expect(await failure(pairing.verify(code))).toBe('no pairing code')
    expect(await exists(pairing.path)).toBe(false)
    expect(await exists(pairing.codePath)).toBe(false)
    // Expired on disk: removed at load
    const other = fast()
    await Bun.write(other.path, JSON.stringify({ ...stored, expires: now() - 1 }))
    await Bun.write(other.codePath, code)
    await other.load()
    expect(other.active).toBe(false)
    expect(await exists(other.path)).toBe(false)
    expect(await exists(other.codePath)).toBe(false)
  })

  test('the expiry timer deletes the plain code', async () => {
    const pairing = fast()
    await pairing.create()
    const stored = await Bun.file(pairing.path).json()
    await Bun.write(pairing.path, JSON.stringify({ ...stored, expires: now() + 1 }))
    await pairing.load()
    expect(pairing.active).toBe(true)
    await waitFor(async () => !(await exists(pairing.codePath)), 3000)
    expect(await exists(pairing.path)).toBe(false)
  }, 5000)

  test('the expiry timer keeps a code another process made meanwhile', async () => {
    const pairing = fast()
    await pairing.create()
    const stored = await Bun.file(pairing.path).json()
    await Bun.write(pairing.path, JSON.stringify({ ...stored, expires: now() + 1 }))
    await pairing.load()
    const code = await fast_(pairing.directory).create()
    await Bun.sleep(2100)
    expect(await Bun.file(pairing.codePath).text()).toBe(code)
    await pairing.verify(code)
  }, 5000)

  test('a code made by another process works at once and shares its attempts', async () => {
    const server = await fast().load()
    const oneShot = fast_(server.directory)
    const code = await oneShot.create()
    expect(await failure(server.verify(wrong(code)))).toBe('invalid pairing code')
    expect((await Bun.file(server.path).json()).attempts).toBe(1)
    // A newer code replaces it for the running hub too
    let newer = await oneShot.create()
    while (newer === code) newer = await oneShot.create()
    expect(await failure(server.verify(code))).toBe('invalid pairing code')
    await server.verify(newer)
    expect(await exists(server.codePath)).toBe(false)
  })

  test('a new code replaces the old one', async () => {
    const pairing = fast()
    const old = await pairing.create()
    let code = await pairing.create()
    while (code === old) code = await pairing.create()
    expect(await failure(pairing.verify(old))).toBe('invalid pairing code')
    await pairing.verify(code)
  })

  test('start makes a code only when needed or forced, and reuses a valid one', async () => {
    const pairing = await fast().load()
    expect(await pairing.start({ needed: false })).toBeUndefined()
    expect(await exists(pairing.path)).toBe(false)
    const code = await pairing.start({ needed: true })
    expect(code).toBeDefined()
    expect(await failure(pairing.verify(wrong(code!)))).toBe('invalid pairing code')
    // A restart while nobody owns the hub keeps the code and its attempts
    const restarted = await new Pairing(pairing.directory, { minDuration: 0 }).load()
    expect(await restarted.start({ needed: true })).toBe(code)
    expect((await Bun.file(pairing.path).json()).attempts).toBe(1)
    // `--pair` replaces it, also when the hub has owners
    let forced = await restarted.start({ needed: false, force: true })
    while (forced === code) forced = await restarted.start({ needed: false, force: true })
    expect(await failure(restarted.verify(code))).toBe('invalid pairing code')
    await restarted.verify(forced)
  })
})

describe('pairing timing', () => {
  test('every verification takes at least 1 s', async () => {
    const pairing = new Pairing(directory())
    expect(pairing.minDuration).toBe(1000)
    const timed = async (attempt: () => Promise<unknown>) => {
      const start = Date.now()
      await attempt().catch(() => {})
      return Date.now() - start
    }
    expect(await timed(() => pairing.verify('K7Q-2MX'))).toBeGreaterThanOrEqual(1000)
    const code = await pairing.create()
    expect(await timed(() => pairing.verify(wrong(code)))).toBeGreaterThanOrEqual(1000)
    expect(await timed(() => pairing.verify('nonsense'))).toBeGreaterThanOrEqual(1000)
    expect(await timed(() => pairing.verify(code))).toBeGreaterThanOrEqual(1000)
  }, 60_000)

  test('verifications run one at a time', async () => {
    const pairing = new Pairing(directory())
    const code = await pairing.create()
    const start = Date.now()
    const finished: number[] = []
    const attempts = [wrong(code), wrong(code), code, code].map(attempt =>
      failure(pairing.verify(attempt)).then(result => {
        finished.push(Date.now() - start)
        return result
      }),
    )
    const results = await Promise.all(attempts)
    expect(results).toEqual(['invalid pairing code', 'invalid pairing code', 'ok', 'no pairing code'])
    expect(finished[0]).toBeGreaterThanOrEqual(1000)
    for (let i = 1; i < finished.length; i++) expect(finished[i] - finished[i - 1]).toBeGreaterThanOrEqual(990)
    expect(finished[3]).toBeGreaterThanOrEqual(4000)
  }, 90_000)
})

describe('pairing on the hub', () => {
  const port = freePort()
  let hub: Hub
  const clients: Client[] = []
  const client = (key?: TestKey, device?: TestKey) => {
    const c = connect(port, () =>
      key
        ? { auth: token(key, security.hubKey, security.nonces), v: '1', ...(device ? { device: certificate(device, key) } : {}) }
        : {},
    )
    clients.push(c)
    return c
  }

  beforeAll(async () => {
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    await hub.ready
    hub.pairing.minDuration = 0
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('a hub without owners makes a code at start, one with owners does not', async () => {
    for (const member of Array.from(security.members.members(ownersGroup))) security.members.remove(ownersGroup, member)
    await hub.pairing.clear()
    const code = await hub.startPairing()
    expect(code).toBeDefined()
    expect(await Bun.file('data/pairing-code').text()).toBe(code!)
    security.members.add(ownersGroup, keyMember(makeKey().key))
    await hub.pairing.clear()
    expect(await hub.startPairing()).toBeUndefined()
  })

  test('hub-server --pair writes a code the running hub takes at once, and exits', async () => {
    await hub.pairing.clear()
    const proc = Bun.spawn(['bun', join(import.meta.dir, '..', 'index.ts'), '--pair'], {
      cwd: process.cwd(),
      env: { ...process.env, HUBOWNER: '', HUB_MODE: '' },
      stdout: 'pipe',
    })
    expect(await proc.exited).toBe(0)
    const printed = (await new Response(proc.stdout).text()).match(/Pairing code: ([0-9A-Z]{3}-[0-9A-Z]{3})/)?.[1]
    expect(printed).toBeDefined()
    expect(await Bun.file('data/pairing-code').text()).toBe(printed!)
    expect(mode('data/pairing.json')).toBe(0o600)
    const key = makeKey()
    expect(await client(key).sender.send('hub/pair', { code: printed })).toMatchObject({ owner: true })
    expect(security.isOwner(key.key)).toBe(true)
  }, 60_000)

  test('anonymous callers cannot pair', async () => {
    const code = await hub.pairing.create()
    expect(await failure(client().sender.send('hub/pair', { code }))).toContain('unauthorized')
    expect(hub.pairing.active).toBe(true)
  })

  test('the code makes the caller and its device owners and approves the device', async () => {
    const code = await hub.pairing.create()
    const key = makeKey()
    const device = makeKey()
    const id = deviceId(device.key)
    const caller = client(key, device)
    expect(await failure(caller.sender.send('hub/connections'))).toContain('permissions required')
    expect(await failure(caller.sender.send('hub/pair', { code: wrong(code) }))).toContain('invalid pairing code')
    const result = await caller.sender.send('hub/pair', { code: code.toLowerCase() })
    expect(result).toEqual({ owner: true, hubKey: security.hubKey, name: (await hub.header.load()).name })
    expect(security.members.has(ownersGroup, keyMember(key.key))).toBe(true)
    expect(security.members.has(ownersGroup, deviceMember(id))).toBe(true)
    expect(hub.devices.registry.device(id)?.approved).toBe(true)
    expect(await caller.sender.send('hub/key')).toBe(security.hubKey)
    // Consumed
    expect(await failure(client(makeKey()).sender.send('hub/pair', { code }))).toContain('no pairing code')
  })

  test('without a certificate only the key becomes an owner', async () => {
    const code = await hub.pairing.create()
    const key = makeKey()
    await client(key).sender.send('hub/pair', { code })
    expect(security.isOwner(key.key)).toBe(true)
  })

  test('hub/pair/new is for owners only, not the launcher key', async () => {
    const strangerKey = makeKey()
    const stranger = client(strangerKey)
    expect(await failure(stranger.sender.send('hub/pair/new'))).toContain('permissions required')
    const launcher = makeKey()
    security.launcher = launcher.key
    expect(await failure(client(launcher).sender.send('hub/pair/new'))).toContain('permissions required')
    security.launcher = undefined
    const owner = makeKey()
    security.addOwner(owner.key)
    const result = await client(owner).sender.send('hub/pair/new')
    expect(result.code).toMatch(/^[0-9A-Z]{3}-[0-9A-Z]{3}$/)
    expect(result.expires).toBe(hub.pairing.expires)
    expect(await Bun.file('data/pairing-code').text()).toBe(result.code)
    await stranger.sender.send('hub/pair', { code: result.code })
    expect(security.isOwner(strangerKey.key)).toBe(true)
  })
})
