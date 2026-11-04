import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { randomBytes } from 'node:crypto'
import { Hub, security } from '../src/hub'
import { TokenNonces, verifyHubProof, nonceLifetime } from '../src/nonces'
import { certificate, challenge, connect, first, freePort, makeKey, token, waitFor, type Client } from './helpers'

// Auth v2 (protocol.md section 2): the holes these close are written out in each test's name

const port = freePort()
const clients: Client[] = []
const hub = new Hub(port)
const open = (headers: () => Record<string, string> | Promise<Record<string, string>> = () => ({})) => {
  const c = connect(port, headers)
  clients.push(c)
  return c
}
/** Whether a connection with these headers opens */
const opens = async (headers: Record<string, string>) => {
  const c = open(() => headers)
  const result = await Promise.race([c.sender.send('hub/info').then(() => true, () => false), Bun.sleep(1500).then(() => false)])
  c.sender.stop()
  return result
}
const v1 = (key: ReturnType<typeof makeKey>, nonce: string, hubKey = security.hubKey!) => ({ auth: token(key, hubKey, nonce), v: '1' })

beforeAll(() => hub.ready)
afterAll(() => {
  clients.forEach(c => c.sender.stop())
  hub.server?.stop(true)
})

describe('hub/info', () => {
  test('answers a client nonce with a proof of its key', async () => {
    const nonce = randomBytes(32).toString('base64url')
    const c = open()
    const info = await c.sender.send('hub/info', { nonce })
    expect(info.key).toBe(security.hubKey)
    expect(info.protocol).toBe(2)
    expect(verifyHubProof(info, nonce)).toBe(true)
    expect(verifyHubProof(info, randomBytes(32).toString('base64url'))).toBe(false)
  })
  test('a hub claiming another hub key without its private key has no proof', async () => {
    const nonce = randomBytes(32).toString('base64url')
    const impostor = makeKey()
    const { sign } = await import('node:crypto')
    const proof = sign(null, Buffer.from(`hubinfo1:${security.hubKey}:${nonce}`), impostor.privateKey).toString('base64')
    expect(verifyHubProof({ key: security.hubKey, proof, challenge: 'x' }, nonce)).toBe(false)
  })
  test('refuses a nonce it could be tricked into signing something else with', async () => {
    const c = open()
    expect(c.sender.send('hub/info', { nonce: 'x:y' })).rejects.toThrow()
    expect(c.sender.send('hub/info', { nonce: 'short' })).rejects.toThrow()
    expect(c.sender.send('hub/info', { nonce: 'a'.repeat(129) })).rejects.toThrow()
  })
})

describe('v1 tokens', () => {
  test('a sniffed token is refused the second time', async () => {
    const key = makeKey()
    const { challenge: nonce } = await challenge(port)
    const headers = v1(key, nonce)
    expect(await opens(headers)).toBe(true)
    expect(await opens(headers)).toBe(false)
  })
  test('a token without a nonce is refused', async () => {
    const key = makeKey()
    const time = `${Math.round(Date.now() / 1000) + 30}`
    const { sign } = await import('node:crypto')
    const signature = sign(null, Buffer.from(`hub1:${security.hubKey}:${time}`), key.privateKey).toString('base64')
    expect(await opens({ auth: `key.${key.key}.${signature}.${time}`, v: '1' })).toBe(false)
  })
  test('a nonce this hub did not make is refused', async () => {
    expect(await opens(v1(makeKey(), Buffer.alloc(40, 3).toString('base64url')))).toBe(false)
  })
  test('a token signed for another hub is refused', async () => {
    const { challenge: nonce } = await challenge(port)
    expect(await opens(v1(makeKey(), nonce, makeKey().key))).toBe(false)
  })
  test('a token living longer than its nonce is refused', async () => {
    const { challenge: nonce } = await challenge(port)
    const key = makeKey()
    expect(await opens({ auth: token(key, security.hubKey, nonce, 300), v: '1' })).toBe(false)
  })
  test('a v0 token, the old way in for a replay, is refused by default', async () => {
    expect(await opens({ auth: token(makeKey()), v: '0' })).toBe(false)
  })
  test('a refused signature leaves no used nonce behind', async () => {
    const before = security.nonces.usedCount
    const { challenge: nonce } = await challenge(port)
    const stranger = makeKey()
    const bad = v1(stranger, nonce, makeKey().key)
    expect(await opens(bad)).toBe(false)
    expect(security.nonces.usedCount).toBe(before)
    expect(await opens(v1(stranger, nonce))).toBe(true)
  })
})

describe('a malicious hub', () => {
  // What a hub collects from a client of this device: everything it can get on first contact and later
  const realHubOwnerKey = makeKey()
  const realHubOwnerDevice = makeKey()
  beforeAll(() => {
    security.addOwner(realHubOwnerKey.key)
    security.addOwner(realHubOwnerDevice.key)
  })
  test('replaying what it received for itself gets nothing here', async () => {
    // Credentials per hub address: on another hub this device's client signs with keys of that address
    const perHubClient = makeKey()
    const perHubDevice = makeKey()
    const { challenge: relayed } = await challenge(port)
    // Even a live relay of this hub's challenge only logs in a key that means nothing here
    const c = open(() => ({ ...v1(perHubClient, relayed), device: certificate(perHubDevice, perHubClient) }))
    expect(await c.sender.send('hub/info')).toMatchObject({ key: security.hubKey })
    await expect(c.sender.send('hub/connections')).rejects.toThrow()
    await expect(c.sender.send('hub/pair/new')).rejects.toThrow()
    const owner = open(() => ({ auth: token(realHubOwnerKey, security.hubKey, security.nonces), v: '1' }))
    const pending = await waitFor(async () => {
      const list = await first<any[]>(owner, 'hub/devices/pending')
      return list.find(d => d.key === perHubDevice.key)
    })
    expect(pending.key).toBe(perHubDevice.key)
  })
  test('a v0 token and certificate it captured do not make an owner here', async () => {
    const service = makeKey()
    const c = open(() => ({ auth: token(service), v: '0', device: certificate(realHubOwnerDevice, service) }))
    await expect(c.sender.send('hub/connections')).rejects.toThrow()
  })
})

describe('whitelist', () => {
  test('a known client can still get its challenge, and an anonymous connection nothing more', async () => {
    const known = makeKey()
    security.whitelist.add(known.key)
    security.whitelist.setEnabled(true)
    try {
      const anon = open()
      const info = await anon.sender.send('hub/info', { nonce: randomBytes(32).toString('base64url') })
      expect(info.challenge).toBeString()
      await expect(anon.sender.send('hub/api')).rejects.toThrow()
      expect(await opens(v1(known, info.challenge))).toBe(true)
      const { challenge: nonce } = await challenge(port)
      expect(await opens(v1(makeKey(), nonce))).toBe(false)
    } finally {
      security.whitelist.setEnabled(false)
      security.whitelist.remove(known.key)
    }
  })
})

describe('used nonces', () => {
  test('a used nonce stays used until it expires', () => {
    const nonces = new TokenNonces()
    const now = 1_800_000_000
    const nonce = nonces.issue(now)
    expect(nonces.isValid(nonce, now)).toBe(true)
    expect(nonces.consume(nonce, now)).toBe(true)
    expect(nonces.consume(nonce, now)).toBe(false)
    expect(nonces.isValid(nonce, now + nonceLifetime - 1)).toBe(false)
    expect(nonces.isValid(nonce, now + nonceLifetime + 1)).toBe(false)
  })
  test('issuing stores nothing', () => {
    const nonces = new TokenNonces()
    for (let i = 0; i < 1000; i++) nonces.issue()
    expect(nonces.usedCount).toBe(0)
  })
  test('expired entries make room', () => {
    const nonces = new TokenNonces(4)
    const now = 1_800_000_000
    for (let i = 0; i < 4; i++) expect(nonces.consume(nonces.issue(now), now)).toBe(true)
    expect(nonces.usedCount).toBe(4)
    expect(nonces.consume(nonces.issue(now + nonceLifetime + 1), now + nonceLifetime + 1)).toBe(true)
    expect(nonces.usedCount).toBe(1)
  })
  test('a full store changes the secret: nothing can be replayed, and it stays bounded', () => {
    const nonces = new TokenNonces(4)
    const now = 1_800_000_000
    const used = [nonces.issue(now), nonces.issue(now), nonces.issue(now), nonces.issue(now)]
    used.forEach(nonce => expect(nonces.consume(nonce, now)).toBe(true))
    const waiting = nonces.issue(now)
    // The flood's next one: refused, and it resets the store
    expect(nonces.consume(nonces.issue(now), now)).toBe(false)
    expect(nonces.usedCount).toBe(0)
    used.forEach(nonce => {
      expect(nonces.isValid(nonce, now)).toBe(false)
      expect(nonces.consume(nonce, now)).toBe(false)
    })
    // A client that was between its two steps asks again
    expect(nonces.isValid(waiting, now)).toBe(false)
    const fresh = nonces.issue(now)
    expect(nonces.consume(fresh, now)).toBe(true)
    expect(nonces.usedCount).toBeLessThanOrEqual(4)
  })
  test('a tampered nonce or one with a padded encoding is not this hub\'s', () => {
    const nonces = new TokenNonces()
    const nonce = nonces.issue()
    const flipped = (nonce[0] === 'A' ? 'B' : 'A') + nonce.slice(1)
    expect(nonces.isValid(flipped)).toBe(false)
    expect(nonces.isValid(nonce + '=')).toBe(false)
    expect(nonces.isValid(nonce.slice(0, -1))).toBe(false)
  })
})
