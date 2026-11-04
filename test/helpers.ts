import { generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto'
import { Channel } from 'channel/client'
import type { Sender } from 'channel/client'

export interface TestKey {
  key: string
  privateKey: KeyObject
}

export function makeKey(): TestKey {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return { key: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'), privateKey }
}

/** An `auth` token: v0 without `hubKey`, v1 for `hubKey` over a challenge from the hub's `hub/info`, or `nonces` here */
export function token(key: TestKey, hubKey?: string, nonces?: { issue(): string } | string, expiresIn = 30): string {
  const time = `${Math.round(Date.now() / 1000) + expiresIn}`
  const sig = (text: string) => sign(null, Buffer.from(text), key.privateKey).toString('base64')
  if (!hubKey) return `key.${key.key}.${sig(time)}.${time}`
  const nonce = typeof nonces === 'string' ? nonces : nonces!.issue()
  return `key.${key.key}.${sig(`hub1:${hubKey}:${nonce}:${time}`)}.${time}.${nonce}`
}

/** A challenge from the hub at `port`, asked on an anonymous connection */
export async function challenge(port: number): Promise<{ key: string; challenge: string; proof?: string; [k: string]: unknown }> {
  const probe = new Channel<any>().connect(`ws://localhost:${port}`) as any
  try {
    return await probe.send('hub/info', { nonce: randomBytes(32).toString('base64url') })
  } finally {
    probe.stop()
  }
}

export interface Client {
  sender: Sender & { stop(): void }
  channel: Channel<any>
}

/** Connects to the hub, `headers` evaluated at connect */
export function connect(port: number, headers: () => Record<string, string> | Promise<Record<string, string>> = () => ({})): Client {
  const channel = new Channel<any>()
  const sender = channel.connect(`ws://localhost:${port}`, { headers }) as any
  return { sender, channel }
}

export async function waitFor<T>(check: () => T | undefined | false | Promise<T | undefined | false>, timeout = 3000): Promise<T> {
  const start = Date.now()
  while (true) {
    const value = await check()
    if (value) return value
    if (Date.now() - start > timeout) throw new Error('timed out')
    await Bun.sleep(10)
  }
}

let nextPort = 20000 + Math.floor(Math.random() * 20000)
export const freePort = () => nextPort++

/** A `device` header signed by `device` for `service` */
export function certificate(
  device: TestKey,
  service: TestKey,
  fields: Record<string, unknown> = {},
  now = Math.floor(Date.now() / 1000),
): string {
  const body = { v: 1, device: device.key, service: service.key, instance: 'test', iat: now, exp: now + 3600, ...fields }
  const payload = Buffer.from(JSON.stringify(body)).toString('base64url')
  return `${payload}.${sign(null, Buffer.from(payload), device.privateKey).toString('base64')}`
}

/** First value of a stream */
export async function first<T = any>(client: Client, path: string, body?: any): Promise<T> {
  for await (const value of client.sender.values(path, body)) return value
  throw new Error('stream ended')
}

/** Reads a stream until a value passes `check`, returns that value */
export async function until<T = any>(client: Client, path: string, check: (value: T) => boolean, body?: any, timeout = 3000): Promise<T> {
  const iterator = client.sender.values(path, body)[Symbol.asyncIterator]()
  const timer = Bun.sleep(timeout).then(() => {
    throw new Error(`${path} never matched`)
  })
  try {
    while (true) {
      const { value, done } = await Promise.race([iterator.next(), timer])
      if (done) throw new Error('stream ended')
      if (check(value)) return value
    }
  } finally {
    iterator.return?.()
  }
}
