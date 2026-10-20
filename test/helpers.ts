import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto'
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

/** An `auth` token, v1 when `hubKey` is given */
export function token(key: TestKey, hubKey?: string, expiresIn = 60): string {
  const time = `${Math.round(Date.now() / 1000) + expiresIn}`
  const signed = hubKey ? `hub1:${hubKey}:${time}` : time
  return `key.${key.key}.${sign(null, Buffer.from(signed), key.privateKey).toString('base64')}.${time}`
}

export interface Client {
  sender: Sender & { stop(): void }
  channel: Channel<any>
}

/** Connects to the hub, `headers` evaluated at connect */
export function connect(port: number, headers: () => Record<string, string> = () => ({})): Client {
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
