import { mkdir, rename } from 'fs/promises'
import { dirname } from 'path'
import { hostname } from 'os'
import { LazyState } from 'channel/more'
import type { Channel } from 'channel/server'
import type { Security } from './security'

/** Public, extensible metadata for a Hub. */
export interface HubHeader {
  name: string
}

export const HUB_HEADER_NAME_MAX_SCALARS = 128

/**
 * Reject invalid display names before they can replace the persisted header.
 * Array.from counts Unicode scalar values instead of UTF-16 code units.
 */
export function validateHubHeader(value: unknown): HubHeader {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_hub_header')
  const name = (value as { name?: unknown }).name
  if (typeof name !== 'string') throw new Error('invalid_hub_header')
  const normalized = name.trim()
  if (!normalized) throw new Error('invalid_hub_header_name')
  if (Array.from(normalized).length > HUB_HEADER_NAME_MAX_SCALARS) {
    throw new Error('invalid_hub_header_name')
  }
  return { name: normalized }
}

/**
 * Small durable store kept separate from ordinary Hub settings. Writes use
 * write-then-rename and serialize updates, so a published value is always one
 * which has already reached its final storage path.
 */
export class HubHeaderStore {
  header?: HubHeader
  private writeChain: Promise<void> = Promise.resolve()

  constructor(
    readonly path = 'data/header.json',
    private readonly getHostname: () => string = hostname,
  ) {}

  async load(): Promise<HubHeader> {
    if (this.header) return this.header
    let stored: unknown
    try {
      stored = await Bun.file(this.path).json()
    } catch {}

    if (stored !== undefined) {
      this.header = validateHubHeader(stored)
      return this.header
    }

    const header = validateHubHeader({ name: this.getHostname() })
    await this.commit(header)
    return header
  }

  async update(value: unknown): Promise<HubHeader> {
    const header = validateHubHeader(value)
    await this.commit(header)
    return header
  }

  private async commit(header: HubHeader): Promise<void> {
    const write = this.writeChain.then(async () => {
      await mkdir(dirname(this.path), { recursive: true })
      const temporaryPath = `${this.path}.${crypto.randomUUID()}.tmp`
      await Bun.write(temporaryPath, JSON.stringify(header, null, 2))
      await rename(temporaryPath, this.path)
      this.header = header
    })
    this.writeChain = write.catch(() => {})
    await write
  }
}

interface HubHeaderState {
  device?: string
  key?: string
}

type HubHeaderSecurity = Pick<Security, 'isOwner' | 'registerProtectedApis'>

/**
 * Register public header reads and owner-only updates. Updates publish only
 * after HubHeaderStore has atomically committed the new value.
 */
export function registerHubHeaderAPIs<State extends HubHeaderState>(
  channel: Channel<State>,
  security: HubHeaderSecurity,
  store: HubHeaderStore,
): LazyState<HubHeader> {
  const state = new LazyState(() => store.load()).dedupe('json')
  security.registerProtectedApis({ 'hub/header/set': 'Hub: Update Header' })

  channel
    .stream('hub/header', () => state.makeIterator())
    .post('hub/header/set', async ({ body, state: connection }) => {
      if (!security.isOwner(connection)) throw 'Permissions required'
      const header = await store.update(body)
      state.send(header)
      return header
    })

  return state
}
