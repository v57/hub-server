import type { Name as LoadBalancer } from './load balancers'
import { mkdir, rename, unlink, writeFile } from 'fs/promises'
import { dirname } from 'path'
try {
  await mkdir('data', { recursive: true })
} catch {}

interface Settings {
  merge: string[]
  proxies: string[]
  api: { [key: string]: ApiSettings | undefined }
  pendingLimit: number
  security: SecuritySettings
  /** Hub keys learned from `hub/info` of the hubs this one merges into, by address */
  mergeKeys: { [address: string]: string | undefined }
}
export type SecurityMode = 'default-allow' | 'default-deny'
export interface SecuritySettings {
  mode: SecurityMode
  requireV1: boolean
}
interface ApiSettings {
  loadBalancer?: LoadBalancer
}

export class HubSettings {
  data: Settings = {
    merge: [],
    proxies: [],
    api: {},
    pendingLimit: 0,
    security: { mode: 'default-deny', requireV1: false },
    mergeKeys: {},
  }
  storage: Storage
  private storedMode = false
  constructor(path = 'data/hub.json') {
    this.storage = new Storage(
      path,
      () => this.data,
      data => {
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not an object')
        this.data = data
        this.data.merge ??= []
        this.data.proxies ??= []
        this.data.api ??= {}
        this.data.pendingLimit ??= 0
        this.data.mergeKeys ??= {}
        // A hub that ran before the security mode existed keeps today's behaviour
        this.storedMode = data.security?.mode !== undefined
        this.data.security = {
          mode: data.security?.mode === 'default-deny' ? 'default-deny' : 'default-allow',
          requireV1: data.security?.requireV1 === true,
        }
      },
    )
  }
  /**
   * A hub starting for the first time (no `data/hub.json` and no hub key in `data/auth`) gets `default-deny`. One
   * that ran before keeps `default-allow` until an owner switches it, also when it never wrote `data/hub.json`. A
   * corrupt `data/hub.json` gives `default-deny`. The mode is written at once so it doesn't change on restart.
   */
  async load() {
    const path = this.storage.path
    const existed = await Bun.file(path).exists()
    const ranBefore = existed || (await Bun.file(dirname(path) + '/auth').exists())
    await this.storage.load()
    if (this.storage.corrupt) {
      this.data.security.mode = 'default-deny'
    } else if (!existed) {
      this.data.security.mode = ranBefore ? 'default-allow' : 'default-deny'
    }
    if (!existed || this.storage.corrupt || !this.storedMode) {
      await this.storage.write().catch(error => console.error(`Failed to write ${path}:`, error))
    }
    return this
  }
  setSecurity(security: Partial<SecuritySettings>) {
    let changed = false
    if (security.mode === 'default-allow' || security.mode === 'default-deny') {
      changed ||= this.data.security.mode !== security.mode
      this.data.security.mode = security.mode
    }
    if (typeof security.requireV1 === 'boolean') {
      changed ||= this.data.security.requireV1 !== security.requireV1
      this.data.security.requireV1 = security.requireV1
    }
    if (changed) this.storage.save()
  }
  setMergeKey(address: string, key: string) {
    if (this.data.mergeKeys[address] === key) return
    this.data.mergeKeys[address] = key
    this.storage.save()
  }
  async setNeedsSave() {
    this.storage.save()
  }
  addMerge(address: string) {
    if (this.data.merge.includes(address)) return
    this.data.merge.push(address)
    this.storage.save()
  }
  removeMerge(address: string) {
    const i = this.data.merge.findIndex(a => a === address)
    if (i == -1) return
    this.data.merge.splice(i, 1)
    this.storage.save()
  }
  addProxy(address: string) {
    if (this.data.proxies.includes(address)) return
    this.data.proxies.push(address)
    this.storage.save()
  }
  removeProxy(address: string) {
    const i = this.data.proxies.findIndex(a => a === address)
    if (i == -1) return
    this.data.proxies.splice(i, 1)
    this.storage.save()
  }
  updateApi(path: string, update: (settings: ApiSettings) => boolean) {
    const settings = (this.data.api[path] ??= {})
    if (update(settings)) this.storage.save()
  }
}

export let settings = await new HubSettings().load()

/**
 * JSON file store. Writes go to a temporary file that is renamed over the old one, one at a time, so a crash never
 * leaves a half-written file. A missing file loads as empty. A file that can't be read or decoded is moved aside to
 * `<path>.corrupt-<unix time>` and the store loads as empty with `corrupt` set, so callers can deny what it would
 * have granted.
 */
export class Storage {
  path: string
  encode: () => any
  decode: (data: any) => void
  isSavePending = false
  corrupt = false
  private writeChain: Promise<void> = Promise.resolve()
  constructor(path: string, encode: () => any, decode: (data: any) => void) {
    this.path = path
    this.encode = encode
    this.decode = decode
  }
  async load() {
    const file = Bun.file(this.path)
    if (!(await file.exists())) return
    try {
      const value = JSON.parse(await file.text())
      this.decode(value)
      this.corrupt = false
    } catch (error) {
      this.corrupt = true
      const aside = `${this.path}.corrupt-${Math.floor(Date.now() / 1000)}`
      console.error(`${this.path} is corrupt, moved it to ${aside}:`, error)
      await rename(this.path, aside).catch(error => console.error(`Failed to move ${this.path} aside:`, error))
    }
  }
  async save() {
    if (this.isSavePending) return
    this.isSavePending = true
    setTimeout(() => {
      this.isSavePending = false
      this.write().catch(error => console.error(`Failed to write ${this.path}:`, error))
    }, 1000)
  }
  /** Writes the current value now, after any write already in progress */
  write(): Promise<void> {
    const write = this.writeChain.then(() => writeAtomically(this.path, JSON.stringify(this.encode(), null, 2)))
    this.writeChain = write.catch(() => {})
    return write
  }
}

export async function writeAtomically(path: string, text: string, mode?: number) {
  await mkdir(dirname(path), { recursive: true })
  const temporaryPath = `${path}.${crypto.randomUUID()}.tmp`
  try {
    await writeFile(temporaryPath, text, mode === undefined ? undefined : { mode })
    await rename(temporaryPath, path)
  } catch (error) {
    await unlink(temporaryPath).catch(() => {})
    throw error
  }
}
