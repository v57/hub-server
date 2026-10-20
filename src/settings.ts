import type { Name as LoadBalancer } from './load balancers'
import { mkdir, rename, unlink } from 'fs/promises'
import { dirname } from 'path'
try {
  await mkdir('data', { recursive: true })
} catch {}

interface Settings {
  merge: string[]
  proxies: string[]
  api: { [key: string]: ApiSettings | undefined }
  pendingLimit: number
}
interface ApiSettings {
  loadBalancer?: LoadBalancer
}

class HubSettings {
  data: Settings = {
    merge: [],
    proxies: [],
    api: {},
    pendingLimit: 0,
  }
  storage: Storage
  constructor() {
    this.storage = new Storage(
      'data/hub.json',
      () => this.data,
      data => {
        this.data = data
        this.data.merge ??= []
        this.data.proxies ??= []
        this.data.api ??= {}
        this.data.pendingLimit ??= 0
      },
    )
  }
  async load() {
    await this.storage.load()
    return this
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
    const settings = this.data.api[path] ?? {}
    if (update(settings)) this.storage.save()
  }
}

export let settings = await new HubSettings().load()

/**
 * JSON file store. Writes go to a temporary file that is renamed over the old one, one at a time, so a crash never
 * leaves a half-written file. A missing file loads as empty. A file that exists but can't be read or decoded marks
 * the store `corrupt`: it keeps its empty value, refuses to write over the file, and security stores deny everything
 * except owners until the file is repaired and the hub restarted.
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
      this.decode(JSON.parse(await file.text()))
      this.corrupt = false
    } catch (error) {
      this.corrupt = true
      console.error(`${this.path} is corrupt, denying everything it grants until it is repaired:`, error)
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
    if (this.corrupt) return Promise.reject(new Error(`${this.path} is corrupt, not overwriting it`))
    const write = this.writeChain.then(() => writeAtomically(this.path, JSON.stringify(this.encode(), null, 2)))
    this.writeChain = write.catch(() => {})
    return write
  }
}

export async function writeAtomically(path: string, text: string) {
  await mkdir(dirname(path), { recursive: true })
  const temporaryPath = `${path}.${crypto.randomUUID()}.tmp`
  try {
    await Bun.write(temporaryPath, text)
    await rename(temporaryPath, path)
  } catch (error) {
    await unlink(temporaryPath).catch(() => {})
    throw error
  }
}
