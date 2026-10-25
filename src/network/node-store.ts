import { mkdir, rename } from 'fs/promises'
import { dirname } from 'path'

/** The coordinator v57 runs for everyone: a hub uses it until an owner sets another. */
export const defaultHubNetNode = 'wss://v57.dev:1964'

/** The Hub Network node agents use: the one an owner set, else v57's. */
export class HubNetNodeStore {
  /** The node an owner set, `null` for the default */
  stored: string | null = null
  private writeChain: Promise<void> = Promise.resolve()

  constructor(readonly path = 'data/hub-net-node.json') {}

  get value(): string {
    return this.stored ?? defaultHubNetNode
  }

  async load(): Promise<string> {
    try {
      const stored = await Bun.file(this.path).json()
      this.stored = validateNode(stored)
    } catch {}
    return this.value
  }

  /** Sets the node; `null` goes back to the default */
  async set(input: unknown): Promise<string | null> {
    const value = input === null || input === undefined ? null : validateNode(input)
    const write = this.writeChain.then(async () => {
      await mkdir(dirname(this.path), { recursive: true })
      const temporaryPath = `${this.path}.${crypto.randomUUID()}.tmp`
      await Bun.write(temporaryPath, JSON.stringify(value))
      await rename(temporaryPath, this.path)
      this.stored = value
    })
    this.writeChain = write.catch(() => {})
    await write
    return value
  }
}

function validateNode(input: unknown): string {
  if (typeof input !== 'string' || !input.trim() || input !== input.trim()) {
    throw new Error('invalid node address')
  }
  return input
}
