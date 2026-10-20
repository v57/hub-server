import { mkdir, rename } from 'fs/promises'
import { dirname } from 'path'

/** The Hub Network node agents use. There is no built-in node: `null` until an owner sets one. */
export class HubNetNodeStore {
  value: string | null = null
  private writeChain: Promise<void> = Promise.resolve()

  constructor(readonly path = 'data/hub-net-node.json') {}

  async load(): Promise<string | null> {
    try {
      const stored = await Bun.file(this.path).json()
      this.value = validateNode(stored)
    } catch {}
    return this.value
  }

  async set(input: unknown): Promise<string | null> {
    const value = input === null || input === undefined ? null : validateNode(input)
    const write = this.writeChain.then(async () => {
      await mkdir(dirname(this.path), { recursive: true })
      const temporaryPath = `${this.path}.${crypto.randomUUID()}.tmp`
      await Bun.write(temporaryPath, JSON.stringify(value))
      await rename(temporaryPath, this.path)
      this.value = value
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
