import { describe, expect, test } from 'bun:test'
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Storage } from '../src/settings'

const directory = () => mkdtempSync(join(tmpdir(), 'hub-server-storage-'))

function store(path: string) {
  let value: any = { empty: true }
  const storage = new Storage(path, () => value, data => (value = data))
  return { storage, get: () => value, set: (v: any) => (value = v) }
}

describe('Storage', () => {
  test('loads a missing file as empty', async () => {
    const { storage, get } = store(join(directory(), 'missing.json'))
    await storage.load()
    expect(storage.corrupt).toBe(false)
    expect(get()).toEqual({ empty: true })
  })
  test('writes through a temporary file and leaves nothing behind', async () => {
    const dir = directory()
    const path = join(dir, 'store.json')
    const { storage, set } = store(path)
    set({ a: 1 })
    await Promise.all([storage.write(), storage.write()])
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({ a: 1 })
    expect(readdirSync(dir)).toEqual(['store.json'])
  })
  test('moves a corrupt file aside and loads as empty', async () => {
    const dir = directory()
    const path = join(dir, 'store.json')
    writeFileSync(path, '{"a": ')
    const { storage, get } = store(path)
    await storage.load()
    expect(storage.corrupt).toBe(true)
    expect(get()).toEqual({ empty: true })
    const files = readdirSync(dir)
    expect(files).toHaveLength(1)
    expect(files[0]).toMatch(/^store\.json\.corrupt-\d+$/)
    expect(readFileSync(join(dir, files[0]), 'utf8')).toBe('{"a": ')
  })
  test('marks a file the decoder rejects as corrupt', async () => {
    const path = join(directory(), 'store.json')
    writeFileSync(path, '{}')
    const storage = new Storage(path, () => ({}), () => {
      throw new Error('bad shape')
    })
    await storage.load()
    expect(storage.corrupt).toBe(true)
  })
})

describe('NetworkRegistry', () => {
  test('a corrupt registry gets no new identity and allocates nothing', async () => {
    const { NetworkRegistry } = await import('../src/network/registry')
    const path = join(directory(), 'network.json')
    writeFileSync(path, '{"schemaVersion": 1, "allocations": ')
    const registry = await new NetworkRegistry(path).load()
    expect(registry.getIdentity().hubNetworkId).toBe('')
    expect(() => registry.allocateAddresses('key')).toThrow('corrupt')
  })
})

describe('DeviceRegistry', () => {
  test('a corrupt devices.json moves aside and loads empty', async () => {
    const { DeviceRegistry } = await import('../src/devices')
    const dir = directory()
    const path = join(dir, 'devices.json')
    writeFileSync(path, '{"schema": 1, "revokedKeys": [')
    const registry = await new DeviceRegistry(path).load()
    expect(registry.storage.corrupt).toBe(true)
    expect(registry.data.revokedKeys).toEqual([])
  })
  test('an unknown schema is treated as corrupt', async () => {
    const { DeviceRegistry } = await import('../src/devices')
    const path = join(directory(), 'devices.json')
    writeFileSync(path, '{"schema": 2}')
    expect((await new DeviceRegistry(path).load()).storage.corrupt).toBe(true)
  })
})
