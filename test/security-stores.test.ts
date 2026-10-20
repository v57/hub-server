import { describe, expect, test } from 'bun:test'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Security } from '../src/security'

const owner = 'owner-key'
const user = 'user-key'

async function securityWith(files: Record<string, string>): Promise<Security> {
  const directory = mkdtempSync(join(tmpdir(), 'hub-pro-security-'))
  mkdirSync(join(directory, 'data'))
  for (const [name, text] of Object.entries(files)) writeFileSync(join(directory, 'data', name), text)
  const cwd = process.cwd()
  process.chdir(directory)
  try {
    const security = await new Security().load()
    security.addOwner(owner)
    return security
  } finally {
    process.chdir(cwd)
  }
}

describe('corrupt security stores', () => {
  test('a readable call list grants as before', async () => {
    const security = await securityWith({ 'clients.json': JSON.stringify({ allowed: { [user]: ['s3/read'] } }) })
    expect(security.corrupt).toBe(false)
    expect(security.allowsCall(user, 's3/read')).toBe(true)
  })
  test('a corrupt path list denies every non-owner call', async () => {
    const security = await securityWith({ 'paths.json': '{' })
    expect(security.corrupt).toBe(true)
    expect(security.allowsCall(user, 'anything/open')).toBe(false)
    expect(security.allowsCall(undefined, 'anything/open')).toBe(false)
    expect(security.allowsCall(owner, 'anything/open')).toBe(true)
    expect(security.allowedApi(user, new Set(['anything/open']))).toEqual([])
  })
  test('a corrupt host list lets only owners host', async () => {
    const security = await securityWith({ 'services.json': 'not json' })
    expect(security.allowsHost(user, 's3/read')).toBe(false)
    expect(security.allowsHost(owner, 's3/read')).toBe(true)
  })
  test('a corrupt whitelist admits only owners', async () => {
    const security = await securityWith({ 'whitelist.json': '[' })
    expect(security.whitelist.enforced).toBe(true)
    expect(security.whitelist.allows(user)).toBe(false)
    expect(security.whitelist.allows(owner)).toBe(true)
    expect(() => security.keys.verify(undefined, security.whitelist)).toThrow('hub is not available')
  })
})
