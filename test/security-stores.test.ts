import { describe, expect, test } from 'bun:test'
import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Security } from '../src/security'

const owner = 'owner-key'
const user = 'user-key'

async function securityWith(files: Record<string, string>): Promise<{ security: Security; data: string }> {
  const directory = mkdtempSync(join(tmpdir(), 'hub-server-security-'))
  const data = join(directory, 'data')
  mkdirSync(data)
  for (const [name, text] of Object.entries(files)) writeFileSync(join(data, name), text)
  const cwd = process.cwd()
  process.chdir(directory)
  try {
    const security = await new Security().load()
    security.addOwner(owner)
    return { security, data }
  } finally {
    process.chdir(cwd)
  }
}

describe('corrupt security stores', () => {
  test('a readable call list grants as before', async () => {
    const { security } = await securityWith({ 'clients.json': JSON.stringify({ allowed: { [user]: ['s3/read'] } }) })
    expect(security.lockdown).toBe(false)
    expect(security.allowsCall(user, 's3/read')).toBe(true)
  })
  test('a corrupt call list loads empty without a lockdown', async () => {
    const { security, data } = await securityWith({ 'clients.json': '{' })
    expect(security.lockdown).toBe(false)
    expect(security.call.storage.corrupt).toBe(true)
    expect(security.call.allows(user, 's3/read')).toBe(false)
    expect(readdirSync(data).some(name => name.startsWith('clients.json.corrupt-'))).toBe(true)
  })
  test('a corrupt path list locks the hub down to owners', async () => {
    const { security } = await securityWith({ 'paths.json': '{' })
    expect(security.lockdown).toBe(true)
    expect(security.effectiveMode).toBe('default-deny')
    expect(security.allowsCall(user, 'anything/open')).toBe(false)
    expect(security.allowsCall(user, 'anything/open', true)).toBe(false)
    expect(security.allowsCall(undefined, 'anything/open')).toBe(false)
    expect(security.allowsCall(owner, 'anything/open')).toBe(true)
    expect(security.allowedApi(user, new Set(['anything/open', 'hub/info']))).toEqual(['hub/info'])
  })
  test('an owner setting the mode ends the lockdown', async () => {
    const { security } = await securityWith({ 'paths.json': '{' })
    security.setMode({ mode: 'default-allow' })
    expect(security.lockdown).toBe(false)
    expect(security.allowsCall(user, 'anything/open')).toBe(true)
  })
  test('a corrupt whitelist locks down and admits only owners', async () => {
    const { security } = await securityWith({ 'whitelist.json': '[' })
    expect(security.lockdown).toBe(true)
    expect(security.whitelist.enforced).toBe(true)
    expect(security.whitelist.allows(user)).toBe(false)
    expect(security.whitelist.allows(owner)).toBe(true)
    expect(() => security.keys.verify(undefined, security.whitelist)).toThrow('hub is not available')
  })
})
