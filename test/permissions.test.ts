import { describe, expect, test } from 'bun:test'
import { chmodSync, mkdirSync, mkdtempSync, statSync, writeFileSync } from 'node:fs'
import { generateKeyPairSync } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { connect, freePort, waitFor } from './helpers'

const mode = (path: string) => statSync(path).mode & 0o777
const index = join(import.meta.dir, '..', 'index.ts')
const env = (cwd: string) => ({ ...process.env, HUB_DEVICE_KEY: join(cwd, 'device.key'), HUBLISTEN: '', HUBOWNER: '', HUB_MODE: '' })

/** Runs hub-server in `cwd` until `hub/info` answers, returns that */
async function run(cwd: string) {
  const port = freePort()
  const proc = Bun.spawn(['bun', index, '-p', `${port}`], { cwd, env: env(cwd), stdout: 'pipe', stderr: 'pipe' })
  try {
    return await waitFor(async () => {
      const c = connect(port)
      const result = await Promise.race([c.sender.send('hub/info').catch(() => undefined), Bun.sleep(300)])
      c.sender.stop()
      return result as any
    }, 20_000)
  } finally {
    proc.kill()
    await proc.exited
  }
}

describe('the hub key is private', () => {
  test('a fresh hub makes data/ 0700 and data/auth 0600', async () => {
    const cwd = mkdtempSync(join(tmpdir(), 'hub-server-perm-'))
    await run(cwd)
    expect(mode(join(cwd, 'data'))).toBe(0o700)
    expect(mode(join(cwd, 'data', 'auth'))).toBe(0o600)
  }, 30_000)

  test('an older hub with a readable key gets it fixed at start and keeps it', async () => {
    const cwd = mkdtempSync(join(tmpdir(), 'hub-server-perm-'))
    const data = join(cwd, 'data')
    mkdirSync(data)
    chmodSync(data, 0o755)
    const keys = generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'der', type: 'pkcs8' },
      publicKeyEncoding: { format: 'der', type: 'spki' },
    })
    writeFileSync(join(data, 'auth'), Buffer.concat([keys.privateKey, keys.publicKey]).toString('base64'))
    chmodSync(join(data, 'auth'), 0o644)
    const info = await run(cwd)
    expect(info.key).toBe(keys.publicKey.toString('base64'))
    expect(mode(data)).toBe(0o700)
    expect(mode(join(data, 'auth'))).toBe(0o600)
  }, 30_000)

  test('the one-shot --pair makes data/ 0700', async () => {
    const cwd = mkdtempSync(join(tmpdir(), 'hub-server-perm-'))
    const proc = Bun.spawn(['bun', index, '--pair'], { cwd, env: env(cwd), stdout: 'pipe' })
    expect(await proc.exited).toBe(0)
    expect(mode(join(cwd, 'data'))).toBe(0o700)
    expect(mode(join(cwd, 'data', 'pairing.json'))).toBe(0o600)
    expect(mode(join(cwd, 'data', 'pairing-code'))).toBe(0o600)
  }, 30_000)
})
