// Raw-protocol conformance harness for a Hub server against Docs/Devices/protocol.md (hub-server, the Swift HubServer).
// Run from Core/hub-server: bun run conformance   (or bun test/conformance/e2e-hub.ts)
// Another server: HUB_SERVER_CMD='swift run --package-path ../HubServer hub-server-swift' bun run conformance
//
// The command is run through sh in a fresh empty working directory, with HUB_DEVICE_KEY pointing into it, as
// `<command> --port <port> [--owner <SPKI>]`. Without --owner it must print `Pairing code: XXX-XXX` to stdout (or
// write the code to data/pairing-code), per protocol.md section 12.
import { Channel } from 'channel/client'
import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const HUB_SERVER_CMD = process.env.HUB_SERVER_CMD || `bun '${join(import.meta.dir, '..', '..', 'index.ts')}'`
const START_TIMEOUT = Number(process.env.HUB_SERVER_START_TIMEOUT || 30) * 1000
const port = 20000 + Math.floor(Math.random() * 5000)
const address = `ws://127.0.0.1:${port}`

type Key = { pub: string; priv: ReturnType<typeof createPrivateKey> }
function newKey(): Key {
  const k = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { format: 'der', type: 'pkcs8' },
    publicKeyEncoding: { format: 'der', type: 'spki' },
  })
  return { pub: k.publicKey.toString('base64'), priv: createPrivateKey({ key: k.privateKey, format: 'der', type: 'pkcs8' }) }
}
const sig = (k: Key, s: string) => sign(null, Buffer.from(s), k.priv).toString('base64')
const now = () => Math.floor(Date.now() / 1000)
const deviceId = (k: Key) => createHash('sha256').update(Buffer.from(k.pub, 'base64')).digest('hex').slice(0, 32)
function auth(k: Key, hubKey?: string) {
  const exp = now() + 60
  return hubKey
    ? { v: '1', auth: `key.${k.pub}.${sig(k, `hub1:${hubKey}:${exp}`)}.${exp}` }
    : { v: '0', auth: `key.${k.pub}.${sig(k, `${exp}`)}.${exp}` }
}
function cert(device: Key, service: Key, instance: string, extra: Record<string, unknown> = {}) {
  const iat = now()
  const payload = Buffer.from(JSON.stringify({ v: 1, device: device.pub, service: service.pub, instance, deviceName: 'E2E Mac', platform: 'macos', ...extra, iat, exp: iat + 3600 })).toString('base64url')
  return `${payload}.${sig(device, payload)}`
}

const results: [string, boolean, string?][] = []
async function check(name: string, fn: () => Promise<unknown>) {
  try { await fn(); results.push([name, true]) } catch (e: any) { results.push([name, false, String(e?.message ?? e)]) }
}
const assert = (c: unknown, m: string) => { if (!c) throw new Error(m) }
const wait = (ms: number) => new Promise(r => setTimeout(r, ms))
async function first<T>(it: AsyncIterable<T>, pred: (v: T) => boolean, ms = 4000): Promise<T> {
  const timer = wait(ms).then(() => { throw new Error('timeout waiting for stream value') })
  const run = (async () => { for await (const v of it) if (pred(v)) return v; throw new Error('stream ended') })()
  return Promise.race([run, timer]) as Promise<T>
}

/** Starts the server in a fresh directory and waits until `hub/info` answers */
async function startHub(port: number, args: string[]) {
  const dir = mkdtempSync(join(tmpdir(), 'hub-e2e-'))
  const proc = Bun.spawn(['sh', '-c', `exec ${HUB_SERVER_CMD} "$@"`, 'hub-server', '--port', String(port), ...args], {
    cwd: dir,
    env: { ...process.env, HUB_DEVICE_KEY: join(dir, 'device.key'), HUBLISTEN: '', HUBOWNER: '', HUB_MODE: '' },
    stdout: 'pipe',
    stderr: 'inherit',
  })
  let stdout = ''
  ;(async () => {
    const decoder = new TextDecoder()
    for await (const chunk of proc.stdout) stdout += decoder.decode(chunk)
  })()
  const start = Date.now()
  while (true) {
    const probe = new Channel<any>().connect(`ws://127.0.0.1:${port}`, { headers: () => ({}) }) as any
    const info = await Promise.race([probe.send('hub/info').catch(() => undefined), wait(500)])
    probe.stop?.()
    if (info) break
    if (proc.exitCode !== null) throw new Error(`server exited with ${proc.exitCode}`)
    if (Date.now() - start > START_TIMEOUT) throw new Error('server did not answer hub/info')
    await wait(200)
  }
  return { dir, proc, stdout: () => stdout }
}

/** The pairing code from stdout or data/pairing-code */
async function pairingCode(hub: Awaited<ReturnType<typeof startHub>>): Promise<string> {
  const start = Date.now()
  while (Date.now() - start < 10_000) {
    const printed = hub.stdout().match(/Pairing code: ([0-9A-Z]{3}-[0-9A-Z]{3})/)
    if (printed) return printed[1]
    const file = Bun.file(join(hub.dir, 'data', 'pairing-code'))
    if (await file.exists()) return (await file.text()).trim()
    await wait(100)
  }
  throw new Error('no pairing code printed')
}

const owner = newKey(), svcKey = newKey(), devKey = newKey(), stranger = newKey()
const hub = await startHub(port, ['--owner', owner.pub])
const dir = hub.dir
let pairingHub: Awaited<ReturnType<typeof startHub>> | undefined

let hubKey = ''
const connect = (headers: () => any, onConnect?: (s: any) => Promise<void>, to = address) =>
  new Channel<any>().connect(to, { headers, onConnect })

try {
  // 1. hub/info and v1 auth
  const anon = connect(() => ({}))
  await check('hub/info public', async () => {
    const info = await anon.send('hub/info')
    assert(info?.key && info.protocol === 1, `bad info ${JSON.stringify(info)}`)
    assert(info.mode === 'default-deny', `fresh hub mode ${info.mode}`)
    hubKey = info.key
  })
  const ownerC = connect(() => auth(owner, hubKey))
  await check('owner v1 connect + owner API', async () => { await ownerC.send('hub/security/mode/set', { requireV1: false }) })
  await check('v1 token for another hub is refused', async () => {
    const other = newKey().pub
    const bad = connect(() => auth(stranger, other))
    let failed = false
    try { await Promise.race([bad.send('hub/info'), wait(2000).then(() => { throw new Error('no answer') })]) } catch { failed = true }
    bad.ws?.close?.()
    assert(failed, 'wrong-hub token accepted')
  })

  // 2. a device-certified service registers
  const svcChannel = new Channel<any>()
  let lastContext: any
  svcChannel.post('e2e/whoami', ({ context }: any) => { lastContext = context; return context?.hub?.caller ?? null })
  const svc = svcChannel.connect(address, {
    headers: () => ({ ...auth(svcKey, hubKey), device: cert(devKey, svcKey, 'e2e/echo') }),
    async onConnect(s) { await s.send('hub/service/update', { services: [{ path: 'e2e/whoami' }], reporter: true }) },
  })
  await wait(800)
  await check('device appears pending with safety code', async () => {
    const list: any[] = await first(ownerC.values('hub/devices/pending'), (l: any) => Array.isArray(l) && l.some(d => d.id === deviceId(devKey)))
    const d = list.find(d => d.id === deviceId(devKey))
    assert(/^\d{3} \d{3}$/.test(d.safetyCode), `safety code ${d.safetyCode}`)
  })
  await check('owner approves hosting and device', async () => {
    await ownerC.send('hub/host/update', { key: svcKey.pub, allow: ['e2e/whoami'] }).catch(() => {})
    await ownerC.send('hub/device/approve', { id: deviceId(devKey) })
  })
  await wait(800)
  await check('hub/devices lists device with service instance', async () => {
    const list: any[] = await first(ownerC.values('hub/devices'), (l: any) => Array.isArray(l) && l.some(d => d.id === deviceId(devKey) && d.approved))
    const d = list.find(d => d.id === deviceId(devKey))
    assert(d.services?.some((s: any) => s.key === svcKey.pub && s.instance === 'e2e/echo'), `services ${JSON.stringify(d.services)}`)
  })

  // 3. caller identity and default deny
  await check('owner call carries caller.owner', async () => {
    const caller = await ownerC.send('e2e/whoami')
    assert(caller?.owner === true && caller.key === owner.pub, `caller ${JSON.stringify(caller)}`)
    assert(lastContext?.hub?.hubKey === hubKey, 'hubKey missing in context')
  })
  await check('client-supplied context.hub is replaced', async () => {
    const caller = await ownerC.send('e2e/whoami', undefined, { context: { hub: { caller: { owner: false, key: 'forged' } } } })
    assert(caller?.key === owner.pub, `forged caller passed: ${JSON.stringify(caller)}`)
  })
  const strangerC = connect(() => auth(stranger, hubKey))
  await check('default-deny refuses a stranger', async () => {
    let refused = false
    try { await strangerC.send('e2e/whoami') } catch { refused = true }
    assert(refused, 'stranger allowed')
  })
  await check('hub/connections is owner-only', async () => {
    let refused = false
    try { await first(strangerC.values('hub/connections'), () => true, 1500) } catch { refused = true }
    assert(refused, 'stranger can read hub/connections')
  })
  await check('grant to key lets stranger call', async () => {
    await ownerC.send('hub/grant/add', { subject: { key: stranger.pub }, object: { path: 'e2e/whoami' } })
    const caller = await strangerC.send('e2e/whoami')
    assert(caller?.key === stranger.pub && caller.owner === false, `caller ${JSON.stringify(caller)}`)
  })

  // 4a. groups: person group, several groups per member, group grant
  await check('person group + several groups + group grant', async () => {
    const g1: any = await ownerC.send('hub/group/create', { name: 'Alex', person: true })
    const g2: any = await ownerC.send('hub/group/create', 'Readers')
    const id1 = typeof g1 === 'string' ? g1 : g1?.id, id2 = typeof g2 === 'string' ? g2 : g2?.id
    assert(id1 && id2, `group ids ${JSON.stringify([g1, g2])}`)
    await ownerC.send('hub/group/update/users', { group: id1, add: [`key:${stranger.pub}`] })
    await ownerC.send('hub/group/update/users', { group: id2, add: [`key:${stranger.pub}`] })
    const groups: any = await first(ownerC.values('hub/group/list'), () => true)
    const text = JSON.stringify(groups)
    assert(text.includes('Alex') && !text.includes('[object Object]'), `groups ${text}`)
    const caller = await strangerC.send('e2e/whoami')
    assert(caller?.groups?.includes(id1) && caller.groups.includes(id2), `caller groups ${JSON.stringify(caller?.groups)}`)
  })

  // 4. reporter and selection
  await check('reporter describe + data', async () => {
    await svc.send('hub/device/describe', { os: '27.0', arch: 'arm64', capabilities: { cpu: { cores: 8 } } })
    await svc.send('hub/device/data', { cpu: 0.25 })
    const data: any = await first(ownerC.values('hub/devices/data', { id: deviceId(devKey) }), (d: any) => d?.cpu === 0.25)
    assert(data.cpu === 0.25, 'no data')
  })
  await check('context.device selection', async () => {
    const caller = await ownerC.send('e2e/whoami', undefined, { context: { device: deviceId(devKey) } })
    assert(caller?.owner, 'selection failed')
    let refused = false
    try { await ownerC.send('e2e/whoami', undefined, { context: { device: '0'.repeat(32) } }) } catch { refused = true }
    assert(refused, 'unknown device selection should fail')
  })

  // 5. revoke
  await check('revoke closes the service and refuses its key', async () => {
    await ownerC.send('hub/device/revoke', { id: deviceId(devKey) })
    await wait(800)
    let refused = false
    try { await Promise.race([ownerC.send('e2e/whoami'), wait(2500).then(() => { throw new Error('timeout') })]) } catch { refused = true }
    assert(refused, 'revoked service still answers')
    const list: any[] = await first(ownerC.values('hub/devices'), (l: any) => Array.isArray(l) && l.some(d => d.id === deviceId(devKey)))
    assert(list.find(d => d.id === deviceId(devKey)).revoked === true, 'device not marked revoked')
  })
  await check('revoked key is refused at connect', async () => {
    const again = new Channel<any>().connect(address, { headers: () => ({ ...auth(svcKey, hubKey), device: cert(devKey, svcKey, 'e2e/echo') }) })
    let refused = false
    try { await Promise.race([again.send('hub/info'), wait(2500).then(() => { throw new Error('timeout') })]) } catch { refused = true }
    assert(refused, 'revoked service key could connect')
  })
  await check('network/devices/revoked readable stream exists', async () => {
    let value: any
    try { value = await first(ownerC.values('network/devices/revoked'), () => true, 2500) } catch (e: any) { value = String(e?.message ?? e) }
    assert(Array.isArray(value), `network/devices/revoked → ${JSON.stringify(value)}`)
  })

  // 6. pairing the first owner (protocol.md section 12)
  const pairingPort = port + 5000
  const pairingAddress = `ws://127.0.0.1:${pairingPort}`
  let code = ''
  let pairingKey = ''
  await check('a hub without owners prints a pairing code', async () => {
    pairingHub = await startHub(pairingPort, [])
    code = await pairingCode(pairingHub)
    assert(/^[0-9A-HJKMNP-TV-Z]{3}-[0-9A-HJKMNP-TV-Z]{3}$/.test(code), `code ${code}`)
    const info = await connect(() => ({}), undefined, pairingAddress).send('hub/info')
    pairingKey = info.key
  })
  const pairer = newKey(), pairerDevice = newKey()
  const pairerC = connect(() => ({ ...auth(pairer, pairingKey), device: cert(pairerDevice, pairer, 'e2e/pair') }), undefined, pairingAddress)
  const failure = (promise: Promise<unknown>) => promise.then(() => 'ok', (e: any) => String(e?.message ?? e))
  const wrong = (c: string) => (c[0] === 'A' ? 'B' : 'A') + c.slice(1)
  await check('hub/pair refuses anonymous callers', async () => {
    const result = await failure(connect(() => ({}), undefined, pairingAddress).send('hub/pair', { code }))
    assert(result !== 'ok', 'anonymous caller paired')
  })
  await check('a wrong code fails with invalid pairing code after at least 1 s', async () => {
    const start = Date.now()
    const result = await failure(pairerC.send('hub/pair', { code: wrong(code) }))
    assert(result.includes('invalid pairing code'), `result ${result}`)
    assert(Date.now() - start >= 1000, `answered in ${Date.now() - start} ms`)
  })
  await check('pairing attempts run one at a time', async () => {
    const start = Date.now()
    await Promise.all([1, 2, 3].map(() => failure(pairerC.send('hub/pair', { code: wrong(code) }))))
    assert(Date.now() - start >= 3000, `3 attempts in ${Date.now() - start} ms`)
  })
  await check('the code makes the caller an owner and approves its device', async () => {
    const result = await pairerC.send('hub/pair', { code: code.toLowerCase().replace('-', ' ') })
    assert(result?.owner === true && result.hubKey === pairingKey && typeof result.name === 'string', `result ${JSON.stringify(result)}`)
    const list: any[] = await first(pairerC.values('hub/devices'), (l: any) => Array.isArray(l) && l.some(d => d.id === deviceId(pairerDevice)))
    assert(list.find(d => d.id === deviceId(pairerDevice)).approved === true, 'device not approved')
    await first(pairerC.values('hub/connections'), () => true, 2500)
  })
  await check('the code works once', async () => {
    const result = await failure(connect(() => auth(newKey(), pairingKey), undefined, pairingAddress).send('hub/pair', { code }))
    assert(result.includes('no pairing code'), `result ${result}`)
  })
} finally {
  hub.proc.kill()
  pairingHub?.proc.kill()
  const failed = results.filter(r => !r[1])
  for (const [n, ok, err] of results) console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${err ? ` — ${err}` : ''}`)
  console.log(`\n${results.length - failed.length}/${results.length} passed (hub data in ${dir})`)
  process.exit(failed.length ? 1 : 0)
}
