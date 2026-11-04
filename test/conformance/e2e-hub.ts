// Raw-protocol conformance harness for a Hub server against Docs/Devices/protocol.md (hub-server, the Swift HubServer).
// Run from Core/hub-server: bun run conformance   (or bun test/conformance/e2e-hub.ts)
// Another server: HUB_SERVER_CMD='swift run --package-path ../HubServer hub-server-swift' bun run conformance
//
// The command is run through sh in a fresh empty working directory, with HUB_DEVICE_KEY pointing into it, as
// `<command> --port <port> [--owner <SPKI>]`. Without --owner it must print `Pairing code: XXX-XXX` to stdout (or
// write the code to data/pairing-code), per protocol.md section 12. `<command> --pair` in the same directory must print
// a new code and exit while the server runs, and the server must take that code at once.
import { Channel } from 'channel/client'
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
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
/** protocol.md section 1 */
function safetyCode(hub: string, device: string, codeValue: string) {
  const hex = createHash('sha256').update(`hubcode1:${hub}:${device}:${codeValue}`).digest('hex')
  const digits = (parseInt(hex.slice(0, 8), 16) % 1000000).toString().padStart(6, '0')
  return `${digits.slice(0, 3)} ${digits.slice(3)}`
}
/** Anonymous `hub/info` with a client nonce (protocol.md section 2) */
async function ask(to: string, nonce = randomBytes(32).toString('base64url')) {
  const probe = new Channel<any>().connect(to) as any
  try {
    return { nonce, info: await probe.send('hub/info', { nonce }, { timeout: 5 }) }
  } finally {
    probe.stop?.()
  }
}
const proofHolds = (key: string, nonce: string, proof: string) =>
  verify(null, Buffer.from(`hubinfo1:${key}:${nonce}`), createPublicKey({ key: Buffer.from(key, 'base64'), format: 'der', type: 'spki' }), Buffer.from(proof, 'base64'))
const v1Token = (k: Key, hubKey: string, nonce: string, exp = now() + 30) => ({ v: '1', auth: `key.${k.pub}.${sig(k, `hub1:${hubKey}:${nonce}:${exp}`)}.${exp}.${nonce}` })
/** v1 headers over a fresh challenge from the server at `to` */
async function auth(k: Key, hubKey: string, to = address) {
  return v1Token(k, hubKey, (await ask(to)).info.challenge)
}
/** Whether a connection with these headers opens and answers */
async function opens(headers: any, to = address, ms = 2000): Promise<boolean> {
  const c = new Channel<any>().connect(to, { headers: () => headers }) as any
  try {
    await Promise.race([c.send('hub/info'), wait(ms).then(() => { throw new Error('no answer') })])
    return true
  } catch {
    return false
  } finally {
    c.stop?.()
  }
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

/** Starts the server in a fresh directory and waits until `hub/info` answers. `prepare` plants files there first. */
async function startHub(port: number, args: string[], prepare?: (dir: string) => void) {
  const dir = mkdtempSync(join(tmpdir(), 'hub-e2e-'))
  prepare?.(dir)
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
    assert(info?.key && info.protocol === 2, `bad info ${JSON.stringify(info)}`)
    assert(info.mode === 'default-deny', `fresh hub mode ${info.mode}`)
    assert(typeof info.challenge === 'string' && info.proof === undefined, `bad challenge ${JSON.stringify(info)}`)
    hubKey = info.key
  })
  await check('hub/info proves the key over the client nonce', async () => {
    const { nonce, info } = await ask(address)
    assert(info.key === hubKey && typeof info.proof === 'string', `no proof ${JSON.stringify(info)}`)
    assert(proofHolds(hubKey, nonce, info.proof), 'proof does not verify')
    assert(!proofHolds(hubKey, nonce + 'x', info.proof), 'proof verifies for another nonce')
    let failed = false
    try { await anon.send('hub/info', { nonce: 'short' }) } catch { failed = true }
    assert(failed, 'invalid client nonce accepted')
  })
  await check('v0 and nonce-less v1 tokens are refused by default', async () => {
    const exp = now() + 60
    assert(!(await opens({ v: '0', auth: `key.${owner.pub}.${sig(owner, `${exp}`)}.${exp}` })), 'v0 accepted')
    assert(!(await opens({ v: '1', auth: `key.${owner.pub}.${sig(owner, `hub1:${hubKey}:${exp}`)}.${exp}` })), 'v1 without nonce accepted')
  })
  await check('a v1 token works once', async () => {
    const headers = await auth(owner, hubKey)
    assert(await opens(headers), 'first use refused')
    assert(!(await opens(headers)), 'replayed token accepted')
    const { info } = await ask(address)
    const other = v1Token(stranger, hubKey, info.challenge)
    assert(await opens(other), 'fresh challenge refused')
    assert(!(await opens(v1Token(owner, hubKey, info.challenge))), 'used nonce accepted under another key')
  })
  await check('a made-up or expired-looking nonce is refused', async () => {
    assert(!(await opens(v1Token(owner, hubKey, Buffer.alloc(40, 7).toString('base64url')))), 'forged nonce accepted')
    assert(!(await opens(v1Token(owner, hubKey, 'a.b'))), 'malformed nonce accepted')
  })
  await check('a token over a challenge expires within a minute', async () => {
    const { info } = await ask(address)
    assert(!(await opens(v1Token(owner, hubKey, info.challenge, now() + 300))), 'long token accepted')
  })
  const ownerC = connect(() => auth(owner, hubKey))
  await check('owner v1 connect + owner API', async () => {
    const mode = await first(ownerC.values('hub/security/mode'), (m: any) => !!m)
    assert((mode as any).requireV1 === true, 'requireV1 is off on a new hub')
    await ownerC.send('hub/security/mode/set', { requireV1: true })
  })
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
    headers: async () => ({ ...(await auth(svcKey, hubKey)), device: cert(devKey, svcKey, 'e2e/echo') }),
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

  // 4b. service features: error codes, hub/grant/check, draining (protocol.md sections 5, 6 and 11)
  const rejection = (promise: Promise<unknown>) =>
    promise.then(() => 'ok', (e: any) => `${e?.message ?? e}|${e?.code ?? ''}`)
  await check('call errors carry codes', async () => {
    const nobody = connect(() => auth(newKey(), hubKey))
    const refused = await rejection(nobody.send('e2e/whoami'))
    assert(refused === 'permissions required|forbidden', `stranger call → ${refused}`)
    const missing = await rejection(ownerC.send('e2e/missing'))
    assert(missing === 'api not found|not_found', `missing path → ${missing}`)
    nobody.ws?.close?.()
  })
  await check('hub/grant/check answers for paths under the service\'s own', async () => {
    const ask = (path: string) => svc.send('hub/grant/check', { path, caller: { key: stranger.pub } })
    const before: any = await ask('e2e/moderate')
    assert(before?.allowed === false, `before grant ${JSON.stringify(before)}`)
    const grant: any = await ownerC.send('hub/grant/add', { subject: { key: stranger.pub }, object: { path: 'e2e/moderate' } })
    const after: any = await ask('e2e/moderate')
    assert(after?.allowed === true, `after grant ${JSON.stringify(after)}`)
    await ownerC.send('hub/grant/remove', { id: grant.id })
    const owned: any = await svc.send('hub/grant/check', { path: 'e2e/anything', caller: { key: owner.pub } })
    assert(owned?.allowed === true, `owner ${JSON.stringify(owned)}`)
    const outside = await rejection(ask('billing/refund'))
    assert(outside === 'permissions required|forbidden', `outside its paths → ${outside}`)
  })
  await check('a draining provider finishes running calls and takes no new ones', async () => {
    const provider = (key: Key, answer: (release: Promise<void>) => Promise<string>, release: Promise<void>) => {
      const channel = new Channel<any>()
      channel.post('e2e/drain', () => answer(release))
      return channel.connect(address, {
        headers: () => auth(key, hubKey),
        async onConnect(s) { await s.send('hub/service/update', { services: [{ path: 'e2e/drain' }] }) },
      })
    }
    const firstKey = newKey(), secondKey = newKey()
    let release!: () => void
    const released = new Promise<void>(r => (release = r))
    const first = provider(firstKey, async gate => (await gate, 'first'), released)
    await wait(300)
    await ownerC.send('hub/host/update', { key: firstKey.pub, allow: ['e2e/drain'] })
    await wait(300)
    const running = ownerC.send('e2e/drain')
    await wait(300)
    await first.send('hub/service/update', { draining: true })
    const waiting = ownerC.send('e2e/drain')
    const second = provider(secondKey, async () => 'second', released)
    await wait(300)
    await ownerC.send('hub/host/update', { key: secondKey.pub, allow: ['e2e/drain'] })
    const next = await Promise.race([waiting, wait(4000).then(() => 'timeout')])
    assert(next === 'second', `call after draining → ${next}`)
    release()
    const done = await Promise.race([running, wait(4000).then(() => 'timeout')])
    assert(done === 'first', `running call → ${done}`)
    first.ws?.close?.()
    second.ws?.close?.()
  })

  await check('a caller leaving a stream cancels it at a waiting provider', async () => {
    const key = newKey()
    let cancelled = false
    let sent = false
    const channel = new Channel<any>()
    channel.stream('e2e/feed', () => ({
      next: () => (sent ? new Promise(() => {}) : ((sent = true), Promise.resolve({ value: 'first', done: false }))),
      return: async () => ((cancelled = true), { value: undefined, done: true }),
    }) as any)
    const provider = channel.connect(address, {
      headers: () => auth(key, hubKey),
      async onConnect(s) { await s.send('hub/service/update', { services: [{ path: 'e2e/feed' }] }) },
    })
    await wait(300)
    await ownerC.send('hub/host/update', { key: key.pub, allow: ['e2e/feed'] })
    await wait(300)
    const value = await first(ownerC.values('e2e/feed'), () => true)
    assert(value === 'first', `stream value ${JSON.stringify(value)}`)
    for (let i = 0; i < 40 && !cancelled; i += 1) await wait(50)
    assert(cancelled, 'the provider never saw the cancel')
    provider.ws?.close?.()
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
    const again = new Channel<any>().connect(address, { headers: async () => ({ ...(await auth(svcKey, hubKey)), device: cert(devKey, svcKey, 'e2e/echo') }) })
    let refused = false
    try { await Promise.race([again.send('hub/info'), wait(2500).then(() => { throw new Error('timeout') })]) } catch { refused = true }
    assert(refused, 'revoked service key could connect')
  })
  await check('network/devices/revoked readable stream exists', async () => {
    let value: any
    try { value = await first(ownerC.values('network/devices/revoked'), () => true, 2500) } catch (e: any) { value = String(e?.message ?? e) }
    assert(Array.isArray(value), `network/devices/revoked → ${JSON.stringify(value)}`)
  })

  // 5b. device requests: safety codes and the rate limit (protocol.md sections 1 and 6)
  const failed = (promise: Promise<unknown>, ms = 3000) =>
    Promise.race([promise.then(() => 'ok', (e: any) => String(e?.message ?? e)), wait(ms).then(() => 'timeout')])
  const asking = (name: string, device = newKey(), service = newKey()) => {
    const c = connect(async () => ({ ...(await auth(service, hubKey)), device: cert(device, service, name, { deviceName: name }) }))
    return { c, device, service, id: deviceId(device) }
  }
  const requested = (a: { c: any }, status = 'pending', ms = 6000) =>
    first<any>(a.c.values('hub/device/request'), r => r?.status === status, ms)
  const pendingRow = async (id: string) =>
    (await first<any[]>(ownerC.values('hub/devices/pending'), l => Array.isArray(l) && l.some(d => d.id === id))).find(d => d.id === id)
  await check('a request gets a value from the hub, and both sides compute one code from it', async () => {
    const a = asking('Coded')
    const request = await requested(a)
    assert(request.id === a.id && typeof request.codeValue === 'string' && request.codeValue.length >= 32, `request ${JSON.stringify(request)}`)
    const row = await pendingRow(a.id)
    assert(row.codeValue === request.codeValue, 'the owner and the device got different values')
    assert(row.safetyCode === safetyCode(hubKey, a.device.pub, request.codeValue), `code ${row.safetyCode}`)
    a.c.stop()
  })
  await check('a request sent again with the same key keeps its value', async () => {
    const device = newKey()
    const a = asking('Again', device)
    const { codeValue } = await requested(a)
    a.c.stop()
    const b = asking('Again', device)
    assert((await requested(b)).codeValue === codeValue, 'the value changed for the same key')
    b.c.stop()
  })
  await check('new requests get on the list one a second at most', async () => {
    const before = Date.now()
    const many = [1, 2, 3].map(n => asking(`Many ${n}`))
    await Promise.all(many.map(a => requested(a)))
    assert(Date.now() - before >= 1700, `3 requests in ${Date.now() - before} ms`)
    many.forEach(a => a.c.stop())
  })
  await check('hub/device/request needs a key and a certificate', async () => {
    const plain = connect(() => auth(newKey(), hubKey))
    assert((await failed(first(plain.values('hub/device/request'), () => true))).includes('no device certificate'), 'a plain key has a request')
    assert((await failed(first(connect(() => ({})).values('hub/device/request'), () => true))) !== 'ok', 'an anonymous connection has a request')
  })

  // 5c. names, unique per hub (protocol.md section 13)
  const approved = async (name: string, device?: Key, service?: Key) => {
    const a = asking(name, device, service)
    await requested(a)
    const result = await ownerC.send('hub/device/approve', { id: a.id })
    return { ...a, name: result.name as string }
  }
  const nameOf = async (id: string, expected: string) =>
    (await first<any[]>(ownerC.values('hub/devices'), l => Array.isArray(l) && l.find(d => d.id === id)?.name === expected)).find(d => d.id === id).name
  await check('the second device asking for a name gets a suffix on approval', async () => {
    const a = await approved('Avery'), b = await approved('Avery')
    assert(a.name === 'Avery' && b.name === 'Avery-2', `${a.name}, ${b.name}`)
  })
  await check('lookalikes count as the same name, and it stays as written', async () => {
    const cyrillic = await approved('\u0410very'), spaced = await approved('A very'), invisible = await approved('A\u200Bvery')
    assert(cyrillic.name === '\u0410very-3' && spaced.name === 'A very-4' && invisible.name === 'A\u200Bvery-5', [cyrillic.name, spaced.name, invisible.name].join(', '))
  })
  await check('a pending request holds no name and shows what it asks for', async () => {
    const early = asking('Quinn')
    await requested(early)
    const holder = await approved('Quinn')
    assert(holder.name === 'Quinn', `holder ${holder.name}`)
    assert((await pendingRow(early.id)).name === 'Quinn', 'the request should still show what it asks for')
    assert((await ownerC.send('hub/device/approve', { id: early.id })).name === 'Quinn-2', 'the request took a held name')
    assert((await requested(early, 'approved')).name === 'Quinn-2', 'the device was not told its final name')
    early.c.stop()
  })
  await check('hub/profile/update names no device and needs a key', async () => {
    const quiet = asking('Quiet')
    await requested(quiet)
    await quiet.c.send('hub/profile/update', { name: 'Avery' })
    assert((await pendingRow(quiet.id)).name === 'Quiet', 'a profile changed the name of a request')
    assert((await failed(connect(() => ({})).send('hub/profile/update', { name: 'Avery' }))) !== 'ok', 'an anonymous caller set a name')
    const service = connect(() => auth(newKey(), hubKey))
    await service.send('hub/profile/update', { name: 'S3 Backup' })
    await first<any[]>(ownerC.values('hub/connections'), l => Array.isArray(l) && l.some(c => c.name === 'S3 Backup'))
    quiet.c.stop()
  })
  await check('an approved device asking again keeps its name, and a new one has to be free', async () => {
    const device = newKey()
    const first_ = await approved('Harper')
    const second = await approved('Harper', device)
    assert(second.name === 'Harper-2', second.name)
    first_.c.stop()
    const again = asking('Harper', device)
    await again.c.send('hub/info')
    await nameOf(second.id, 'Harper-2')
    const moved = asking('Fresh Name', device)
    await moved.c.send('hub/info')
    await nameOf(second.id, 'Fresh Name')
    again.c.stop()
    moved.c.stop()
  })
  await check('owner-set names win', async () => {
    const asked = await approved('Morgan'), other = await approved('Dana')
    assert((await ownerC.send('hub/device/rename', { id: other.id, name: 'MORGAN' })).name === 'MORGAN', 'rename')
    await nameOf(asked.id, 'Morgan-2')
    const result = await failed(ownerC.send('hub/device/rename', { id: asked.id, name: 'morgan' }))
    assert(result.includes('name taken'), `renaming onto an owner's name: ${result}`)
    const late = await approved('Morgan')
    assert(late.name === 'Morgan-3', `a device took an owner's name: ${late.name}`)
  })

  // 5d. what members see (protocol.md section 13)
  const list = (c: any, pred: (l: any[]) => boolean = () => true) => first<any[]>(c.values('hub/devices'), l => Array.isArray(l) && pred(l))
  const ids = (l: any[]) => l.map(d => d.id).sort().join()
  const memberA = await approved('Member A'), memberB = await approved('Member B')
  await check('a member sees its own device, not the others', async () => {
    const seen = await list(memberA.c)
    assert(ids(seen) === memberA.id, `saw ${seen.map(d => d.name)}`)
    const everything = await list(ownerC, l => l.some(d => d.id === memberA.id) && l.some(d => d.id === memberB.id))
    assert(everything.length > 2, 'an owner sees everything')
  })
  await check('a grant on a service path shows the device live, with only that path, and removing it hides it', async () => {
    const pathA = 'e2e/dir-one', pathB = 'e2e/dir-two'
    await ownerC.send('hub/host/update', { key: memberB.service.pub, allow: [pathA, pathB] })
    await memberB.c.send('hub/service/update', { services: [{ path: pathA }, { path: pathB }], reporter: true })
    await memberB.c.send('hub/device/describe', { os: 'secret', capabilities: { cpu: { cores: 64 } } })
    const updates = memberA.c.values('hub/devices')[Symbol.asyncIterator]()
    assert(ids((await updates.next()).value) === memberA.id, 'the first value')
    const grant = await ownerC.send('hub/grant/add', { subject: { device: memberA.id }, object: { path: pathA } })
    const next = async (pred: (l: any[]) => boolean) => {
      const timer = wait(4000).then(() => { throw new Error('no live update') })
      while (true) {
        const { value, done } = await Promise.race([updates.next(), timer])
        if (done) throw new Error('stream ended')
        if (pred(value)) return value as any[]
      }
    }
    const shown = (await next(l => l.some(d => d.id === memberB.id))).find(d => d.id === memberB.id)
    assert(shown.services.length === 1 && shown.services[0].paths.join() === pathA, `services ${JSON.stringify(shown.services)}`)
    assert(shown.os === undefined && shown.capabilities === undefined && shown.codeValue === undefined, `too much: ${JSON.stringify(shown)}`)
    await ownerC.send('hub/grant/remove', { id: grant.id })
    await next(l => !l.some(d => d.id === memberB.id))
    updates.return?.()
  })
  await check('a person group shows that person\'s devices', async () => {
    const group = await ownerC.send('hub/group/create', { name: 'Same Person', person: true })
    const id = typeof group === 'string' ? group : group?.id
    await ownerC.send('hub/group/update/users', { group: id, add: [`device:${memberA.id}`, `device:${memberB.id}`] })
    await list(memberA.c, l => l.some(d => d.id === memberB.id && d.os === 'secret'))
    await ownerC.send('hub/group/update/users', { group: id, remove: [`device:${memberA.id}`, `device:${memberB.id}`] })
    await list(memberA.c, l => !l.some(d => d.id === memberB.id))
  })
  await check('live data stays with the device and owners', async () => {
    await memberB.c.send('hub/device/data', { cpu: 0.5 })
    const hidden = await failed(first(memberA.c.values('hub/devices/data', { id: memberB.id }), () => true))
    assert(hidden.includes('device not found'), `another's data: ${hidden}`)
    const missing = await failed(first(memberA.c.values('hub/devices/data', { id: '0'.repeat(32) }), () => true))
    assert(missing === hidden, 'a hidden device answers differently from one that does not exist')
    await first<any>(memberB.c.values('hub/devices/data', { id: memberB.id }), d => d?.cpu === 0.5)
    await first<any>(ownerC.values('hub/devices/data', { id: memberB.id }), d => d?.cpu === 0.5)
  })
  await check('a pending device and an unapproved key see no devices', async () => {
    const waiting = asking('Waiting')
    await requested(waiting)
    assert((await failed(first(waiting.c.values('hub/devices'), () => true))).includes('permissions required'), 'a pending device read the directory')
    assert((await failed(first(connect(() => auth(newKey(), hubKey)).values('hub/devices'), () => true))).includes('permissions required'), 'a plain key read the directory')
    waiting.c.stop()
  })
  await check('network/agents/list hides other members from a member', async () => {
    const value = await first<any>(memberA.c.values('network/agents/list'), () => true)
    assert(Array.isArray(value) && value.length === 0, `agents ${JSON.stringify(value)}`)
  })

  // 5e. a store from before names were unique
  await check('duplicate names in a store settle at load, without touching owner-set names', async () => {
    const storedOwner = newKey()
    const stored = (name: string, createdAt: string, extra: object = {}) => ({ key: name, name, approved: true, createdAt, lastSeen: createdAt, revoked: null, ...extra })
    const old = await startHub(port + 6000, ['--owner', storedOwner.pub], dir => {
      mkdirSync(join(dir, 'data'), { recursive: true })
      writeFileSync(join(dir, 'data', 'devices.json'), JSON.stringify({
        schema: 1,
        services: {},
        revokedKeys: [],
        devices: {
          ['a'.repeat(32)]: stored('Alex', '2026-03-01T00:00:00Z'),
          ['b'.repeat(32)]: stored('Alex', '2026-01-01T00:00:00Z'),
          ['c'.repeat(32)]: stored('\u0410lex', '2026-02-01T00:00:00Z'),
          ['d'.repeat(32)]: stored('Sam', '2026-01-01T00:00:00Z', { nameByOwner: true }),
          ['e'.repeat(32)]: stored('Sam', '2026-02-01T00:00:00Z', { nameByOwner: true }),
          ['f'.repeat(32)]: stored('Alex', '2026-04-01T00:00:00Z', { approved: false }),
        },
      }))
    })
    try {
      const to = `ws://127.0.0.1:${port + 6000}`
      const key = (await ask(to)).info.key
      const c = connect(() => auth(storedOwner, key, to), undefined, to)
      const devices = await list(c, l => l.length >= 6)
      const name = (letter: string) => devices.find(d => d.id === letter.repeat(32))?.name
      assert(name('b') === 'Alex', `oldest ${name('b')}`)
      assert(name('c') === '\u0410lex-2', `second ${name('c')}`)
      assert(name('a') === 'Alex-3', `third ${name('a')}`)
      assert(name('d') === 'Sam' && name('e') === 'Sam', `owner-set ${name('d')}, ${name('e')}`)
      assert(name('f') === 'Alex', `pending ${name('f')}`)
      c.stop?.()
    } finally {
      old.proc.kill()
    }
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
  const pairerC = connect(async () => ({ ...(await auth(pairer, pairingKey, pairingAddress)), device: cert(pairerDevice, pairer, 'e2e/pair') }), undefined, pairingAddress)
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
  await check('the one-shot --pair replaces the code for the running hub and exits', async () => {
    const proc = Bun.spawn(['sh', '-c', `exec ${HUB_SERVER_CMD} "$@"`, 'hub-server', '--pair'], {
      cwd: pairingHub!.dir,
      env: { ...process.env, HUB_DEVICE_KEY: join(pairingHub!.dir, 'device.key'), HUBLISTEN: '', HUBOWNER: '', HUB_MODE: '' },
      stdout: 'pipe',
      stderr: 'inherit',
    })
    const exited = await Promise.race([proc.exited, wait(START_TIMEOUT).then(() => 'timeout')])
    if (exited === 'timeout') proc.kill()
    assert(exited === 0, `--pair exited with ${exited}`)
    const printed = (await new Response(proc.stdout).text()).match(/Pairing code: ([0-9A-Z]{3}-[0-9A-Z]{3})/)?.[1]
    assert(printed, 'no pairing code printed')
    if (printed !== code) {
      const old = await failure(pairerC.send('hub/pair', { code }))
      assert(old.includes('invalid pairing code'), `old code: ${old}`)
    }
    code = printed!
  })
  await check('the code makes the caller an owner and approves its device', async () => {
    const result = await pairerC.send('hub/pair', { code: code.toLowerCase().replace('-', ' ') })
    assert(result?.owner === true && result.hubKey === pairingKey && typeof result.name === 'string', `result ${JSON.stringify(result)}`)
    const list: any[] = await first(pairerC.values('hub/devices'), (l: any) => Array.isArray(l) && l.some(d => d.id === deviceId(pairerDevice)))
    assert(list.find(d => d.id === deviceId(pairerDevice)).approved === true, 'device not approved')
    await first(pairerC.values('hub/connections'), () => true, 2500)
  })
  await check('the code works once', async () => {
    const result = await failure(connect(() => auth(newKey(), pairingKey, pairingAddress), undefined, pairingAddress).send('hub/pair', { code }))
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
