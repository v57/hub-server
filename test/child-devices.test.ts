import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { sign } from 'node:crypto'
import { Hub, security } from '../src/hub'
import { attachSignedData, deviceId } from '../src/devices'
import { deviceMember, keyMember, ownersGroup } from '../src/security'
import { certificate, connect, freePort, makeKey, token, until, waitFor, type Client, type TestKey } from './helpers'

const failure = (promise: Promise<unknown>) => promise.then(() => 'ok', error => String(error))

describe('child devices (protocol.md section 14)', () => {
  const port = freePort()
  let hub: Hub
  const clients: Client[] = []
  const owner = makeKey()
  const ownerDevice = makeKey()
  let ownerClient: Client

  /** A device connection with its own service key */
  function device(key = makeKey(), service = makeKey()) {
    const client = connect(port, () => ({
      auth: token(service, security.hubKey, security.nonces),
      v: '1',
      device: certificate(key, service),
    }))
    clients.push(client)
    return { key, service, client, id: deviceId(key.key) }
  }
  const signature = (parent: TestKey, child: TestKey, at = Math.floor(Date.now() / 1000), hubKey = security.hubKey!) => ({
    at,
    signature: sign(null, Buffer.from(attachSignedData(hubKey, parent.key, child.key, at)), parent.privateKey).toString('base64'),
  })
  const row = (id: string) => hub.devices.registry.device(id)
  const grantsOf = (id: string) => security.grants.grants.filter(grant => 'device' in grant.subject && grant.subject.device === id)
  /** Waits until a new device has a row, past the one-a-second gate */
  const hasRow = (id: string) => waitFor(() => !!row(id), 5000)
  async function attached(parent: ReturnType<typeof device>, name = makeKey()) {
    const child = device(name)
    // Below another child the parent is no owner: the child names it, and an owner approves
    const isOwner = parent.client === ownerClient
    await child.client.sender.send('hub/device/attach/ask', isOwner ? {} : { parent: parent.id })
    await hasRow(child.id)
    await parent.client.sender.send('hub/device/attach', { child: child.id, ...signature(parent.key, child.key) })
    if (!isOwner) await ownerClient.sender.send('hub/device/approve', { id: child.id })
    await waitFor(() => row(child.id)?.approved)
    return child
  }

  beforeAll(async () => {
    hub = new Hub(port)
    await hub.ready
    hub.devices.gate.interval = 1
    security.addOwner(owner.key)
    security.addOwner(ownerDevice.key)
    ownerClient = connect(port, () => ({ auth: token(owner, security.hubKey, security.nonces), v: '1', device: certificate(ownerDevice, owner) }))
    clients.push(ownerClient)
    await ownerClient.sender.send('hub/key')
    await waitFor(() => row(deviceId(ownerDevice.key))?.approved)
  })
  afterAll(() => {
    clients.forEach(client => client.sender.stop())
    hub.server?.stop(true)
  })
  const parentDevice = (): ReturnType<typeof device> => ({ key: ownerDevice, service: owner, client: ownerClient, id: deviceId(ownerDevice.key) })

  test('a declared parent name counts for nothing', async () => {
    const child = makeKey()
    const service = makeKey()
    const client = connect(port, () => ({
      auth: token(service, security.hubKey, security.nonces),
      v: '1',
      device: certificate(child, service, { parent: 'Mac Studio', deviceName: 'declared' }),
    }))
    clients.push(client)
    await client.sender.send('hub/api')
    const id = deviceId(child.key)
    await hasRow(id)
    expect(row(id)).toMatchObject({ parent: 'Mac Studio', approved: false })
    expect(row(id)?.attached).toBeUndefined()
    expect(hub.devices.describe(id)?.attachedTo).toBeUndefined()
    // Asking isn't attaching either
    await client.sender.send('hub/device/attach/ask', {})
    expect(row(id)?.approved).toBe(false)
    expect(row(id)?.attached).toBeUndefined()
  })

  test('only the parent\'s signature attaches, for this hub and this child', async () => {
    const parent = parentDevice()
    const child = device()
    await child.client.sender.send('hub/device/attach/ask', {})
    await hasRow(child.id)
    const send = (body: any) => failure(parent.client.sender.send('hub/device/attach', { child: child.id, ...body }))
    const stranger = makeKey()
    expect(await send(signature(stranger, child.key))).toContain('invalid signature')
    expect(await send(signature(parent.key, makeKey()))).toContain('invalid signature')
    expect(await send(signature(parent.key, child.key, undefined, makeKey().key))).toContain('invalid signature')
    expect(await send(signature(parent.key, child.key, Math.floor(Date.now() / 1000) - 400))).toContain('expired')
    expect(await send({})).toContain('expired')
    expect(row(child.id)?.attached).toBeUndefined()
    expect(row(child.id)?.approved).toBe(false)
    expect(await send(signature(parent.key, child.key))).toBe('ok')
    expect(row(child.id)?.attached?.parent).toBe(parent.id)
    expect(row(child.id)?.approved).toBe(true)
    expect(hub.devices.describe(child.id)).toMatchObject({ attachedTo: parent.id, linked: false })
    expect(await send(signature(parent.key, child.key))).toContain('already attached')
  })

  test('a device that did not ask can not be taken', async () => {
    const parent = parentDevice()
    const child = device()
    await child.client.sender.send('hub/api')
    await hasRow(child.id)
    expect(await failure(parent.client.sender.send('hub/device/attach', { child: child.id, ...signature(parent.key, child.key) }))).toContain('no attach request')
  })

  test('a new child has no grants, and asking needs a certificate', async () => {
    const parent = parentDevice()
    await ownerClient.sender.send('hub/grant/add', { subject: { device: parent.id }, object: { path: 'tools/first' } })
    const child = await attached(parent)
    expect(grantsOf(child.id)).toEqual([])
    const plain = makeKey()
    const client = connect(port, () => ({ auth: token(plain, security.hubKey, security.nonces), v: '1' }))
    clients.push(client)
    expect(await failure(client.sender.send('hub/device/attach/ask', {}))).toContain('no device certificate')
  })

  test('a loop is refused, at any depth', async () => {
    const parent = parentDevice()
    const a = await attached(parent)
    const b = await attached(a)
    const c = await attached(b)
    // a would become a child of its own descendant: detach it from the top first, keeping the chain below it
    await ownerClient.sender.send('hub/device/detach', { id: a.id })
    await a.client.sender.send('hub/device/attach/ask', { parent: c.id })
    expect(await failure(c.client.sender.send('hub/device/attach', { child: a.id, ...signature(c.key, a.key) }))).toContain('loop')
    const self = device()
    await self.client.sender.send('hub/device/attach/ask', {})
    await hasRow(self.id)
    await ownerClient.sender.send('hub/device/approve', { id: self.id })
    expect(await failure(self.client.sender.send('hub/device/attach', { child: self.id, ...signature(self.key, self.key) }))).not.toBe('ok')
  })

  test('only linked grants pass, only to linked children, in one go down the chain', async () => {
    const parent = parentDevice()
    const child = await attached(parent)
    const grandchild = await attached(child)
    const grant = await ownerClient.sender.send('hub/grant/add', { subject: { device: parent.id }, object: { path: 'tools/linked' } })
    const unlinked = await ownerClient.sender.send('hub/grant/add', { subject: { device: parent.id }, object: { path: 'tools/unlinked' } })
    await ownerClient.sender.send('hub/grant/link', { id: grant.id, linked: true })
    // Nothing passes while the child isn't linked
    expect(grantsOf(child.id)).toEqual([])
    await ownerClient.sender.send('hub/device/link', { id: child.id, linked: true })
    expect(grantsOf(child.id)).toMatchObject([{ object: { path: 'tools/linked' }, copyOf: grant.id }])
    expect(grantsOf(grandchild.id)).toEqual([])
    await ownerClient.sender.send('hub/device/link', { id: grandchild.id, linked: true })
    expect(grantsOf(grandchild.id)).toMatchObject([{ object: { path: 'tools/linked' }, copyOf: grant.id }])
    expect(security.granted(security.caller({ device: grandchild.id }), 'tools/linked')).toBe(true)
    expect(security.granted(security.caller({ device: grandchild.id }), 'tools/unlinked')).toBe(false)
    // A grant added later and linked goes down too
    await ownerClient.sender.send('hub/grant/link', { id: unlinked.id, linked: true })
    expect(security.granted(security.caller({ device: grandchild.id }), 'tools/unlinked')).toBe(true)
    await ownerClient.sender.send('hub/grant/link', { id: unlinked.id, linked: false })
    expect(security.granted(security.caller({ device: grandchild.id }), 'tools/unlinked')).toBe(false)
    expect(security.granted(security.caller({ device: child.id }), 'tools/unlinked')).toBe(false)
    // Unlinking a child in the middle takes what passed through it
    await ownerClient.sender.send('hub/device/link', { id: child.id, linked: false })
    expect(grantsOf(child.id)).toEqual([])
    expect(grantsOf(grandchild.id)).toEqual([])
    await ownerClient.sender.send('hub/device/link', { id: child.id, linked: true })
    expect(grantsOf(grandchild.id)).toHaveLength(1)
    await ownerClient.sender.send('hub/grant/remove', { id: grant.id })
    expect(grantsOf(child.id)).toEqual([])
    expect(grantsOf(grandchild.id)).toEqual([])
  })

  test('a copy goes with its grant, and what the owner gave directly stays', async () => {
    const parent = parentDevice()
    const child = await attached(parent)
    await ownerClient.sender.send('hub/device/link', { id: child.id, linked: true })
    const source = await ownerClient.sender.send('hub/grant/add', { subject: { device: parent.id }, object: { prefix: 'both/' } })
    await ownerClient.sender.send('hub/grant/link', { id: source.id, linked: true })
    const direct = await ownerClient.sender.send('hub/grant/add', { subject: { device: child.id }, object: { path: 'only/child' } })
    const copy = grantsOf(child.id).find(grant => grant.copyOf)!
    expect(copy.object).toEqual({ prefix: 'both/' })
    expect(await failure(ownerClient.sender.send('hub/grant/remove', { id: copy.id }))).toContain('copy')
    expect(await failure(ownerClient.sender.send('hub/grant/link', { id: copy.id, linked: true }))).not.toBe('ok')
    await ownerClient.sender.send('hub/grant/remove', { id: source.id })
    expect(grantsOf(child.id).map(grant => grant.id)).toEqual([direct.id])
  })

  test('an owner adding what a child has by copy makes it direct', async () => {
    const parent = parentDevice()
    const child = await attached(parent)
    await ownerClient.sender.send('hub/device/link', { id: child.id, linked: true })
    const source = await ownerClient.sender.send('hub/grant/add', { subject: { device: parent.id }, object: { path: 'kept/path' } })
    await ownerClient.sender.send('hub/grant/link', { id: source.id, linked: true })
    const copy = grantsOf(child.id)[0]!
    const direct = await ownerClient.sender.send('hub/grant/add', { subject: { device: child.id }, object: { path: 'kept/path' } })
    expect(direct.id).toBe(copy.id)
    expect(direct.copyOf).toBeUndefined()
    await ownerClient.sender.send('hub/grant/remove', { id: source.id })
    expect(grantsOf(child.id).map(grant => grant.id)).toEqual([copy.id])
    // And removing it now is the owner's to do
    await ownerClient.sender.send('hub/grant/remove', { id: copy.id })
    expect(grantsOf(child.id)).toEqual([])
  })

  test('groups never pass down, and a child is never an owner', async () => {
    const parent = parentDevice()
    const child = await attached(parent)
    await ownerClient.sender.send('hub/device/link', { id: child.id, linked: true })
    expect(security.caller({ device: parent.id }).owner).toBe(true)
    expect(security.caller({ device: child.id }).owner).toBe(false)
    // Grants to a group the parent is in don't come along
    const group = await ownerClient.sender.send('hub/grant/add', { subject: { group: ownersGroup }, object: { path: 'group/only' } })
    expect(await failure(ownerClient.sender.send('hub/grant/link', { id: group.id, linked: true }))).not.toBe('ok')
    expect(security.granted(security.caller({ device: child.id }), 'group/only')).toBe(false)
    await ownerClient.sender.send('hub/grant/remove', { id: group.id })
    // Added to the group by hand it still isn't one
    security.members.add(ownersGroup, deviceMember(child.id))
    security.members.add(ownersGroup, keyMember(child.service.key))
    expect(security.caller({ device: child.id, key: child.service.key })).toMatchObject({ owner: false })
    expect(security.isOwner({ device: child.id })).toBe(false)
    expect(await failure(child.client.sender.send('hub/key'))).toContain('permissions required')
    security.members.remove(ownersGroup, deviceMember(child.id))
    security.members.remove(ownersGroup, keyMember(child.service.key))
    // It can't pair its way there, and the code isn't used up
    const code = await hub.pairing.create()
    expect(await failure(child.client.sender.send('hub/pair', { code }))).toContain('child')
    await hub.pairing.clear()
    // An owner can't become a child
    const another = device()
    security.addOwner(another.key.key)
    await another.client.sender.send('hub/device/attach/ask', {})
    await hasRow(another.id)
    expect(await failure(ownerClient.sender.send('hub/device/attach', { child: another.id, ...signature(ownerDevice, another.key) }))).toContain('owner')
    security.members.remove(ownersGroup, deviceMember(another.id))
    security.members.remove(ownersGroup, keyMember(another.key.key))
  })

  test('the change fires for copies, so Hub Network can close a child\'s share connections', async () => {
    const parent = parentDevice()
    const child = await attached(parent)
    await ownerClient.sender.send('hub/device/link', { id: child.id, linked: true })
    const seen: any[] = []
    const previous = security.grants.onChange
    security.grants.onChange = changed => {
      seen.push(...changed)
      previous?.(changed)
    }
    try {
      const source = await ownerClient.sender.send('hub/grant/add', { subject: { device: parent.id }, object: { share: 'resource-1' } })
      await ownerClient.sender.send('hub/grant/link', { id: source.id, linked: true })
      expect(seen.some(grant => grant.subject.device === child.id && grant.object.share === 'resource-1')).toBe(true)
      seen.length = 0
      await ownerClient.sender.send('hub/grant/remove', { id: source.id })
      expect(seen.some(grant => grant.subject.device === child.id && grant.object.share === 'resource-1')).toBe(true)
      expect(security.grants.allowsShare(security.caller({ device: child.id }), 'resource-1')).toBe(false)
    } finally {
      security.grants.onChange = previous
    }
  })

  test('revoking a parent revokes everything below, revoking a child leaves the parent', async () => {
    const owners = parentDevice()
    const parent = await attached(owners)
    const child = await attached(parent)
    const grandchild = await attached(child)
    await ownerClient.sender.send('hub/device/revoke', { id: grandchild.id })
    expect(row(grandchild.id)?.revoked).toBeTruthy()
    expect(row(child.id)?.revoked).toBeFalsy()
    expect(row(parent.id)?.revoked).toBeFalsy()
    const another = await attached(parent)
    await ownerClient.sender.send('hub/device/revoke', { id: parent.id })
    for (const device of [parent, child, another]) {
      expect(row(device.id)?.revoked).toBeTruthy()
      expect(hub.devices.registry.isKeyRevoked(device.service.key)).toBe(true)
    }
    expect(row(owners.id)?.revoked).toBeFalsy()
  })

  test('removing a parent sends its children back to asking', async () => {
    const owners = parentDevice()
    const parent = await attached(owners)
    const child = await attached(parent)
    await ownerClient.sender.send('hub/device/remove', { id: parent.id })
    expect(row(parent.id)).toBeUndefined()
    expect(row(child.id)).toBeUndefined()
  })

  test('a member\'s device takes only a child that named it, and an owner approves that child', async () => {
    const member = device()
    await member.client.sender.send('hub/api')
    await hasRow(member.id)
    await ownerClient.sender.send('hub/device/approve', { id: member.id })
    await waitFor(() => row(member.id)?.approved)
    const stranger = device()
    await stranger.client.sender.send('hub/device/attach/ask', {})
    await hasRow(stranger.id)
    expect(await failure(member.client.sender.send('hub/device/attach', { child: stranger.id, ...signature(member.key, stranger.key) }))).toContain('permissions required')
    const child = device()
    await child.client.sender.send('hub/device/attach/ask', { parent: member.id })
    await hasRow(child.id)
    // It sees only what names it
    const requests = await until<any[]>(member.client, 'hub/device/attach/requests', list => list.length > 0)
    expect(requests.map(request => request.id)).toEqual([child.id])
    await member.client.sender.send('hub/device/attach', { child: child.id, ...signature(member.key, child.key) })
    expect(row(child.id)?.attached?.parent).toBe(member.id)
    expect(row(child.id)?.approved).toBe(false)
    await ownerClient.sender.send('hub/device/approve', { id: child.id })
    expect(row(child.id)?.approved).toBe(true)
    // A member can't link, and an owner naming another parent is held to it
    expect(await failure(member.client.sender.send('hub/device/link', { id: child.id, linked: true }))).toContain('permissions required')
    const named = device()
    await named.client.sender.send('hub/device/attach/ask', { parent: member.id })
    await hasRow(named.id)
    expect(await failure(ownerClient.sender.send('hub/device/attach', { child: named.id, ...signature(ownerDevice, named.key) }))).toContain('another parent')
  })

  test('a turned down request stays down, and detaching drops copies but not the device', async () => {
    const parent = parentDevice()
    const asker = device()
    await asker.client.sender.send('hub/device/attach/ask', {})
    await hasRow(asker.id)
    await ownerClient.sender.send('hub/device/attach/dismiss', { id: asker.id })
    await asker.client.sender.send('hub/device/attach/ask', {})
    expect(row(asker.id)?.attachAsk).toBeUndefined()
    const child = await attached(parent)
    await ownerClient.sender.send('hub/device/link', { id: child.id, linked: true })
    const source = await ownerClient.sender.send('hub/grant/add', { subject: { device: parent.id }, object: { path: 'detach/me' } })
    await ownerClient.sender.send('hub/grant/link', { id: source.id, linked: true })
    expect(grantsOf(child.id)).toHaveLength(1)
    await ownerClient.sender.send('hub/device/detach', { id: child.id })
    expect(grantsOf(child.id)).toEqual([])
    expect(row(child.id)).toMatchObject({ approved: true })
    expect(row(child.id)?.attached).toBeUndefined()
    await ownerClient.sender.send('hub/grant/remove', { id: source.id })
  })

  test('calls read the copies: a child\'s connection may call what passed to it, with no walk', async () => {
    const parent = parentDevice()
    const child = await attached(parent)
    await ownerClient.sender.send('hub/device/link', { id: child.id, linked: true })
    const source = await ownerClient.sender.send('hub/grant/add', { subject: { device: parent.id }, object: { path: 'walk/none' } })
    await ownerClient.sender.send('hub/grant/link', { id: source.id, linked: true })
    // Corrupt the links on purpose: a call only looks at this device's own grants
    const stored = row(child.id)!.attached
    delete row(child.id)!.attached
    expect(security.granted(security.caller({ device: child.id }), 'walk/none')).toBe(true)
    row(child.id)!.attached = stored
    await ownerClient.sender.send('hub/grant/remove', { id: source.id })
  })
})
