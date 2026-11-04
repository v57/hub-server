import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { Hub, security } from '../src/hub'
import { deviceId } from '../src/devices'
import { HUB_NETWORK_WIRE_VERSION } from '../src/network/wire'
import { certificate, connect, first, freePort, makeKey, token, until, type Client, type TestKey } from './helpers'

describe('what members see of the devices', () => {
  const port = freePort()
  const owner = makeKey()
  let hub: Hub
  const clients: Client[] = []
  const v1 = (key: TestKey, device?: TestKey, fields?: Record<string, unknown>) => () => ({
    auth: token(key, security.hubKey, security.nonces),
    v: '1',
    ...(device ? { device: certificate(device, key, fields) } : {}),
  })
  const client = (headers?: () => Record<string, string>) => {
    const c = connect(port, headers)
    clients.push(c)
    return c
  }
  let owners: Client
  interface Member {
    device: TestKey
    key: TestKey
    id: string
    client: Client
  }
  async function member(name: string): Promise<Member> {
    const device = makeKey()
    const key = makeKey()
    const id = deviceId(device.key)
    const c = client(v1(key, device, { deviceName: name }))
    await until<any>(c, 'hub/device/request', r => r.status === 'pending')
    await owners.sender.send('hub/device/approve', { id })
    await until<any>(c, 'hub/device/request', r => r.status === 'approved')
    return { device, key, id, client: c }
  }
  const ids = (list: any[]) => list.map(d => d.id).sort()
  const sees = (m: Member, check: (list: any[]) => boolean) => until<any[]>(m.client, 'hub/devices', check)
  const stream = (m: Member) => m.client.sender.values('hub/devices')[Symbol.asyncIterator]()

  beforeAll(async () => {
    security.addOwner(owner.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    hub.devices.gate.interval = 0
    await hub.ready
    owners = client(v1(owner))
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('a member sees its own device, not the others', async () => {
    const a = await member('A one')
    const b = await member('B one')
    expect(ids(await first(a.client, 'hub/devices'))).toEqual([a.id])
    expect(ids(await first(b.client, 'hub/devices'))).toEqual([b.id])
    // Owners still see everything
    const all = await until<any[]>(owners, 'hub/devices', list => [a.id, b.id].every(id => list.some(d => d.id === id)))
    expect(all.some(d => d.id === hub.devices.selfId)).toBe(true)
  })

  test('a member sees its own device in full, with what its code covers', async () => {
    const a = await member('A two')
    await a.client.sender.send('hub/service/update', { reporter: true })
    await a.client.sender.send('hub/device/describe', { os: '27', arch: 'arm64', capabilities: { cpu: { cores: 8 } } })
    const [own] = await sees(a, list => list[0]?.os === '27')
    expect(own).toMatchObject({ os: '27', arch: 'arm64', capabilities: { cpu: { cores: 8 } } })
    expect(own.codeValue).toBeString()
  })

  test('a grant on a service path shows the device with only that path', async () => {
    const a = await member('A three')
    const b = await member('B three')
    security.host.allow(b.key.key, ['dir/one', 'dir/two'])
    await b.client.sender.send('hub/service/update', { services: [{ path: 'dir/one' }, { path: 'dir/two' }], reporter: true })
    await b.client.sender.send('hub/device/describe', { os: 'secret-os', capabilities: { cpu: { cores: 64 }, ssh: undefined } })
    const updates = stream(a)
    expect(ids((await updates.next()).value)).toEqual([a.id])
    const grant = await owners.sender.send<any>('hub/grant/add', { subject: { device: a.id }, object: { path: 'dir/one' } })
    // The live update, not only the first response
    let list: any[] = []
    while (!list.some(d => d.id === b.id)) list = (await updates.next()).value
    const shared = list.find(d => d.id === b.id)
    expect(shared.name).toBe('B three')
    expect(shared.services).toEqual([expect.objectContaining({ key: b.key.key, paths: ['dir/one'] })])
    for (const hidden of ['os', 'arch', 'parent', 'capabilities', 'codeValue']) expect(shared[hidden]).toBeUndefined()
    // Taking it back reaches the same stream
    await owners.sender.send('hub/grant/remove', { id: grant.id })
    while (list.some(d => d.id === b.id)) list = (await updates.next()).value
    expect(ids(list)).toEqual([a.id])
    updates.return?.()
  })

  test('a share shows the device fronting it, for the member it was shared with', async () => {
    const a = await member('A four')
    const b = await member('B four')
    const c = await member('C four')
    hub.networkAPI!.registry.data.resources['res-four'] = {
      resourceId: 'res-four',
      ownerKey: b.key.key,
      policy: { mode: 'private' },
    } as any
    expect(ids(await first(a.client, 'hub/devices'))).toEqual([a.id])
    await owners.sender.send('hub/grant/add', { subject: { key: a.key.key }, object: { share: 'res-four' } })
    const list = await sees(a, l => l.some(d => d.id === b.id))
    expect(ids(list)).toEqual([a.id, b.id].sort())
    expect(ids(await first(c.client, 'hub/devices'))).toEqual([c.id])
    delete hub.networkAPI!.registry.data.resources['res-four']
  })

  test('a person group shows the devices of that person, in full', async () => {
    const phone = await member('Lee phone')
    const laptop = await member('Lee laptop')
    const other = await member('Not Lee')
    const group: any = await owners.sender.send('hub/group/create', { name: 'Lee', person: true })
    await owners.sender.send('hub/group/update/users', { group, add: [`device:${phone.id}`, `device:${laptop.id}`] })
    const list = await sees(phone, l => l.some(d => d.id === laptop.id))
    expect(ids(list)).toEqual([phone.id, laptop.id].sort())
    // A group that isn't a person shares nothing by itself
    const team: any = await owners.sender.send('hub/group/create', 'Team four')
    await owners.sender.send('hub/group/update/users', { group: team, add: [`device:${phone.id}`, `device:${other.id}`] })
    await Bun.sleep(100)
    expect(ids(await first(other.client, 'hub/devices'))).toEqual([other.id])
  })

  test('a grant on hub/devices itself is the whole directory, by an owner\'s choice', async () => {
    const reader = makeKey()
    const c = client(v1(reader))
    await expect(first(c, 'hub/devices')).rejects.toThrow('permissions required')
    const grant = await owners.sender.send<any>('hub/grant/add', { subject: { key: reader.key }, object: { path: 'hub/devices' } })
    const fresh = client(v1(reader))
    const list = await first<any[]>(fresh, 'hub/devices')
    expect(list.some(d => d.id === hub.devices.selfId)).toBe(true)
    await owners.sender.send('hub/grant/remove', { id: grant.id })
  })

  test('live data stays with the device, its person and owners, and stops when access does', async () => {
    const a = await member('A five')
    const b = await member('B five')
    await b.client.sender.send('hub/service/update', { services: [{ path: 'dir/five' }], reporter: true })
    await b.client.sender.send('hub/device/data', { cpu: 0.5 })
    await expect(first(a.client, 'hub/devices/data', { id: b.id })).rejects.toThrow('device not found')
    await expect(first(a.client, 'hub/devices/data', { id: 'nope' })).rejects.toThrow('device not found')
    expect(await until<any>(b.client, 'hub/devices/data', d => d.cpu === 0.5, { id: b.id })).toEqual({ cpu: 0.5 })
    expect(await until<any>(owners, 'hub/devices/data', d => d.cpu === 0.5, { id: b.id })).toEqual({ cpu: 0.5 })
    // A person group opens it, and leaving the group closes the running stream
    const group: any = await owners.sender.send('hub/group/create', { name: 'Five', person: true })
    await owners.sender.send('hub/group/update/users', { group, add: [`device:${a.id}`, `device:${b.id}`] })
    const data = a.client.sender.values('hub/devices/data', { id: b.id })[Symbol.asyncIterator]()
    expect((await data.next()).value).toEqual({ cpu: 0.5 })
    await owners.sender.send('hub/group/update/users', { group, remove: [`device:${a.id}`] })
    expect((await data.next()).value).toEqual({})
    await b.client.sender.send('hub/device/data', { cpu: 0.9 })
    const nothing = await Promise.race([data.next(), Bun.sleep(200).then(() => 'silent')])
    expect(nothing).toBe('silent')
    data.return?.()
  })

  test('a pending device and an unapproved key see nothing', async () => {
    const device = makeKey()
    const pending = client(v1(makeKey(), device))
    await until<any>(pending, 'hub/device/request', r => r.status === 'pending')
    await expect(first(pending, 'hub/devices')).rejects.toThrow('permissions required')
    await expect(first(pending, 'hub/devices/data', { id: hub.devices.selfId })).rejects.toThrow('permissions required')
    await expect(first(client(), 'hub/devices')).rejects.toThrow('permissions required')
  })

  test('network/agents/list shows a member only what it may reach, under hub-given names', async () => {
    const memberA = await member('Agent member')
    const agentDevice = makeKey()
    security.addOwner(agentDevice.key)
    const agent = client(v1(makeKey(), agentDevice, { deviceName: 'Real name' }))
    await agent.sender.send('hub/net/bind', {
      version: HUB_NETWORK_WIRE_VERSION,
      bindingKind: 'apple-app',
      wireGuardKey: 'wg-directory',
      name: 'Agent Member',
      overlayAddresses: [],
      connectedAt: new Date().toISOString(),
    })
    const all = await until<any[]>(owners, 'network/agents/list', list => list.some(p => p.wireGuardKey === 'wg-directory'))
    expect(all.find(p => p.wireGuardKey === 'wg-directory').name).toBe('Real name')
    expect(await first(memberA.client, 'network/agents/list')).toEqual([])
  })
})
