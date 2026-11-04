import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Security } from '../src/security'
import { GrantStore } from '../src/grants'
import { NetworkAPI } from '../src/network/api'
import { HUB_NETWORK_WIRE_VERSION, type NetworkResource } from '../src/network/wire'
import { Hub, security } from '../src/hub'
import { deviceId } from '../src/devices'
import type { State } from '../src/hub'
import { certificate, connect, freePort, makeKey, token, until, type Client, type TestKey } from './helpers'

async function inDirectory<T>(files: Record<string, string>, action: () => Promise<T>): Promise<T> {
  const directory = mkdtempSync(join(tmpdir(), 'hub-server-grants-'))
  mkdirSync(join(directory, 'data'))
  for (const [name, text] of Object.entries(files)) writeFileSync(join(directory, 'data', name), text)
  const cwd = process.cwd()
  process.chdir(directory)
  try {
    return await action()
  } finally {
    process.chdir(cwd)
  }
}

describe('migration to grants', () => {
  const legacy = {
    'clients.json': JSON.stringify({ allowed: { alice: ['s3/read', 's3/list'] } }),
    'groups.json': JSON.stringify({ family: ['photos/view'], empty: [] }),
    'group_users.json': JSON.stringify({ family: ['bob'] }),
  }
  test('call lists, group path lists and group users become grants and members', async () => {
    await inDirectory(legacy, async () => {
      const s = await new Security().load()
      expect(s.call.allows('alice', 's3/read')).toBe(true)
      expect(s.grants.grants.filter(g => 'key' in g.subject)).toHaveLength(2)
      expect(s.group.allowed('family')).toEqual(new Set(['photos/view']))
      expect(s.groups({ key: 'bob' })).toEqual(['family'])
      expect(s.allowsCall('bob', 'photos/view')).toBe(true)
      expect(s.grants.migrated).toEqual(['clients', 'groups', 'group_users'])
      expect(s.group.list().map(g => g.id)).toEqual(['owners', 'family', 'empty'])
      await Promise.all([s.grants.storage.write(), s.group.storage.write(), s.members.storage.write()])
      // A second start reads the new files and migrates nothing again
      const again = await new Security().load()
      expect(again.grants.grants).toHaveLength(3)
      expect(again.group.list().map(g => g.id)).toEqual(['owners', 'family', 'empty'])
      expect((await Bun.file('data/groups.json').json()).schema).toBe(1)
    })
  })
  test('a corrupt grants.json locks down and migrates nothing', async () => {
    await inDirectory({ ...legacy, 'grants.json': '{' }, async () => {
      const s = await new Security().load()
      expect(s.lockdown).toBe(true)
      expect(s.grants.grants).toEqual([])
      expect(s.allowsCall('alice', 's3/read')).toBe(false)
    })
  })
})

describe('grant matching', () => {
  const store = new GrantStore()
  store.add({ key: 'k' }, { path: 'a/b' }, 'o')
  store.add({ device: 'd' }, { prefix: 'build/' }, 'o')
  store.add({ group: 'g' }, { path: 'c' }, 'o')
  store.add({ everyone: true }, { share: 'hnr1_x' }, 'o')
  test.each([
    [{ key: 'k', groups: [] }, 'a/b', true],
    [{ key: 'other', groups: [] }, 'a/b', false],
    [{ device: { id: 'd' }, groups: [] }, 'build/run', true],
    [{ device: { id: 'd' }, groups: [] }, 'buildx', false],
    [{ groups: ['g'] }, 'c', true],
    [{ groups: ['h'] }, 'c', false],
  ])('%j calling %s: %s', (caller, path, allowed) => {
    expect(store.allowsPath(caller, path)).toBe(allowed)
  })
  test('shares match only share grants', () => {
    expect(store.allowsShare({ groups: [] }, 'hnr1_x')).toBe(true)
    expect(store.allowsShare({ groups: [] }, 'hnr1_y')).toBe(false)
    expect(store.allowsPath({ groups: [] }, 'hnr1_x')).toBe(false)
  })
  test('adding the same grant twice keeps one', () => {
    const first = store.add({ key: 'k' }, { path: 'a/b' }, 'o')
    expect(store.grants.filter(g => g.id === first.id)).toHaveLength(1)
    expect(store.grants).toHaveLength(4)
  })
})

describe('share policies as grants', () => {
  const owner = makeKey()
  const member = makeKey()
  const stranger = makeKey()
  const state = (key: TestKey): State => ({ id: crypto.randomUUID(), key: key.key, services: new Set(), apps: new Set() })
  test('a group policy is a group grant and membership decides', async () => {
    await inDirectory({}, async () => {
      const s = await new Security().load()
      s.addOwner(owner.key)
      const api = new NetworkAPI(s)
      await api.registry.load()
      const resource: NetworkResource = {
        version: HUB_NETWORK_WIRE_VERSION,
        resourceId: 'hnr1_test',
        ownerKey: owner.key,
        shareName: 'files',
        authority: 'files.hub.invalid',
        policy: { mode: 'private' },
        generation: 0,
      }
      api.registry.registerResource(resource)
      for (const key of [member, stranger]) {
        api.agents.registerProfile({ version: 1, key: key.key, wireGuardKey: key.key, overlayAddresses: [], connectedAt: '' })
      }
      expect(api.listResources(state(member))).toEqual([])
      s.group.create({ name: 'family', person: false })
      s.group.users.add(member.key, 'family')
      api.updateResourcePolicy('hnr1_test', { mode: 'group', group: 'family' }, state(owner))
      expect(s.grants.forShare('hnr1_test').map(g => g.subject)).toEqual([{ group: 'family' }])
      expect(api.listResources(state(member)).map(r => r.resourceId)).toEqual(['hnr1_test'])
      expect(api.listResources(state(stranger))).toEqual([])
      // A direct share grant opens it to one more key and starts a new generation
      const before = api.registry.getResource('hnr1_test')!.generation
      s.grants.onChange = changed => api.handleGrantsChanged(changed)
      s.addGrant({ subject: { key: stranger.key }, object: { share: 'hnr1_test' } }, owner.key)
      expect(api.listResources(state(stranger))).toHaveLength(1)
      expect(api.registry.getResource('hnr1_test')!.generation).toBe(before + 1)
      api.updateResourcePolicy('hnr1_test', { mode: 'disabled' }, state(owner))
      expect(api.listResources(state(member))).toEqual([])
    })
  })
})

describe('grants on the hub', () => {
  const port = freePort()
  const owner = makeKey()
  let hub: Hub
  let owners: Client
  const clients: Client[] = []
  const client = (key: TestKey, device?: TestKey) => {
    const c = connect(port, () => ({
      auth: token(key, security.hubKey, security.nonces),
      v: '1',
      ...(device ? { device: certificate(device, key) } : {}),
    }))
    clients.push(c)
    return c
  }
  beforeAll(async () => {
    security.addOwner(owner.key)
    security.setMode({ mode: 'default-deny' })
    hub = new Hub(port)
    hub.devices.gate.interval = 0
    await hub.ready
    owners = client(owner)
    const provider = makeKey()
    security.host.allow(provider.key, ['grant/a', 'grant/b', 'tools/x'])
    const service = client(provider)
    service.channel.post('grant/a', () => 'a').post('grant/b', () => 'b').post('tools/x', ({ context }) => context.hub.caller.groups)
    await service.sender.send('hub/service/update', { services: [{ path: 'grant/a' }, { path: 'grant/b' }, { path: 'tools/x' }] })
  })
  afterAll(() => clients.forEach(c => c.sender.stop()))

  test('a key grant opens a path, removing it closes it', async () => {
    const user = makeKey()
    const c = client(user)
    await expect(c.sender.send('grant/a')).rejects.toThrow('permissions required')
    const grant = await owners.sender.send('hub/grant/add', { subject: { key: user.key }, object: { path: 'grant/a' } })
    expect(grant).toMatchObject({ subject: { key: user.key }, object: { path: 'grant/a' }, by: owner.key })
    expect(await c.sender.send('grant/a')).toBe('a')
    await expect(c.sender.send('grant/b')).rejects.toThrow('permissions required')
    expect((await until<any[]>(owners, 'hub/grants', list => list.some(g => g.id === grant.id))).length).toBeGreaterThan(0)
    await owners.sender.send('hub/grant/remove', { id: grant.id })
    await expect(c.sender.send('grant/a')).rejects.toThrow('permissions required')
    await expect(owners.sender.send('hub/grant/remove', { id: grant.id })).rejects.toThrow('grant not found')
  })
  test('a prefix grant to everyone opens every path under it', async () => {
    const grant = await owners.sender.send('hub/grant/add', { subject: { everyone: true }, object: { prefix: 'grant/' } })
    try {
      expect(await client(makeKey()).sender.send('grant/b')).toBe('b')
    } finally {
      await owners.sender.send('hub/grant/remove', { id: grant.id })
    }
  })
  test('a device grant applies to every service on the device until it is removed', async () => {
    const device = makeKey()
    const user = makeKey()
    const id = deviceId(device.key)
    const c = client(user, device)
    await c.sender.send('hub/info')
    await owners.sender.send('hub/device/approve', { id })
    await owners.sender.send('hub/grant/add', { subject: { device: id }, object: { path: 'grant/b' } })
    expect(await client(makeKey(), device).sender.send('grant/b')).toBe('b')
    await owners.sender.send('hub/device/remove', { id })
    expect(security.grants.grants.some(g => 'device' in g.subject && g.subject.device === id)).toBe(false)
  })
  test('a key can be in several groups, and person groups are listed as people', async () => {
    const user = makeKey()
    await owners.sender.send('hub/group/create', { name: 'Anna', person: true })
    await owners.sender.send('hub/group/create', 'builders')
    await owners.sender.send('hub/group/update/users', { group: 'Anna', add: [user.key] })
    await owners.sender.send('hub/group/update/users', { group: 'builders', add: [user.key] })
    await owners.sender.send('hub/group/update', { group: 'builders', add: ['tools/x'], remove: [] })
    expect(await client(user).sender.send('tools/x')).toEqual(['Anna', 'builders'])
    const groups = await until<any[]>(owners, 'hub/groups', list => list.some(g => g.id === 'Anna'))
    expect(groups.find(g => g.id === 'Anna')).toEqual({ id: 'Anna', person: true, members: [`key:${user.key}`], paths: [] })
    expect(groups.find(g => g.id === 'builders')).toMatchObject({ person: false, paths: ['tools/x'] })
    expect(groups[0].id).toBe('owners')
    const list = await until<any>(owners, 'hub/group/list', value => !!value.builders)
    expect(list.builders).toEqual(['tools/x'])
  })
  test('renaming and removing a group moves and drops its grants and members', async () => {
    const user = makeKey()
    await owners.sender.send('hub/group/create', 'old')
    await owners.sender.send('hub/group/update/users', { group: 'old', add: [user.key] })
    await owners.sender.send('hub/group/update', { group: 'old', add: ['grant/a'], remove: [] })
    await owners.sender.send('hub/group/rename', { group: 'old', name: 'new' })
    expect(security.groups({ key: user.key })).toEqual(['new'])
    expect(await client(user).sender.send('grant/a')).toBe('a')
    await owners.sender.send('hub/group/remove', 'new')
    await expect(client(user).sender.send('grant/a')).rejects.toThrow('permissions required')
    expect(security.groups({ key: user.key })).toEqual([])
    await expect(owners.sender.send('hub/group/remove', 'owners')).rejects.toThrow('owners can not be removed')
  })
  test('grant APIs are owner-only and validate their input', async () => {
    const user = client(makeKey())
    await expect(user.sender.send('hub/grant/add', { subject: { everyone: true }, object: { path: 'x' } })).rejects.toThrow(
      'permissions required',
    )
    await expect(owners.sender.send('hub/grant/add', { subject: { nobody: 1 }, object: { path: 'x' } })).rejects.toThrow(
      'invalid subject',
    )
    await expect(owners.sender.send('hub/grant/add', { subject: { everyone: true }, object: {} })).rejects.toThrow(
      'invalid object',
    )
  })
})
