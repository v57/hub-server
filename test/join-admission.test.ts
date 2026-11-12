import { beforeAll, describe, expect, test } from 'bun:test'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import fixture from './fixtures/join-admission.json'
import { validateJoinAdmission } from '../src/network/crypto'
import { NetworkAPI } from '../src/network/api'
import type { DirectBootstrapResponse } from '../src/network/wire'
import { Security } from '../src/security'
import { MAX_HELD_INVITATIONS } from '../src/network/registry'
import type { State } from '../src/hub'

// Signed by hub-service-go (protocol.SignEnvelope), so this also checks that
// the Go and Bun canonical JSON encodings agree.
const admission = fixture.admission as DirectBootstrapResponse
const issuedAt = Date.parse(admission.issuedAt)
const joinerKey = admission.joinerServiceKey
const joinerWireGuardKey = admission.joinerWireGuardKey

describe('validateJoinAdmission', () => {
  test('accepts the Go-signed admission for its joiner', () => {
    expect(validateJoinAdmission(admission, joinerKey, joinerWireGuardKey, issuedAt + 1000)).toBe(true)
  })
  test('rejects another joiner key', () => {
    expect(validateJoinAdmission(admission, admission.inviterServiceKey, joinerWireGuardKey, issuedAt)).toBe(false)
  })
  test('rejects another WireGuard key', () => {
    expect(validateJoinAdmission(admission, joinerKey, admission.inviterWireGuardKey, issuedAt)).toBe(false)
  })
  test('rejects a tampered field', () => {
    const tampered = { ...admission, hubProHost: '100.96.0.9' }
    expect(validateJoinAdmission(tampered, joinerKey, joinerWireGuardKey, issuedAt)).toBe(false)
  })
  test('rejects an expired admission', () => {
    expect(validateJoinAdmission(admission, joinerKey, joinerWireGuardKey, Date.parse(admission.expiresAt) + 1)).toBe(false)
  })
})

describe('hub/net/bind join', () => {
  beforeAll(() => {
    // NetworkRegistry persists to data/network.json relative to cwd.
    process.chdir(mkdtempSync(join(tmpdir(), 'hub-server-join-')))
  })

  const state = (key: string, id: string) => ({ key, id }) as unknown as State
  const request = (admission?: DirectBootstrapResponse) => ({
    version: 1 as const,
    bindingKind: 'join' as const,
    wireGuardKey: joinerWireGuardKey,
    overlayAddresses: [],
    connectedAt: new Date(issuedAt).toISOString(),
    admission,
  })
  const withInviter = (owner = true) => {
    const security = new Security()
    if (owner) security.members.add('owners', `key:${admission.inviterServiceKey}`)
    const api = new NetworkAPI(security)
    api.agents.registerProfile({
      version: 1,
      key: admission.inviterServiceKey,
      wireGuardKey: admission.inviterWireGuardKey,
      overlayAddresses: [],
      connectedAt: new Date(issuedAt).toISOString(),
    }, 'inviter-connection')
    return api
  }

  test('rejects a first bind without admission', async () => {
    const api = withInviter()
    await expect(api.bindAgent(request(), {} as never, state(joinerKey, 'joiner'))).rejects.toMatchObject({ code: 'forbidden' })
  })

  test('rejects an admission whose inviter is not bound', async () => {
    const api = new NetworkAPI(new Security())
    const pending = api.bindAgent(request(admission), {} as never, state(joinerKey, 'joiner'))
    await expect(pending).rejects.toMatchObject({ code: 'forbidden' })
  })

  test('rejects an admission presented by another key', async () => {
    const api = withInviter()
    const pending = api.bindAgent(request(admission), {} as never, state(admission.inviterServiceKey, 'other'))
    await expect(pending).rejects.toMatchObject({ code: 'forbidden' })
  })

  test('admits the invited joiner, then lets it re-bind without admission', async () => {
    const api = withInviter()
    const realNow = Date.now
    Date.now = () => issuedAt + 1000
    try {
      const first = await api.bindAgent(request(admission), {} as never, state(joinerKey, 'joiner'))
      expect(first.profile.key).toBe(joinerKey)
      expect(first.profile.overlayAddresses).toHaveLength(2)
      expect(first.profile).not.toHaveProperty('admission')
    } finally {
      Date.now = realNow
    }
    const again = await api.bindAgent(request(), {} as never, state(joinerKey, 'joiner-reconnected'))
    expect(again.profile.overlayAddresses).toEqual((await api.bindAgent(request(), {} as never, state(joinerKey, 'x'))).profile.overlayAddresses)
  })

  test('lets a member rejoin with a new WireGuard key only with a fresh admission', async () => {
    const api = withInviter()
    // Bound earlier with other tunnel keys, still connected
    api.agents.registerProfile({
      version: 1,
      key: joinerKey,
      wireGuardKey: admission.inviterWireGuardKey,
      overlayAddresses: [],
      connectedAt: new Date(issuedAt).toISOString(),
    }, 'joiner-earlier')
    await expect(api.bindAgent(request(), {} as never, state(joinerKey, 'joiner'))).rejects.toMatchObject({ code: 'forbidden' })
    const realNow = Date.now
    Date.now = () => issuedAt + 1000
    try {
      const rejoined = await api.bindAgent(request(admission), {} as never, state(joinerKey, 'joiner'))
      expect(rejoined.profile.wireGuardKey).toBe(joinerWireGuardKey)
    } finally {
      Date.now = realNow
    }
  })

  test('keeps a disconnected member in the member list', async () => {
    const api = withInviter()
    const realNow = Date.now
    Date.now = () => issuedAt + 1000
    try {
      await api.bindAgent(request(admission), {} as never, state(joinerKey, 'joiner'))
    } finally {
      Date.now = realNow
    }
    api.agents.unregisterProfile(joinerKey)
    const member = api.listMembers().find(profile => profile.key === joinerKey)
    expect(member).toMatchObject({ online: false, wireGuardKey: joinerWireGuardKey })
    expect(member?.overlayAddresses).toHaveLength(2)
  })

  // Security audit M3: any member's admission approved the joining device
  describe('invited by a member who is not an owner', () => {
    const device = (approved: boolean) =>
      ({ key: joinerKey, id: 'joiner', certificate: { deviceId: 'joiner-device' }, ...(approved ? { device: 'joiner-device' } : {}) }) as unknown as State
    const bind = async (api: NetworkAPI, joiner: State) => {
      const realNow = Date.now
      Date.now = () => issuedAt + 1000
      try {
        return await api.bindAgent(request(admission), {} as never, joiner)
      } finally {
        Date.now = realNow
      }
    }

    test('leaves the device pending for an owner', async () => {
      const api = withInviter(false)
      let approved = 0
      api.onBindApprove = () => (approved += 1)
      await expect(bind(api, device(false))).rejects.toMatchObject({ code: 'approval_required' })
      expect(approved).toBe(0)
      expect(api.listMembers().some(member => member.key === joinerKey)).toBe(false)
    })

    test('admits the device once an owner approved it', async () => {
      const api = withInviter(false)
      const joined = await bind(api, device(true))
      expect(joined.profile.device).toBe('joiner-device')
    })

    test('refuses a key without a device to approve', async () => {
      const api = withInviter(false)
      await expect(bind(api, state(joinerKey, 'joiner'))).rejects.toMatchObject({ code: 'forbidden' })
    })
  })

  // Hub app H-034: a member's Add a Device asks the hub machine's agent, an owner's, to make the invitation. The agent
  // holds it for the member, so the joiner waits for an owner all the same; the owner's own invitations don't.
  describe('invited by the hub machine\'s agent for a member', () => {
    const device = (approved: boolean) =>
      ({ key: joinerKey, id: 'joiner', certificate: { deviceId: 'joiner-device' }, ...(approved ? { device: 'joiner-device' } : {}) }) as unknown as State
    const machine = state(admission.inviterServiceKey, 'inviter-connection')
    const week = () => new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString()
    const bind = async (api: NetworkAPI, joiner: State) => {
      const realNow = Date.now
      Date.now = () => issuedAt + 1000
      try {
        return await api.bindAgent(request(admission), {} as never, joiner)
      } finally {
        Date.now = realNow
      }
    }
    const held = () => {
      const api = withInviter(true)
      api.holdInvitation({ replayId: admission.replayId, expiresAt: week(), by: { key: 'member', device: 'member-device', name: 'iPhone' } }, machine)
      return api
    }

    test('leaves the device pending for an owner', async () => {
      const api = held()
      let approved = 0
      api.onBindApprove = () => (approved += 1)
      await expect(bind(api, device(false))).rejects.toMatchObject({ code: 'approval_required' })
      await expect(bind(api, state(joinerKey, 'joiner'))).rejects.toMatchObject({ code: 'forbidden' })
      expect(approved).toBe(0)
      expect(api.registry.heldInvitation(admission.replayId)).toEqual({ key: 'member', device: 'member-device', name: 'iPhone' })
    })

    test('tells a denied device so', async () => {
      const api = held()
      api.isDenied = id => id === 'joiner-device'
      await expect(bind(api, device(false))).rejects.toMatchObject({ code: 'denied' })
    })

    test('admits the device once an owner approved it', async () => {
      const joined = await bind(held(), device(true))
      expect(joined.profile.device).toBe('joiner-device')
    })

    test("admits the owner's own invitation at once", async () => {
      const api = withInviter(true)
      let approved = 0
      api.onBindApprove = () => (approved += 1)
      await bind(api, device(false))
      expect(approved).toBe(1)
    })

    test('holds only for an owner or a bound agent, and only a valid invitation', () => {
      const api = withInviter(false)
      const hold = (body: unknown, by: State) => {
        try {
          api.holdInvitation(body, by)
          return 'ok'
        } catch (error) {
          return (error as { code: string }).code
        }
      }
      const replayId = admission.replayId
      expect(hold({ replayId, expiresAt: week() }, state('stranger', 'stranger'))).toBe('forbidden')
      expect(hold({ replayId: 'short', expiresAt: week() }, machine)).toBe('invalid_request')
      expect(hold({ replayId, expiresAt: new Date(Date.now() - 60_000).toISOString() }, machine)).toBe('invalid_request')
      expect(hold({ replayId, expiresAt: new Date(Date.now() + 9 * 24 * 3600 * 1000).toISOString() }, machine)).toBe('invalid_request')
      expect(hold({ replayId, expiresAt: week() }, machine)).toBe('ok')
      expect(api.registry.heldInvitation(replayId, new Date(Date.now() + 8 * 24 * 3600 * 1000))).toBeUndefined()
    })

    test('a full list refuses the next and drops only expired ones', () => {
      const api = withInviter(true)
      const now = new Date()
      for (let index = 0; index < MAX_HELD_INVITATIONS; index++) {
        api.registry.holdInvitation(`held-${index}`, {}, new Date(now.getTime() + (index === 0 ? 60_000 : 3_600_000)), now)
      }
      expect(() => api.registry.holdInvitation('one-more', {}, new Date(now.getTime() + 3_600_000), now)).toThrow()
      expect(api.registry.heldInvitation('held-0', now)).toBeDefined()
      const later = new Date(now.getTime() + 120_000)
      api.registry.holdInvitation('one-more', {}, new Date(later.getTime() + 3_600_000), later)
      expect(api.registry.heldInvitation('held-0', later)).toBeUndefined()
      expect(api.registry.heldInvitation('held-1', later)).toBeDefined()
    })
  })
})
