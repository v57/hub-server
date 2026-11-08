import { beforeAll, describe, expect, test } from 'bun:test'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import fixture from './fixtures/join-admission.json'
import { validateJoinAdmission } from '../src/network/crypto'
import { NetworkAPI } from '../src/network/api'
import type { DirectBootstrapResponse } from '../src/network/wire'
import { Security } from '../src/security'
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
})
