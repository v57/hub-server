import { describe, expect, test } from 'bun:test'
import {
  HUB_NETWORK_WIRE_VERSION,
  type HubNetworkMessage,
  type NetworkPolicy,
  networkError,
} from './wire'

describe('Hub Network wire models', () => {
  test('serialize a share replacement without implementation-specific values', () => {
    const message: HubNetworkMessage = {
      version: HUB_NETWORK_WIRE_VERSION,
      type: 'shares.replace',
      requestId: 'req-1',
      payload: {
        shares: [
          {
            version: 1,
            name: 's3',
            protocol: 'tcp',
            target: { host: '127.0.0.1', port: 9001 },
            policy: { mode: 'group', group: 'editors' },
            attestation: {
              version: 1,
              attestationId: 'att-1',
              serviceKey: 'service-key',
              key: 'agent-key',
              shareName: 's3',
              protocol: 'tcp',
              target: { host: '127.0.0.1', port: 9001 },
              issuedAt: '2026-07-25T00:00:00.000Z',
              expiresAt: '2026-07-25T00:05:00.000Z',
              signature: 'c2lnbmF0dXJl',
            },
          },
        ],
      },
    }

    expect(JSON.parse(JSON.stringify(message))).toEqual(message)
  })

  test('keeps every policy mode explicitly tagged', () => {
    const policies: NetworkPolicy[] = [
      { mode: 'hub' },
      { mode: 'group', group: 'editors' },
      { mode: 'keys', keys: ['profile-key'] },
      { mode: 'private' },
      { mode: 'disabled' },
    ]
    expect(policies.map(policy => policy.mode)).toEqual(['hub', 'group', 'keys', 'private', 'disabled'])
  })

  test('creates a versioned structured error', () => {
    expect(networkError('agent_unavailable', 'local agent is not running', true)).toEqual({
      version: 1,
      code: 'agent_unavailable',
      message: 'local agent is not running',
      retryable: true,
    })
  })
})

