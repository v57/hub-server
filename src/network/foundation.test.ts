import { describe, expect, test } from 'bun:test'
import {
  NETWORK_DNS_SUFFIX,
  OVERLAY_RANGES,
  canonicalAuthority,
  normalizeShareName,
  stableResourceId,
} from './foundation'

const ownerA = Buffer.from(Array.from({ length: 32 }, (_, index) => index)).toString('base64')
const ownerB = Buffer.from(Array.from({ length: 32 }, (_, index) => 255 - index)).toString('base64')
const hubA = '018f0f67-89ab-7def-8123-456789abcdef'

describe('Hub Network protocol foundations', () => {
  test('matches the cross-language identity vectors', () => {
    expect(stableResourceId(ownerA, 's3')).toBe('hnr1_vu5lgvuep3ijwvktdc3c7jtlkbq7tpio')
    expect(canonicalAuthority(hubA, ownerA, 's3')).toBe(
      's3-vu5lgvuep3ijwvkt.v1-rtmx5wwkl7ux5ivb.hub.invalid',
    )
    expect(canonicalAuthority(hubA, ownerA, 'Café Storage')).toBe(
      'cafe-storage-wueyutzkbjcidw6f.v1-rtmx5wwkl7ux5ivb.hub.invalid',
    )
  })

  test('does not collide for equal display names owned by different keys', () => {
    expect(stableResourceId(ownerA, 's3')).not.toBe(stableResourceId(ownerB, 's3'))
    expect(canonicalAuthority(hubA, ownerA, 's3')).not.toBe(canonicalAuthority(hubA, ownerB, 's3'))
  })

  test('uses unambiguous framing and canonical base64 keys', () => {
    expect(stableResourceId(ownerA.replace(/=+$/, ''), 's3')).toBe(stableResourceId(ownerA, 's3'))
    expect(stableResourceId(ownerA, 'ab\u0000c')).not.toBe(stableResourceId(ownerA, 'ab'))
  })

  test('normalizes names before deriving identity', () => {
    expect(normalizeShareName('  Cafe\u0301  ')).toBe('Café')
    expect(stableResourceId(ownerA, 'Cafe\u0301')).toBe(stableResourceId(ownerA, 'Café'))
  })

  test('keeps the namespace and routing scope explicit', () => {
    expect(NETWORK_DNS_SUFFIX.endsWith('.invalid')).toBeTrue()
    expect(OVERLAY_RANGES.ipv4.cidr).toBe('100.96.0.0/11')
    expect(OVERLAY_RANGES.ipv6.cidr).toBe('fd48:5542:4e45::/48')
  })
})
