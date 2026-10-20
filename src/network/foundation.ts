import { createHash } from 'node:crypto'
import type { ResourceId } from './wire'

export const NETWORK_PROTOCOL_VERSION = 1 as const
export const NETWORK_DNS_SUFFIX = 'hub.invalid' as const

export const OVERLAY_RANGES = {
  ipv4: {
    cidr: '100.96.0.0/11',
    first: '100.96.0.1',
    last: '100.127.254.254',
    reserved: '100.127.255.0/24',
  },
  ipv6: {
    cidr: 'fd48:5542:4e45::/48',
    first: 'fd48:5542:4e45::1',
    last: 'fd48:5542:4e45:ffff:ffff:ffff:ffff:fffe',
    reserved: 'fd48:5542:4e45:ffff::/64',
  },
} as const

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'

function base32(bytes: Uint8Array): string {
  let value = 0
  let bits = 0
  let result = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      result += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits) result += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  return result
}

function digest(domain: string, ...fields: string[]): Uint8Array {
  const hash = createHash('sha256')
  hash.update(domain)
  hash.update('\0')
  for (const field of fields) {
    const encoded = Buffer.from(field, 'utf8')
    const length = Buffer.allocUnsafe(4)
    length.writeUInt32BE(encoded.length)
    hash.update(length)
    hash.update(encoded)
  }
  return hash.digest()
}

function normalizeKey(key: string): string {
  return Buffer.from(key, 'base64').toString('base64')
}

export function normalizeShareName(name: string): string {
  const normalized = name.normalize('NFKC').trim()
  if (!normalized || Buffer.byteLength(normalized, 'utf8') > 128) throw new Error('invalid network share name')
  return normalized
}

export function stableResourceId(ownerKey: string, shareName: string): ResourceId {
  return `hnr1_${base32(digest('hub-network/resource/v1', normalizeKey(ownerKey), normalizeShareName(shareName))).slice(0, 32)}`
}

function displayLabel(name: string): string {
  const label = name
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return (label || 'share').slice(0, 24).replace(/-+$/g, '') || 'share'
}

export function canonicalAuthority(hubNetworkId: string, ownerKey: string, shareName: string): string {
  const resource = stableResourceId(ownerKey, shareName).slice(5, 21)
  const hub = base32(digest('hub-network/authority-hub/v1', hubNetworkId)).slice(0, 16)
  return `${displayLabel(shareName)}-${resource}.v1-${hub}.${NETWORK_DNS_SUFFIX}`
}

/** DNS name of a device member: its label, 16 characters of the device id digest and the hub part of authorities */
export function deviceAuthority(hubNetworkId: string, deviceId: string, deviceName: string): string {
  const device = base32(digest('hub-network/device/v1', deviceId)).slice(0, 16)
  const hub = base32(digest('hub-network/authority-hub/v1', hubNetworkId)).slice(0, 16)
  return `${displayLabel(deviceName)}-${device}.v1-${hub}.${NETWORK_DNS_SUFFIX}`
}
