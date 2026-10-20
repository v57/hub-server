import { describe, expect, test } from 'bun:test'
import { generateKeyPairSync, sign } from 'node:crypto'
import { authClockSkew, authMaxLifetime, Security } from '../src/security'

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const key = publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
const security = new Security()

// Same shape as hub-service sign(): key.<pub>.<sig>.<decimal expiry>
function token(expiresIn: number, time = `${Math.round(Date.now() / 1000) + expiresIn}`): string {
  const signature = sign(null, Buffer.from(time), privateKey).toString('base64')
  return `key.${key}.${signature}.${time}`
}
const verify = (signedKey: string) => security.keys.verify(signedKey, security.whitelist)

describe('auth token expiry', () => {
  test('accepts the default 10 second token', () => {
    expect(verify(token(10))).toBe(key)
  })
  test('accepts the 60 second Swift token', () => {
    expect(verify(token(60))).toBe(key)
  })
  test('accepts a token expired within the clock skew', () => {
    expect(verify(token(-authClockSkew + 5))).toBe(key)
  })
  test('rejects an expired token', () => {
    expect(() => verify(token(-authClockSkew - 5))).toThrow('authorization expired')
  })
  test('rejects a token signed an hour ago', () => {
    expect(() => verify(token(-3600))).toThrow('authorization expired')
  })
  test('rejects a token that expires too late', () => {
    expect(() => verify(token(authMaxLifetime + authClockSkew + 5))).toThrow('authorization expires too late')
  })
  test('rejects a non-decimal expiry', () => {
    const time = (Math.round(Date.now() / 1000) + 10).toString(36)
    expect(() => verify(token(0, time))).toThrow('invalid key')
  })
  test('rejects an expiry changed after signing', () => {
    const [prefix, pub, signature] = token(10).split('.')
    const time = `${Math.round(Date.now() / 1000) + 20}`
    expect(() => verify(`${prefix}.${pub}.${signature}.${time}`)).toThrow('invalid signature')
  })
})
