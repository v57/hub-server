import { describe, expect, test } from 'bun:test'
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto'
import vectors from './testdata/crypto-v1.json'
import { SIGNATURE_DOMAINS, signEnvelope, signatureInput, verifyEnvelope, type SignaturePurpose } from './crypto'

const privateKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(vectors.seed, 'hex'),
  ]),
  format: 'der',
  type: 'pkcs8',
})
const publicKey = createPublicKey(privateKey)

describe('Hub Network cryptographic vectors', () => {
  for (const vector of vectors.vectors) {
    test(`matches ${vector.purpose}`, () => {
      const purpose = vector.purpose as SignaturePurpose
      expect(createHash('sha256').update(signatureInput(purpose, vector.envelope)).digest('hex')).toBe(
        vector.inputSha256,
      )
      expect(signEnvelope(purpose, vector.envelope, privateKey)).toBe(vector.signature)
      expect(verifyEnvelope(purpose, { ...vector.envelope, signature: vector.signature }, publicKey)).toBeTrue()
    })
  }

  test('uses a different signature domain for every purpose', () => {
    const purposes = Object.keys(SIGNATURE_DOMAINS).length
    expect(new Set(Object.values(SIGNATURE_DOMAINS)).size).toBe(purposes)
    const envelope = vectors.vectors[0].envelope
    const signatures = Object.keys(SIGNATURE_DOMAINS).map(purpose =>
      signEnvelope(purpose as SignaturePurpose, envelope, privateKey),
    )
    expect(new Set(signatures).size).toBe(purposes)
  })

  test('rejects mutation and cross-purpose replay', () => {
    const vector = vectors.vectors[2]
    const signed = { ...vector.envelope, signature: vector.signature }
    expect(verifyEnvelope('connection-grant', { ...signed, generation: 5 }, publicKey)).toBeFalse()
    expect(verifyEnvelope('rendezvous-ticket', signed, publicKey)).toBeFalse()
  })
})
