import crypto from 'crypto'

let loadedKey: Promise<string> | undefined

export async function sign(expires: number = 10) {
  const data = `${Math.round(new Date().getTime() / 1000) + expires}`
  const [key, signature] = await Promise.all([loadKey(), signChallenge(data)])
  return `key.${getPublicKey(key)}.${signature}.${data}`
}
export async function signChallenge(data: string | Uint8Array): Promise<string> {
  return makeSignature(await loadKey(), data)
}
export async function publicKey(): Promise<string> {
  const key = await loadKey()
  return getPublicKey(key)
}
async function loadKey(): Promise<string> {
  loadedKey ??= loadStoredKey()
  return loadedKey
}
async function loadStoredKey(): Promise<string> {
  try {
    return await Bun.file('data/auth').text()
  } catch {
    const key = await generateKey()
    await Bun.file('data/auth').write(key)
    return key
  }
}
async function generateKey(): Promise<string> {
  const keys = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { format: 'der', type: 'pkcs8' },
    publicKeyEncoding: { format: 'der', type: 'spki' },
  })
  return Buffer.concat([keys.privateKey, keys.publicKey]).toString('base64')
}
function getPublicKey(key: string): string {
  return Buffer.from(key, 'base64')
    .subarray(48, 48 + 44)
    .toString('base64')
}
function makeSignature(key: string, data: string | Uint8Array): string {
  const keyBuffer = Buffer.from(key, 'base64')
  const privateKey = crypto.createPrivateKey({
    key: keyBuffer.subarray(0, 48), // Extract private key
    format: 'der',
    type: 'pkcs8',
  })
  const challenge = typeof data === 'string'
    ? Buffer.from(data)
    : Buffer.from(data.buffer, data.byteOffset, data.byteLength)
  const signature = crypto.sign(null, challenge, privateKey)
  return signature.toString('base64')
}
