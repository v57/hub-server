import { createPublicKey, randomBytes, verify } from 'node:crypto'
import { request } from 'node:http'
import { mkdir, rename } from 'node:fs/promises'
import { dirname } from 'node:path'
import type {
  AppleAppAgentReadinessAssertion,
  AppleAppAgentUnbindRequest,
} from './wire'

export const LOCAL_AGENT_BINDING_PROOF_DOMAIN = 'hub-network/local-agent-binding/v1'
export const LOCAL_AGENT_BOOTSTRAP_CAPABILITY = 'invitation-bootstrap-v1'
export const DEFAULT_LOCAL_AGENT_SOCKET = process.platform === 'darwin'
  ? '/var/run/hub-net/agent.sock'
  : '/run/hub-net/agent.sock'

export interface LocalAgentProof {
  version: 1
  key: string
  connectionId: string
  nonce: string
  capabilities: string[]
  issuedAt: string
  expiresAt: string
  signature: string
}

interface LocalAgentBindingBase {
  version: 1
  bindingKind: 'machine' | 'apple-app'
  key: string
  capabilities: string[]
}

export interface MachineLocalAgentBinding extends LocalAgentBindingBase {
  bindingKind: 'machine'
  boundAt: string
}

export interface AppleLocalAgentBinding extends LocalAgentBindingBase {
  bindingKind: 'apple-app'
  connectionId: string
  wireGuardKey: string
  hubNetworkId: string
  tunnelInstanceId: string
  generation: number
  expiresAt: string
}

export type LocalAgentBinding =
  | MachineLocalAgentBinding
  | AppleLocalAgentBinding

export interface LocalAgentBindingPin {
  bindingKind: LocalAgentBinding['bindingKind']
  key: string
  tunnelInstanceId?: string
  generation?: number
}

export interface LocalAgentStatus {
  version: 1
  state: 'unbound' | 'available' | 'unavailable'
  bindingKind?: LocalAgentBinding['bindingKind']
  key?: string
  tunnelInstanceId?: string
  generation?: number
  expiresAt?: string
  capabilities: string[]
  connected: boolean
  bootstrapCapable: boolean
  updatedAt: string
  error?: {
    version: 1
    code: 'local_agent_unavailable'
    message: string
    retryable: true
  }
}

interface PendingRebind {
  key: string
}

interface StoredBinding {
  /** Existing on-disk machine binding. Field name remains stable for migration. */
  binding?: Omit<MachineLocalAgentBinding, 'bindingKind'> & {
    bindingKind?: 'machine'
  }
  pendingRebind?: PendingRebind
}

export interface LocalAgentProofVerifier {
  prove(key: string, connectionId: string): Promise<LocalAgentProof>
}

export function localAgentProofInput(proof: Omit<LocalAgentProof, 'signature'>): Buffer {
  return Buffer.from([
    LOCAL_AGENT_BINDING_PROOF_DOMAIN,
    String(proof.version),
    proof.key,
    proof.connectionId,
    proof.nonce,
    [...proof.capabilities].sort().join(','),
    proof.issuedAt,
    proof.expiresAt,
  ].join('\n'))
}

export class UnixLocalAgentProofVerifier implements LocalAgentProofVerifier {
  constructor(
    readonly socketPath = process.env.HUB_NET_AGENT_SOCKET ?? DEFAULT_LOCAL_AGENT_SOCKET,
    readonly timeoutMs = 3_000,
  ) {}

  async prove(key: string, connectionId: string): Promise<LocalAgentProof> {
    const nonce = randomBytes(32).toString('base64url')
    const proof = await this.post('/binding/proof', {
      version: 1,
      type: 'binding-proof',
      key,
      connectionId,
      nonce,
    }) as LocalAgentProof
    validateLocalAgentProof(proof, { key, connectionId, nonce })
    return proof
  }

  private post(path: string, body: unknown): Promise<unknown> {
    const payload = JSON.stringify(body)
    return new Promise((resolve, reject) => {
      const req = request({
        socketPath: this.socketPath,
        path,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
        },
        timeout: this.timeoutMs,
      }, response => {
        const chunks: Buffer[] = []
        response.on('data', chunk => chunks.push(Buffer.from(chunk)))
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString()
          if ((response.statusCode ?? 500) < 200 || (response.statusCode ?? 500) >= 300) {
            reject(new Error(`local agent proof failed: ${response.statusCode} ${text}`))
            return
          }
          try {
            resolve(JSON.parse(text))
          } catch {
            reject(new Error('local agent proof returned invalid JSON'))
          }
        })
      })
      req.on('timeout', () => req.destroy(new Error('local agent proof timed out')))
      req.on('error', reject)
      req.end(payload)
    })
  }
}

export function validateLocalAgentProof(
  proof: LocalAgentProof,
  expected: { key: string; connectionId: string; nonce: string },
  now = Date.now(),
): void {
  if (
    proof?.version !== 1
    || proof.key !== expected.key
    || proof.connectionId !== expected.connectionId
    || proof.nonce !== expected.nonce
    || !proof.key
    || !Array.isArray(proof.capabilities)
    || !proof.capabilities.includes(LOCAL_AGENT_BOOTSTRAP_CAPABILITY)
  ) throw new Error('invalid local agent binding proof')
  const issuedAt = Date.parse(proof.issuedAt)
  const expiresAt = Date.parse(proof.expiresAt)
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || issuedAt > now + 30_000 || expiresAt <= now || expiresAt - issuedAt > 60_000) {
    throw new Error('expired local agent binding proof')
  }
  const { signature: _, ...unsigned } = proof
  const key = createPublicKey({
    key: Buffer.from(proof.key, 'base64'),
    format: 'der',
    type: 'spki',
  })
  if (!verify(null, localAgentProofInput(unsigned), key, Buffer.from(proof.signature, 'base64'))) {
    throw new Error('invalid local agent binding proof signature')
  }
}

export class LocalAgentBindingStore {
  private data: StoredBinding = {}
  private bindings = new Map<LocalAgentBinding['bindingKind'], LocalAgentBinding>()
  private connected = new Map<string, {
    bindingKind: LocalAgentBinding['bindingKind']
    key: string
  }>()
  private writeChain = Promise.resolve()
  private lastError?: string
  private appleExpiryTimer?: ReturnType<typeof setTimeout>
  onAppleInvalidated:
    ((binding: AppleLocalAgentBinding, reason: 'lease_expired' | 'connection_disconnected' | 'unbound') => void)
    | undefined

  constructor(
    readonly path = 'data/local-agent.json',
    readonly verifier: LocalAgentProofVerifier = new UnixLocalAgentProofVerifier(),
  ) {}

  async load(): Promise<void> {
    console.log('load')
    try {
      const value = await Bun.file(this.path).json() as StoredBinding
      if (value?.binding?.version === 1) {
        const machine: MachineLocalAgentBinding = {
          ...value.binding,
          bindingKind: 'machine',
        }
        this.bindings.set('machine', machine)
        this.data = {
          ...value,
          binding: machine,
        }
      }
    } catch {}
  }

  async register(key: string, connectionId: string): Promise<LocalAgentProof> {
    console.log('register')
    let proof: LocalAgentProof
    try {
      console.log('proving', key, connectionId)
      proof = await this.verifier.prove(key, connectionId)
    } catch (error) {
      this.lastError = error instanceof Error ? error.message : String(error)
      throw new Error('local_agent_unavailable')
    }
    if (proof.key !== key) throw new Error('local_agent_proof_mismatch')

    const current = this.binding('machine')
    const same = current?.key === key
    const authorized = this.data.pendingRebind?.key === key
    if (current && !same && !authorized) throw new Error('local_agent_rebind_required')

    if (!current || !same) {
      const binding: MachineLocalAgentBinding = {
        version: 1,
        bindingKind: 'machine',
        key,
        capabilities: [...proof.capabilities].sort(),
        boundAt: new Date().toISOString(),
      }
      this.bindings.set('machine', binding)
      this.data.binding = binding
      delete this.data.pendingRebind
      await this.commit()
    }
    this.connected.set(connectionId, { bindingKind: 'machine', key })
    this.lastError = undefined
    return proof
  }

  async authorizeRebind(key: string): Promise<void> {
    console.log('authorizeRebind')
    if (!key) throw new Error('invalid_local_agent_rebind')
    this.data.pendingRebind = { key }
    await this.commit()
  }

  bindApple(
    assertion: AppleAppAgentReadinessAssertion,
    connectionId: string,
    key: string,
  ): AppleLocalAgentBinding {
    console.log('bindApple')
    const current = this.binding('apple-app') as AppleLocalAgentBinding | undefined
    if (current) {
      const sameTunnel = current.connectionId === connectionId
        && current.key === key
        && current.wireGuardKey === assertion.wireGuardKey
        && current.hubNetworkId === assertion.hubNetworkId
        && current.tunnelInstanceId === assertion.tunnelInstanceId
      if (sameTunnel && assertion.generation < current.generation) {
        throw new Error('stale_apple_agent_generation')
      }
      // Generation is monotonic only inside one tunnel instance. A provider
      // restart creates a new instance and starts its counter independently,
      // so comparing that value with the previous instance rejects fresh,
      // signed readiness assertions when both happen to use generation 2.
      if (!sameTunnel) this.invalidateApple(current, 'unbound')
    }
    const binding: AppleLocalAgentBinding = {
      version: 1,
      bindingKind: 'apple-app',
      key,
      capabilities: [...assertion.capabilities],
      connectionId,
      wireGuardKey: assertion.wireGuardKey,
      hubNetworkId: assertion.hubNetworkId,
      tunnelInstanceId: assertion.tunnelInstanceId,
      generation: assertion.generation,
      expiresAt: assertion.expiresAt,
    }
    this.bindings.set('apple-app', binding)
    this.connected.set(connectionId, { bindingKind: 'apple-app', key: key })
    this.scheduleAppleExpiry(binding)
    this.lastError = undefined
    return binding
  }

  renewApple(
    assertion: AppleAppAgentReadinessAssertion,
    connectionId: string,
    key: string,
  ): AppleLocalAgentBinding {
    console.log('renewApple')
    const current = this.binding('apple-app') as AppleLocalAgentBinding | undefined
    if (
      !current
      || current.connectionId !== connectionId
      || current.key !== key
      || current.wireGuardKey !== assertion.wireGuardKey
      || current.hubNetworkId !== assertion.hubNetworkId
      || current.tunnelInstanceId !== assertion.tunnelInstanceId
    ) throw new Error('apple_agent_binding_mismatch')
    if (assertion.generation < current.generation) throw new Error('stale_apple_agent_generation')
    return this.bindApple(assertion, connectionId, key)
  }

  unbindApple(request: AppleAppAgentUnbindRequest, connectionId: string): void {
    console.log('unbindApple')
    const current = this.binding('apple-app') as AppleLocalAgentBinding | undefined
    if (!current) return
    if (
      current.connectionId !== connectionId
      || current.hubNetworkId !== request.hubNetworkId
      || current.tunnelInstanceId !== request.tunnelInstanceId
      || current.generation !== request.generation
    ) throw new Error('apple_agent_binding_mismatch')
    this.invalidateApple(current, 'unbound')
  }

  disconnect(connectionId: string): void {
    console.log('disconnect')
    this.connected.delete(connectionId)
    const apple = this.binding('apple-app') as AppleLocalAgentBinding | undefined
    if (apple?.connectionId === connectionId) {
      this.invalidateApple(apple, 'connection_disconnected')
    }
  }

  binding(kind: LocalAgentBinding['bindingKind']): LocalAgentBinding | undefined {
    console.log('binding')
    return this.bindings.get(kind)
  }

  readyBinding(): LocalAgentBinding | undefined {
    console.log('readyBinding')
    this.expireApple()
    const machine = this.binding('machine') as MachineLocalAgentBinding | undefined
    if (
      machine
      && machine.capabilities.includes(LOCAL_AGENT_BOOTSTRAP_CAPABILITY)
      && [...this.connected.values()].some(connection =>
        connection.bindingKind === 'machine' && connection.key === machine.key)
    ) return machine

    const apple = this.binding('apple-app') as AppleLocalAgentBinding | undefined
    if (
      apple
      && apple.capabilities.includes(LOCAL_AGENT_BOOTSTRAP_CAPABILITY)
      && Date.parse(apple.expiresAt) > Date.now()
      && this.connected.get(apple.connectionId)?.bindingKind === 'apple-app'
    ) return apple
  }

  readyBindingPin(): LocalAgentBindingPin | undefined {
    console.log('readyBindingPin')
    const binding = this.readyBinding()
    if (!binding) return
    return {
      bindingKind: binding.bindingKind,
      key: binding.key,
      ...(binding.bindingKind === 'apple-app' ? {
        tunnelInstanceId: binding.tunnelInstanceId,
        generation: binding.generation,
      } : {}),
    }
  }

  status(): LocalAgentStatus {
    console.log('status')
    this.expireApple()
    const machine = this.binding('machine') as MachineLocalAgentBinding | undefined
    const apple = this.binding('apple-app') as AppleLocalAgentBinding | undefined
    const machineConnected = machine
      ? [...this.connected.values()].some(connection =>
        connection.bindingKind === machine.bindingKind
        && connection.key === machine.key)
      : false
    const appleConnected = Boolean(apple
      && apple.connectionId
      && this.connected.get(apple.connectionId)?.bindingKind === 'apple-app'
      && Date.parse(apple.expiresAt) > Date.now())
    const binding = machineConnected ? machine : appleConnected ? apple : machine ?? apple
    const connected = binding
      ? binding.bindingKind === 'apple-app'
        ? appleConnected
        : machineConnected
      : false
    const bootstrapCapable = Boolean(binding?.capabilities.includes(LOCAL_AGENT_BOOTSTRAP_CAPABILITY))
    const available = connected && bootstrapCapable
    return {
      version: 1,
      state: !binding ? 'unbound' : available ? 'available' : 'unavailable',
      bindingKind: binding?.bindingKind,
      key: binding?.key,
      ...(binding?.bindingKind === 'apple-app' ? {
        tunnelInstanceId: binding.tunnelInstanceId,
        generation: binding.generation,
        expiresAt: binding.expiresAt,
      } : {}),
      capabilities: binding?.capabilities ?? [],
      connected,
      bootstrapCapable,
      updatedAt: new Date().toISOString(),
      ...(available ? {} : {
        error: {
          version: 1 as const,
          code: 'local_agent_unavailable' as const,
          message: this.lastError ?? (!binding ? 'no local hub-net is bound' : 'bound local hub-net is disconnected'),
          retryable: true as const,
        },
      }),
    }
  }

  private async commit(): Promise<void> {
    console.log('commit')
    const write = this.writeChain.then(async () => {
      await mkdir(dirname(this.path), { recursive: true })
      const temporaryPath = `${this.path}.${crypto.randomUUID()}.tmp`
      await Bun.write(temporaryPath, JSON.stringify(this.data, null, 2))
      await rename(temporaryPath, this.path)
    })
    this.writeChain = write.catch(() => {})
    await write
  }

  private scheduleAppleExpiry(binding: AppleLocalAgentBinding): void {
    console.log('scheduleAppleExpiry')
    if (this.appleExpiryTimer) clearTimeout(this.appleExpiryTimer)
    const delay = Math.max(0, Date.parse(binding.expiresAt) - Date.now())
    console.log('scheduleAppleExpiry', delay)
    this.appleExpiryTimer = setTimeout(() => {
      this.appleExpiryTimer = undefined
      this.expireApple()
    }, delay)
    this.appleExpiryTimer.unref?.()
  }

  private expireApple(now = Date.now()): void {
    const apple = this.binding('apple-app') as AppleLocalAgentBinding | undefined
    if (apple && Date.parse(apple.expiresAt) <= now) {
      this.invalidateApple(apple, 'lease_expired')
    }
  }

  private invalidateApple(
    binding: AppleLocalAgentBinding,
    reason: 'lease_expired' | 'connection_disconnected' | 'unbound',
  ): void {
    console.log('invalidateApple')
    if (this.binding('apple-app') !== binding) return
    if (this.appleExpiryTimer) clearTimeout(this.appleExpiryTimer)
    console.log('invalidating apple')
    this.appleExpiryTimer = undefined
    this.bindings.delete('apple-app')
    this.connected.delete(binding.connectionId)
    this.onAppleInvalidated?.(binding, reason)
  }
}
