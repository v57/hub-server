import { randomUUIDv7 } from 'bun'
import { FreshState } from './fresh-state'
import { Storage } from './settings'

// Grants, protocol.md sections 6, 7 and 9

export type Subject = { key: string } | { device: string } | { group: string } | { everyone: true }
export type GrantObject = { path: string } | { prefix: string } | { share: string }

export interface Grant {
  id: string
  subject: Subject
  object: GrantObject
  /** Key of the owner who added it, `migration` for grants made from the old lists */
  by: string
  at: string
  /** A device's own grant the owner linked: it passes to the device's linked children, any depth (protocol.md section 14) */
  linked?: true
  /** A copy on a child: the id of the grant it came from. Goes when that grant does, and an owner giving the same one directly ends it. */
  copyOf?: string
}

/** Who a grant is checked against */
export interface GrantCaller {
  key?: string
  device?: { id: string }
  groups: string[]
}

const isString = (value: unknown): value is string => typeof value === 'string' && value.length > 0

/** Validates and copies a subject, so stored grants never carry extra fields */
export function parseSubject(value: any): Subject {
  if (value && typeof value === 'object') {
    if (isString(value.key)) return { key: value.key }
    if (isString(value.device)) return { device: value.device }
    if (isString(value.group)) return { group: value.group }
    if (value.everyone === true) return { everyone: true }
  }
  throw 'invalid subject'
}

export function parseObject(value: any): GrantObject {
  if (value && typeof value === 'object') {
    if (isString(value.path)) return { path: value.path }
    if (isString(value.prefix)) return { prefix: value.prefix }
    if (isString(value.share)) return { share: value.share }
  }
  throw 'invalid object'
}

const sameJSON = (a: object, b: object) => JSON.stringify(a) === JSON.stringify(b)
const identity = (subject: Subject, object: GrantObject) => JSON.stringify([subject, object])

/**
 * `data/grants.json`: who may call which paths and connect to which shares. Replaces the per-key call lists, the
 * group path lists and the Hub Network resource policies, which are migrated once and recorded in `migrated`.
 */
export class GrantStore {
  grants: Grant[] = []
  /** Old stores already turned into grants */
  migrated: string[] = []
  subscription = new FreshState<Grant[]>(() => this.grants)
  /** Grants added or removed, copies too, for Hub Network to revoke share connections */
  onChange?: (changed: Grant[]) => void
  /** A device's linked children, from the device registry. No copies change before it has loaded. */
  chain?: (device: string) => string[]
  storage = new Storage(
    'data/grants.json',
    () => ({ schema: 1, grants: this.grants, migrated: this.migrated }),
    data => {
      if (!data || typeof data !== 'object' || data.schema !== 1 || !Array.isArray(data.grants)) {
        throw new Error('unsupported grants file')
      }
      this.grants = data.grants.map((grant: any) => ({
        id: String(grant.id),
        subject: parseSubject(grant.subject),
        object: parseObject(grant.object),
        by: String(grant.by),
        at: String(grant.at),
        ...(grant.linked === true && 'device' in grant.subject && grant.copyOf === undefined ? { linked: true as const } : {}),
        ...(typeof grant.copyOf === 'string' ? { copyOf: grant.copyOf } : {}),
      }))
      this.migrated = Array.isArray(data.migrated) ? data.migrated : []
    },
  )

  /**
   * Adds a grant, or returns the same one if it exists. A copy of it becomes a direct grant: the owner gave it now, so
   * it stays when the grant it came from goes.
   */
  add(subject: Subject, object: GrantObject, by: string): Grant {
    const existing = this.grants.find(grant => sameJSON(grant.subject, subject) && sameJSON(grant.object, object))
    if (existing?.copyOf) {
      delete existing.copyOf
      existing.by = by
      existing.at = new Date().toISOString()
      this.changed([existing])
      return existing
    }
    if (existing) return existing
    const grant: Grant = { id: randomUUIDv7(), subject, object, by, at: new Date().toISOString() }
    this.grants.push(grant)
    this.changed([grant])
    return grant
  }
  remove(id: unknown): Grant | undefined {
    const index = this.grants.findIndex(grant => grant.id === id)
    if (index < 0) return
    const [grant] = this.grants.splice(index, 1)
    this.changed([grant])
    return grant
  }
  removeWhere(match: (grant: Grant) => boolean): Grant[] {
    const removed = this.grants.filter(match)
    if (!removed.length) return removed
    this.grants = this.grants.filter(grant => !match(grant))
    this.changed(removed)
    return removed
  }
  /** Replaces the subject of matching grants, keeping their ids (group renames) */
  renameSubject(from: Subject, to: Subject) {
    const changed = this.grants.filter(grant => sameJSON(grant.subject, from))
    for (const grant of changed) grant.subject = to
    if (changed.length) this.changed(changed)
  }
  markMigrated(name: string) {
    if (!this.migrated.includes(name)) this.migrated.push(name)
    this.storage.save()
  }
  /** Whether a device's own grant passes down its linked children. Only a `{ device }` grant can, and only its own. */
  setLinked(id: unknown, linked: boolean): Grant {
    const grant = this.grants.find(grant => grant.id === id)
    if (!grant) throw 'grant not found'
    if (!('device' in grant.subject) || grant.copyOf) throw 'only a device\'s own grant passes down'
    if ((grant.linked === true) === linked) return grant
    if (linked) grant.linked = true
    else delete grant.linked
    this.changed([grant])
    return grant
  }
  /** The device registry changed links: writes the copies that follow, in one save */
  settleCopies() {
    const changed = this.settle()
    if (!changed.length) return
    this.subscription.setNeedsUpdate()
    this.storage.save()
    this.onChange?.(changed)
  }
  /**
   * Makes the copies what the links say, and returns those added or removed. Every linked grant goes to each device down
   * the chain of linked children, except where that device holds the same grant directly. The walk never decides a call:
   * checks read the copies like any other grant.
   */
  private settle(): Grant[] {
    if (!this.chain) return []
    const direct = new Map(this.grants.filter(grant => !grant.copyOf).map(grant => [identity(grant.subject, grant.object), grant]))
    const wanted = new Map<string, { subject: Subject; object: GrantObject; sources: Grant[] }>()
    for (const grant of this.grants) {
      if (grant.copyOf || !grant.linked || !('device' in grant.subject)) continue
      const seen = new Set([grant.subject.device])
      const walk = [grant.subject.device]
      while (walk.length) {
        for (const child of this.chain(walk.shift()!)) {
          if (seen.has(child)) continue
          seen.add(child)
          walk.push(child)
          const key = identity({ device: child }, grant.object)
          if (direct.has(key)) continue
          const entry = wanted.get(key)
          if (entry) entry.sources.push(grant)
          else wanted.set(key, { subject: { device: child }, object: grant.object, sources: [grant] })
        }
      }
    }
    const changed: Grant[] = []
    const held = new Set<string>()
    this.grants = this.grants.filter(grant => {
      if (!grant.copyOf) return true
      const key = identity(grant.subject, grant.object)
      const entry = wanted.get(key)
      if (!entry) {
        changed.push(grant)
        return false
      }
      if (!entry.sources.some(source => source.id === grant.copyOf)) grant.copyOf = entry.sources[0]!.id
      held.add(key)
      return true
    })
    for (const [key, { subject, object, sources }] of wanted) {
      if (held.has(key)) continue
      const copy: Grant = { id: randomUUIDv7(), subject, object, by: sources[0]!.by, at: new Date().toISOString(), copyOf: sources[0]!.id }
      this.grants.push(copy)
      changed.push(copy)
    }
    return changed
  }
  private changed(grants: Grant[]) {
    const copies = this.settle()
    this.subscription.setNeedsUpdate()
    this.storage.save()
    this.onChange?.([...grants, ...copies])
  }

  /** The subject names this caller: its key, its device, one of its groups, or everyone */
  static matches(subject: Subject, caller: GrantCaller): boolean {
    if ('everyone' in subject) return true
    if ('key' in subject) return subject.key === caller.key
    if ('device' in subject) return subject.device === caller.device?.id
    return caller.groups.includes(subject.group)
  }
  allowsPath(caller: GrantCaller, path: string): boolean {
    return this.grants.some(({ subject, object }) => {
      if ('path' in object) {
        if (object.path !== path) return false
      } else if ('prefix' in object) {
        if (!path.startsWith(object.prefix)) return false
      } else {
        return false
      }
      return GrantStore.matches(subject, caller)
    })
  }
  allowsShare(caller: GrantCaller, share: string): boolean {
    return this.grants.some(
      ({ subject, object }) => 'share' in object && object.share === share && GrantStore.matches(subject, caller),
    )
  }
  /** Paths (not prefixes) granted to exactly this subject, for the old call and group list APIs */
  paths(subject: Subject): Set<string> {
    const paths = new Set<string>()
    for (const grant of this.grants) {
      if ('path' in grant.object && sameJSON(grant.subject, subject)) paths.add(grant.object.path)
    }
    return paths
  }
  forShare(share: string): Grant[] {
    return this.grants.filter(grant => 'share' in grant.object && grant.object.share === share)
  }
}
