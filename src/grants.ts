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

/**
 * `data/grants.json`: who may call which paths and connect to which shares. Replaces the per-key call lists, the
 * group path lists and the Hub Network resource policies, which are migrated once and recorded in `migrated`.
 */
export class GrantStore {
  grants: Grant[] = []
  /** Old stores already turned into grants */
  migrated: string[] = []
  subscription = new FreshState<Grant[]>(() => this.grants)
  /** Grants added or removed, for Hub Network to revoke share connections */
  onChange?: (changed: Grant[]) => void
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
      }))
      this.migrated = Array.isArray(data.migrated) ? data.migrated : []
    },
  )

  /** Adds a grant, or returns the same one if it exists */
  add(subject: Subject, object: GrantObject, by: string): Grant {
    const existing = this.grants.find(grant => sameJSON(grant.subject, subject) && sameJSON(grant.object, object))
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
  private changed(grants: Grant[]) {
    this.subscription.setNeedsUpdate()
    this.storage.save()
    this.onChange?.(grants)
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
