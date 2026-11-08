// API descriptions (protocol.md section 15): what services say about their paths, kept per connection and listed by
// `hub/api/list`

export type ApiKind = 'post' | 'stream'

export interface ApiDescriptionFields {
  title?: string
  description?: string
  inputSchema?: Record<string, unknown>
  outputSchema?: Record<string, unknown>
  annotations?: Partial<Record<(typeof annotationKeys)[number], boolean>>
}

export interface ApiDescription extends ApiDescriptionFields {
  path: string
  kind?: ApiKind
}

/** What one connection said about one path */
export interface PathDescriptions {
  /** Kinds its headers named */
  kinds: Set<ApiKind>
  post?: ApiDescriptionFields
  stream?: ApiDescriptionFields
}

export const limits = { title: 128, description: 4096, schema: 64 * 1024 }
const annotationKeys = ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'] as const

function schema(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return
  try {
    const json = JSON.stringify(value)
    return new TextEncoder().encode(json).length <= limits.schema ? JSON.parse(json) : undefined
  } catch {
    return
  }
}

const text = (value: unknown, limit: number) => (typeof value === 'string' && value.length > 0 && value.length <= limit ? value : undefined)

/** The description fields of a `ServiceHeader` the hub keeps; anything malformed or too large is left out */
export function describedFields(header: any): ApiDescriptionFields | undefined {
  const fields: ApiDescriptionFields = {}
  const title = text(header?.title, limits.title)
  if (title) fields.title = title
  const description = text(header?.description, limits.description)
  if (description) fields.description = description
  const input = schema(header?.inputSchema)
  if (input) fields.inputSchema = input
  const output = schema(header?.outputSchema)
  if (output) fields.outputSchema = output
  const annotations = header?.annotations
  if (annotations && typeof annotations === 'object') {
    const kept: ApiDescriptionFields['annotations'] = {}
    for (const key of annotationKeys) if (typeof annotations[key] === 'boolean') kept[key] = annotations[key]
    if (Object.keys(kept).length) fields.annotations = kept
  }
  return Object.keys(fields).length ? fields : undefined
}

/** A connection's descriptions from the headers of a `services` update, by path */
export function readDescriptions(headers: any[]): Map<string, PathDescriptions> {
  const result = new Map<string, PathDescriptions>()
  for (const header of headers) {
    const path = header?.path
    if (typeof path !== 'string') continue
    let entry = result.get(path)
    if (!entry) result.set(path, (entry = { kinds: new Set() }))
    const kind: ApiKind | undefined = header.kind === 'post' || header.kind === 'stream' ? header.kind : undefined
    if (!kind) continue
    entry.kinds.add(kind)
    const fields = describedFields(header)
    if (fields && !entry[kind]) entry[kind] = fields
  }
  return result
}

/**
 * The `hub/api/list` entries of one path: one per kind that a built-in or a provider's header named, with the fields
 * of the first provider that described it; `{ path }` when nothing named a kind. `providers` are in the hub's order.
 */
export function describePath(path: string, builtinKinds: ApiKind[] | undefined, providers: (PathDescriptions | undefined)[]): ApiDescription[] {
  const kinds = new Set<ApiKind>(builtinKinds)
  providers.forEach(provider => provider?.kinds.forEach(kind => kinds.add(kind)))
  if (!kinds.size) return [{ path }]
  return (['post', 'stream'] as const)
    .filter(kind => kinds.has(kind))
    .map(kind => ({ path, kind, ...providers.find(provider => provider?.[kind])?.[kind] }))
}
