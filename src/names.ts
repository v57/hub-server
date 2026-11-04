// Device names (protocol.md section 13): what counts as the same name, and the name a device gets. Only the hub needs
// this, so it lives in hub-server and HubServer alone; `names` in vectors.json holds both to one result.

/** Capitals whose lowercase form looks like a different letter */
const capitalLookalikes: Record<string, string> = { Η: 'h', Ν: 'n', Υ: 'y' }

/**
 * Letters that look like another one once case and marks are gone: the letter, then its lookalikes. Not all of Unicode's
 * confusables: the ones that pass for Latin letters and digits in Cyrillic, Greek, Armenian, Cherokee, Hebrew and
 * Arabic. A false match only costs a device a suffix.
 */
export const lookalikes: [string, string][] = [
  ['a', 'аɑαꭺ⍺'],
  ['b', 'вьβƅ'],
  ['c', 'сꮯ'],
  ['d', 'ԁꭰđ'],
  ['e', 'еεєҽꭼ'],
  ['f', 'ƒғ'],
  ['g', 'ɡցԍꮐ'],
  ['h', 'һнհꮋħ'],
  ['j', 'јϳ'],
  ['k', 'кκꮶĸ'],
  ['l', 'iіıιɩӏǀ|ꮮ\u05D5\u0627\u0661\u06F1ꓲł1'],
  ['m', 'мꮇϻ'],
  ['n', 'пηո'],
  ['o', 'оοσςօᴏ\u09E6\u0966ⲟø0'],
  ['p', 'рρⲣꮲ'],
  ['q', 'ԛզ'],
  ['r', 'гꭱɾ'],
  ['s', 'ѕꮪƽ'],
  ['t', 'тτꭲŧ'],
  ['u', 'υսʋ'],
  ['v', 'νѵꮩᴠ'],
  ['w', 'ԝѡωꮃᴡ'],
  ['x', 'хχ'],
  ['y', 'уγүꭹʏ'],
  ['z', 'ζᴢꮓ'],
  ['3', 'з'],
  ['ss', 'ß'],
  ['ae', 'æ'],
  ['oe', 'œ'],
]
const lookalikeMap = new Map(lookalikes.flatMap(([letter, others]) => Array.from(others, other => [other, letter] as [string, string])))

/** Pairs of letters that read as one letter */
const pairs: [RegExp, string][] = [
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/cl/g, 'd'],
]

/** What names are compared by: no case, spaces, punctuation, marks or invisible characters, lookalikes as one letter */
export function normalizeName(name: string): string {
  const letters = name
    // Unicode's decomposition reads these as sigma, which looks like nothing they do
    .replace(/[ϲϹ]/g, 'c')
    .normalize('NFKD')
    .replace(/[\p{Mn}\p{Me}\p{C}\p{Z}\p{P}\p{Default_Ignorable_Code_Point}]/gu, '')
    .replace(/[ΗΝΥ]/g, capital => capitalLookalikes[capital]!)
    .toLowerCase()
  let text = Array.from(letters, letter => lookalikeMap.get(letter) ?? letter).join('')
  for (const [pair, letter] of pairs) text = text.replace(pair, letter)
  return text
}

/** Longest device name in bytes */
const maxNameBytes = 64

/** The first code points of `text` that fit in `bytes`, with no space left at the end */
function fit(text: string, bytes: number): string {
  let used = 0
  let kept = ''
  for (const letter of text) {
    used += Buffer.byteLength(letter)
    if (used > bytes) break
    kept += letter
  }
  return kept.trimEnd()
}

/**
 * A name as a device or owner wrote it, ready to show: without control characters and the invisible ones that reorder
 * text, trimmed, at most 64 bytes. A name with nothing left to compare is `Device`.
 */
export function cleanName(name: string): string {
  const clean = fit(name.replace(/[\p{Cc}\u2028\u2029\u200E\u200F\u202A-\u202E\u2066-\u2069\u061C]/gu, '').trim(), maxNameBytes)
  return normalizeName(clean) ? clean : 'Device'
}

/** The name a device asking for `asked` gets: that one if nobody holds it, else `<name>-2`, `-3` and so on */
export function freeName(asked: string, held: (normalized: string) => boolean): string {
  const name = cleanName(asked)
  if (!held(normalizeName(name))) return name
  for (let number = 2; ; number++) {
    const suffix = `-${number}`
    const candidate = `${fit(name, maxNameBytes - suffix.length)}${suffix}`
    if (!held(normalizeName(candidate))) return candidate
  }
}
