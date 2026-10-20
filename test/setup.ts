import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

process.chdir(mkdtempSync(join(tmpdir(), 'hub-pro-test-')))

// Never touch the machine's own ~/.hub/device.key
process.env.HUB_DEVICE_KEY = join(process.cwd(), 'device.key')
