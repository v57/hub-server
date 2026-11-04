#!/usr/bin/env bun
const help = `Usage: hub-server [options]

Options:
  -p, --port <port>      listen on a port or address (default 1997, env HUBLISTEN)
  --merge <address>      merge this hub's api into another hub
  --proxy <address>      join another hub as a proxy
  --owner <key>          trust this key as an owner (env HUBOWNER)
  --launcher <key>       let this key host and call launcher/* (env HUBLAUNCHER); it's no owner
  --local                local mode: 127.0.0.1 only, default-allow (env HUB_MODE=local)
  --pair                 write a new pairing code to data/, replacing the old one, print it and exit; a running
                         hub on that data/ takes it at once (a hub without owners makes one at start anyway)
  -h, --help             print this help`

let port: number | undefined
let merges: string[] = []
let proxies: string[] = []
let owners: string[] = []
let launcher = Bun.env['HUBLAUNCHER']
let pair = false
let local = Bun.env['HUB_MODE'] === 'local'
const argv = process.argv.slice(2)
while (true) {
  const command = argv.shift()
  if (!command) break
  switch (command) {
    case '-p':
    case '--port':
      port = Number(argv.shift())
      break
    case '--merge':
      const merge = argv.shift()
      if (merge) merges.push(merge)
      break
    case '--proxy':
      const proxy = argv.shift()
      if (proxy) proxies.push(proxy)
      break
    case '--owner':
      const id = argv.shift()
      if (id) owners.push(id)
      break
    case '--launcher':
      launcher = argv.shift()
      break
    case '--local':
      local = true
      break
    case '--pair':
      pair = true
      break
    case '-h':
    case '--help':
      console.log(help)
      process.exit(0)
    default:
      break
  }
}
const owner = Bun.env['HUBOWNER']
if (owner?.length) owners.push(owner)

// One-shot, also while a hub runs on this data/: it re-reads data/pairing.json on every attempt
if (pair) {
  const { Pairing } = await import('./src/pairing')
  await new Pairing().start({ needed: true, force: true })
  process.exit(0)
}

// Loads the stores in data/, so it comes after `--help`
const { Hub, security } = await import('./src/hub')
owners.forEach(id => security.addOwner(id))
if (launcher?.length) security.launcher = launcher

const hub = new Hub(port, { local })
hub.startPairing().catch(error => console.error('Pairing code unavailable:', error))
merges.forEach(address => {
  hub.merger.connect(address, hub, false)
})
proxies.forEach(address => {
  hub.merger.connectProxy(address, hub, false)
})
