<h1>
  <img alt="Containerization logo" src="./icon.png" width="70" valign="middle">
  &nbsp;Hub Pro Server
</h1>

`hub-pro` is a secure version of [hub-lite](https://github.com/v57/hub-lite). 
- Load balancers
- Permissions
- Merge hubs

## Quick Start
#### [Run from Hub cli](https://github.com/v57/hub)

#### Run from Bun
```sh
bunx v57/hub-pro
```
#### Run from Source
```sh
bun i && bun .
```

## Options
- `-p`, `--port <port>`: listen on a specific port or address
- `--merge <address>`: will merge api to another Hub.
- `--owner <id>`: set owner key.
- `--launcher <id>`: sets launcher key that allowed to host `launcher/*` APIs.
## Environment
- `HUBLISTEN`: default listen address or port.
- `HUBOWNER`: owner key to trust at startup.
- `HUBLAUNCHER`: launcher key to trust at startup.
## Load balancers:
- `random` will call random service
- `counter` will call next service in the list
- `first` will call first available service in the list
- `available` same as `counter`, but checks for availability

## Permissions
- Owners can call all Hub commands and will bypass any service permissions
- Owners can allow services to host api
- Services can provide permission for each api, so only allowed connections can use it
- Owners can create permission groups and assign keys to it
- Lockdown mode blocks any non whitelisted users to connect to Hub

## Create hub service
[TypeScript](https://github.com/v57/hub-service) [Swift](https://github.com/v57/HubService)

```ts
import { Service } from 'hub-service'
new Service().post('hash/sha256', body => new Bun.SHA256().update(body).digest('hex')).start()
```

## Client api

```ts
import { Service } from 'hub-service'
const service = new Service().start()
const hash = await service.send('hash/sha256', 'Hello World')
console.log(hash)
```
