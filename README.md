<h1>
  <img alt="Containerization logo" src="./icon.png" width="70" valign="middle">
  &nbsp;hub-pro
</h1>

# Usage

## Start hub process

```sh
bunx v57/hub-pro
```

Our just use it in your project `bun add v57/hub-pro`

```ts
import { Hub } from 'hub-pro'
new Hub()
```

## Create hub service

```ts
import { Service } from 'hub-service'
new Service().post('hash/sha256', body => new Bun.SHA256().update(body).digest('hex')).start()
```

## Client api

```ts
import { Client } from 'hub-client'
const client = new Client()
const hash = await client.post('hash/sha256', 'Hello World')
console.log(hash)
```
