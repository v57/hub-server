# Hub Agent Service
post `net/invite Void -> String`
Creates invite code, expires in 7 days
Permission name: Hub Network -> Invite to Hub Net

post `net/ports/update UpdatePorts -> Void`
```ts
interface UpdatePorts {
  users?: string[] // when user is not provided, sets ports for all users (NetInfo.tcp, NetInfo.udp)
  set?: [UpdatePortsCommand] // replaces current configuration
  update?: [UpdatePortsCommand] // updates current configuration if replace == nil
}
interface UpdatePortsCommand { 
  port: number
  tcp: boolean = true
  udp: boolean = true
  add: boolean = true
}
```
Permission name: Hub Network -> Open and close ports

stream `net/users Void -> [NetUser]`
Returns list of registered keys in format:
```ts
interface NetUser { 
  id: string // key
  ip: string
  lastUsed: Date
  online: boolean
  tcp: number[] // only manual ports
  udp: number[] // only manual ports
}
```
Permission name: Hub Network -> View connected devices

stream `net/info Void -> NetInfo`
```ts
interface NetInfo { 
  id: string // key
  ip: string
  ipv6: string
  online: boolean // is connected to hub-net-node
  tcp: number[] // tcp ports opened for all users
  udp: number[] // udp ports opened for all users
  vpn: boolean 
}
```
Permission name: Hub Network -> Read network

post `net/revoke` String -> Void
Revokes key and kicks from network
Permission name: Hub Network -> Revoke access

# Hub Pro
stream `hub/net/list Void -> [HubNetInfo]`
Returns list of agents in format:
```ts
typealias HubNetInfo { 
  id: string // public key of hub-net
  localIp: string // ip address of connection
}
```

stream `hub/net/node` Void -> String
Returns current hub-net-node address (default: `hub.v57.dev/node`)

post `hub/net/node/set` String? -> Void
Permission: Owner only
Sets hub-net-node address (default: `hub.v57.dev/node`)

Connection state now should have ip address to separate devices and see which one is local

# Flows
## hub-net on adding hub connection / Hub App when Join Network toggled on this hub
agent: Service connects to hub-pro and announces its services (just like all services do, nothing changes)
pro: sends update to `hub/net/list` when see `hub/net` api registration
agent: Subscribes to `hub/net/node`, authorizes with provided `hub-net-node` (with its service public key)

## Create Invite
client: Subscribes to `hub/net/list`, displays list of agents. `Copy Invite` button appears in front of agent that have 127.0.0.1 `HubNetInfo.localIp` (when `net/invite` api is available)
client: `Copy Invite` sends `net/invite` with `context.service: HubNetInfo.id` (hub-pro can already pass this request to a proper service)
agent: Generates code in format `$publicKey.$expires.$nonce?query` signs and appends signature `$publicKey.$expires.$nonce?query/$signature`
- nonce: 32bit random number in base64
- expires: 32bit unix timestamp (1 week duration)
- publicKey: agent public key,
- signature: `$nonce.$expires` signed by agent's private key
query commands (all optional):
- e: endpoint address (default: `hub.v57.dev/node`) (example: `e=34.25.235.23`)
client: Converts that code to `hub://join/$publicKey.$expires.$nonce?query/$signature` and copies to clipboard

## Join Invite
client: Opens link, parses all data, verifies signature
client: Sends that link to `hub-net-node` at provided or default endpoint
hub-net-node: Extracts data, verifies (format, signature, expires in less than 8 days, agent online), makes sha256 hash of this code, checks if it's used, adds to in-memory list of used list that will automatically flush after expiration date. Connects it to agent
client: After connecting to agent, connects to `hub-pro` at agent.ip:1997
client: Should get access to all agent ip addresses, shared ports


Let's rethink the tests. 
1. Add NetworkTestingView where all tests would happen
2. Display this view inside HubApp as overlay when it sees the environments
3. Separate environments by network/host/client
4. Create VStack that displays all tests in format: HStack(Image Text) with following icons and colors:
completed successfully: green "checkmark.circle.fill"
failed: red "xmark.circle.fill"
running: blue "arrowtriangle.right.circle.fill"
pending: secondary "circle"
5. Add 100ms delay before starting next task
6. Exit process 1s after tests completed (except for host environment)

## HUBTESTENV=network (only on local mac)
1. Connect to hub-pro
2. Check permissions
3. Join network
4. Share port
5. Allow to use as vpn
6. Share invite

## HUBTESTENV=host (only on local mac)
1. Connect to hub-pro
2. Check permissions
3. Join network
4. Share port 18403
5. Starts some tcp server on that port using Network library
6. Share invite (prints in the logs, then opens HUBTESTENV=client on a remote mac/ios)
7. Waits until test completion

## HUBTESTENV=client (never on local mac)
1. Use invite link
2. Join network
3. Join hub-pro
4. Sends requests to 18403 port

`host` and `network` environments always runs on local machine as owner of `hub-pro`. It does all test and shares invites.
`client` uses invite to join host network and hub-pro through created virtual network
Before updating testing plan, give me examples how it should be expanded (maybe different environments for different tests or additional tasks per environment)
