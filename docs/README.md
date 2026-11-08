# hub-server developer documentation

`hub-server` is the Hub server: one process that services and apps connect to over the
[channel](https://github.com/v57/channel) protocol (WebSocket). It routes calls between them, decides who may call
what, keeps a directory of devices and runs the control plane of the Hub Network. It runs on Bun.

The wire contract is the Hub protocol (`Docs/Devices/protocol.md` in the Hub workspace). These pages describe how
this server implements it and what the protocol leaves to the server: options, files, defaults and tests. Where a
page says "protocol section N", that is the place for message formats and API tables.

| Page | What |
|---|---|
| [Running](running.md) | Options and environment variables, pairing the first owner, local mode, the launcher key, merging and proxies, deployment |
| [Data folder](data.md) | `data/`: the hub key, the JSON stores, the pairing files, what happens to a corrupt file |
| [Security](security.md) | `default-deny` and `default-allow`, owners, grants, groups, hosting approval, the whitelist, lockdown, v0 and v1 tokens |
| [APIs](api.md) | The built-in `hub/*` paths by area, service registration, routing and load balancers, draining, errors, API descriptions (`hub/api/list`) |
| [Hub Network](network.md) | The network control plane it serves (`hub/net/*`, `network/*`) and its settings |
| [Testing](testing.md) | `bun test`, the conformance harness, and running the harness against another server such as the Swift HubServer |

Related:

- [HubServer](https://github.com/v57/HubServer): the same server in Swift, as a library apps embed and as the
  `hub-server-swift` command. It passes this repo's conformance harness.
- [hub-service](https://github.com/v57/hub-service): the TypeScript SDK services and clients use to talk to a hub
  (`docs/service-features.md`, `docs/api-descriptions.md` there). [HubService](https://github.com/v57/HubService) is
  the Swift SDK.
- [hub](https://github.com/v57/hub): the `hub` command, which controls `hub-launcher`; the launcher installs and runs
  hub-server.
