# Hub Network protocol foundations

This document freezes the version 1 naming, identity, and overlay constants. Wire
implementations MUST treat the ASCII strings and byte framing below as normative.

## Canonical DNS authority

- The reserved suffix is `hub.invalid`. `.invalid` is guaranteed not to resolve
  through public DNS; an active Hub Network profile answers only this suffix.
- A resource authority is
  `<display>-<resource-tag>.v1-<hub-tag>.hub.invalid`.
- `display` is for readability only: NFKD, lowercase ASCII, combining marks
  removed, non-alphanumerics collapsed to `-`, trimmed, and limited to 24 bytes.
  An empty result becomes `share`.
- `resource-tag` is the first 16 base32 characters of the stable resource digest.
- `hub-tag` is the first 16 base32 characters of
  `SHA-256("hub-network/authority-hub/v1" || NUL || field(hubNetworkId))`.
- Base32 is lowercase RFC 4648 without padding. Authorities never depend on a
  display name for uniqueness.

## Stable resource identity

A publisher normalizes a share name with Unicode NFKC and trims leading and
trailing whitespace. Empty names and names longer than 128 UTF-8 bytes are
invalid. The owner Ed25519 SPKI key is decoded and re-encoded as canonical
base64.

`resourceId = "hnr1_" + base32(SHA-256(domain || NUL || field(ownerKey) || field(shareName)))[0:32]`

The domain is `hub-network/resource/v1`. Each `field` is its four-byte unsigned
big-endian UTF-8 byte length followed by its bytes. The resulting identifier has
160 digest bits; length-prefixing prevents concatenation ambiguity. A collision
MUST fail registration and be reported as `resource_id_collision`; it MUST NOT
merge ownership or policy.

## Overlay ranges

- Agent IPv4 addresses: `100.96.0.1` through `100.127.254.254`
  (`100.96.0.0/11`), excluding network/broadcast addresses in allocated
  subnets. `100.127.255.0/24` is reserved for future protocol infrastructure.
- Agent IPv6 addresses: `fd48:5542:4e45::1` through
  `fd48:5542:4e45:ffff:ffff:ffff:ffff:fffe`
  (`fd48:5542:4e45::/48`). `fd48:5542:4e45:ffff::/64` is reserved.
- The Hub persists allocations and enforces uniqueness within its network.
  Agents MUST reject startup if either prefix overlaps an existing local route;
  version 1 does not silently install a broader or default route.

## Collision and normalization vectors

The executable vectors live in `src/network/foundation.test.ts`. They cover:

- two owners publishing the same `s3` display name;
- decomposed and composed Unicode share names;
- padded and unpadded representations of the same base64 public key;
- length-framed inputs containing a NUL byte; and
- exact stable IDs and authorities for cross-language conformance.

