# Hub Network protocol foundations

This document freezes version 1 naming, identity, overlay constants. Wire implementations MUST treat ASCII strings and byte framing below as normative.

## Canonical DNS authority

- Reserved suffix: `hub.invalid`. `.invalid` guaranteed not to resolve through public DNS; active Hub Network profile answers only this suffix.
- Resource authority: `<display>-<resource-tag>.v1-<hub-tag>.hub.invalid`.
- `display`: readability only. NFKD, lowercase ASCII, combining marks removed, non-alphanumerics collapsed to `-`, trimmed, limited to 24 bytes. Empty result becomes `share`.
- `resource-tag`: first 16 base32 characters of stable resource digest.
- `hub-tag`: first 16 base32 characters of `SHA-256("hub-network/authority-hub/v1" || NUL || field(hubNetworkId))`.
- Base32: lowercase RFC 4648 without padding. Authorities never depend on display name for uniqueness.

## Stable resource identity

Publisher normalizes share name with Unicode NFKC, trims leading/trailing whitespace. Empty names and names longer than 128 UTF-8 bytes invalid. Owner Ed25519 SPKI key decoded, re-encoded as canonical base64.

`resourceId = "hnr1_" + base32(SHA-256(domain || NUL || field(ownerKey) || field(shareName)))[0:32]`

Domain: `hub-network/resource/v1`. Each `field`: four-byte unsigned big-endian UTF-8 byte length followed by bytes. Resulting identifier has 160 digest bits; length-prefixing prevents concatenation ambiguity. Collision MUST fail registration, reported as `resource_id_collision`; MUST NOT merge ownership or policy.

## Overlay ranges

- Agent IPv4 addresses: `100.96.0.1` through `100.127.254.254` (`100.96.0.0/11`), excluding network/broadcast addresses in allocated subnets. `100.127.255.0/24` reserved for future protocol infrastructure.
- Agent IPv6 addresses: `fd48:5542:4e45::1` through `fd48:5542:4e45:ffff:ffff:ffff:ffff:fffe` (`fd48:5542:4e45::/48`). `fd48:5542:4e45:ffff::/64` reserved.
- Hub persists allocations, enforces uniqueness within network. Agents MUST reject startup if either prefix overlaps existing local route; version 1 does not silently install broader or default route.

## Collision and normalization vectors

Executable vectors live in `src/network/foundation.test.ts`. They cover:

- two owners publishing same `s3` display name;
- decomposed and composed Unicode share names;
- padded and unpadded representations of same base64 public key;
- length-framed inputs containing NUL byte; and
- exact stable IDs and authorities for cross-language conformance.