# ts-mls

[![CI](https://github.com/LukaJCB/ts-mls/actions/workflows/ci.yml/badge.svg)](https://github.com/LukaJCB/ts-mls/actions/workflows/ci.yml)

Typescript implementation of Messaging Layer Security (RFC 9420, MLS).

This project is work in progress, but it will focus on immutability, type safety, minimal dependencies and extensibility.


## Supported Ciphersuites

The following cipher suites are supported:

| KEM                      | AEAD             | KDF         | Hash    | Signature | Name                                                     | ID |
| ------------------------ | ---------------- | ----------- | ------- | --------- | -------------------------------------------------------- | -- |
| DHKEM-X25519-HKDF-SHA256 | AES128GCM        | HKDF-SHA256 | SHA-256 | Ed25519   | MLS\_128\_DHKEMX25519\_AES128GCM\_SHA256\_Ed25519        | 1  |
| DHKEM-P256-HKDF-SHA256   | AES128GCM        | HKDF-SHA256 | SHA-256 | P256      | MLS\_128\_DHKEMP256\_AES128GCM\_SHA256\_P256             | 2  |
| DHKEM-X25519-HKDF-SHA256 | CHACHA20POLY1305 | HKDF-SHA256 | SHA-256 | Ed25519   | MLS\_128\_DHKEMX25519\_CHACHA20POLY1305\_SHA256\_Ed25519 | 3  |
| DHKEM-X448-HKDF-SHA512   | AES256GCM        | HKDF-SHA512 | SHA-512 | Ed448     | MLS\_256\_DHKEMX448\_AES256GCM\_SHA512\_Ed448            | 4  |
| DHKEM-P521-HKDF-SHA512   | AES256GCM        | HKDF-SHA512 | SHA-512 | P521      | MLS\_256\_DHKEMP521\_AES256GCM\_SHA512\_P521             | 5  |
| DHKEM-X448-HKDF-SHA512   | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | Ed448     | MLS\_256\_DHKEMX448\_CHACHA20POLY1305\_SHA512\_Ed448     | 6  |
| DHKEM-P384-HKDF-SHA384   | AES256GCM        | HKDF-SHA384 | SHA-384 | P384      | MLS\_256\_DHKEMP384\_AES256GCM\_SHA384\_P384             | 7  |
| ML-KEM-512               | AES256GCM        | HKDF-SHA256 | SHA-256 | Ed25519   | MLS\_128\_MLKEM512\_AES128GCM\_SHA256\_Ed25519           | 77 |
| ML-KEM-512               | CHACHA20POLY1305 | HKDF-SHA256 | SHA-256 | Ed25519   | MLS\_128\_MLKEM512\_CHACHA20POLY1305\_SHA256\_Ed25519    | 78 |
| ML-KEM-768               | AES256GCM        | HKDF-SHA384 | SHA-384 | Ed25519   | MLS\_256\_MLKEM768\_AES256GCM\_SHA384\_Ed25519           | 79 |
| ML-KEM-768               | CHACHA20POLY1305 | HKDF-SHA384 | SHA-384 | Ed25519   | MLS\_256\_MLKEM768\_CHACHA20POLY1305\_SHA384\_Ed25519    | 80 |
| ML-KEM-1024              | AES256GCM        | HKDF-SHA512 | SHA-512 | Ed25519   | MLS\_256\_MLKEM1024\_AES256GCM\_SHA512\_Ed25519          | 81 |
| ML-KEM-1024              | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | Ed25519   | MLS\_256\_MLKEM1024\_CHACHA20POLY1305\_SHA512\_Ed25519   | 82 |
| X-Wing                   | AES256GCM        | HKDF-SHA512 | SHA-512 | Ed25519   | MLS\_256\_XWING\_AES256GCM\_SHA512\_Ed25519              | 83 |
| X-Wing                   | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | Ed25519   | MLS\_256\_XWING\_CHACHA20POLY1305\_SHA512\_Ed25519       | 84 |



## Basic Usage

```typescript
const impl = getCiphersuiteImpl(getCiphersuiteFromName("MLS_256_XWING_AES256GCM_SHA512_Ed25519"))

// alice generates her key package
const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)

const groupId = new TextEncoder().encode("group1")

// alice creates a new group
let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

// bob generates her key package
const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

// bob sends keyPackage to alice
const keyPackageMessage = encodeMlsMessage({
  keyPackage: bob.publicPackage,
  wireformat: "mls_key_package",
  version: "mls10",
})

// alice decodes bob's keyPackage
const decodedKeyPackage = decodeMlsMessage(keyPackageMessage, 0)![0]

if (decodedKeyPackage.wireformat !== "mls_key_package") throw new Error("Expected key package")

// alice creates proposal to add bob
const addBobProposal: ProposalAdd = {
  proposalType: "add",
  add: {
    keyPackage: decodedKeyPackage.keyPackage,
  },
}

// alice commits
const commitResult = await createCommit(aliceGroup, {}, false, [addBobProposal], impl)

aliceGroup = commitResult.newState

// alice sends welcome message to bob
const encodedWelcome = encodeMlsMessage({
  welcome: commitResult.welcome!,
  wireformat: "mls_welcome",
  version: "mls10",
})

// bob decodes the welcome message
const decodedWelcome = decodeMlsMessage(encodedWelcome, 0)![0]

if (decodedWelcome.wireformat !== "mls_welcome") throw new Error("Expected welcome")

// bob creates his own group state
let bobGroup = await joinGroup(
  decodedWelcome.welcome,
  bob.publicPackage,
  bob.privatePackage,
  [],
  impl,
  aliceGroup.ratchetTree,
)

// ensure epochAuthenticator values are equal
expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

const messageToBob = new TextEncoder().encode("Hello bob!")

// alice creates a message to the group
const aliceCreateMessageResult = await createApplicationMessage(aliceGroup, messageToBob, impl)

aliceGroup = aliceCreateMessageResult.newState

// alice sends the message to bob
const encodedPrivateMessageAlice = encodeMlsMessage({
  privateMessage: aliceCreateMessageResult.privateMessage,
  wireformat: "mls_private_message",
  version: "mls10",
})

// bob decodes the message
const decodedPrivateMessageAlice = decodeMlsMessage(encodedPrivateMessageAlice, 0)![0]

if (decodedPrivateMessageAlice.wireformat !== "mls_private_message") throw new Error("Expected private message")

// bob receives the message
const bobProcessMessageResult = await processPrivateMessage(
  bobGroup,
  decodedPrivateMessageAlice.privateMessage,
  {},
  impl,
)

bobGroup = bobProcessMessageResult.newState

if (bobProcessMessageResult.kind === "newState") throw new Error("Expected application message")

console.log(bobProcessMessageResult.message)
```

## Current Status

The following test vectors are fully passing:

- [x] crypto-basics
- [x] deserialization
- [x] key-schedule
- [x] message-protection
- [x] messages
- [x] passive-client-handling-commit
- [x] passive-client-random
- [x] passive-client-welcome
- [x] psk_secret
- [x] secret-tree
- [x] transcript-hashes
- [x] tree-math
- [x] tree-operations
- [x] tree-validation
- [x] treekem
- [x] welcome
