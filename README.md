# ts-mls

[![CI](https://github.com/LukaJCB/ts-mls/actions/workflows/ci.yml/badge.svg)](https://github.com/LukaJCB/ts-mls/actions/workflows/ci.yml)

Typescript implementation of Messaging Layer Security (RFC 9420, MLS).

This project is work in progress, but it will focus on immutability, type safety, minimal dependencies and extensibility.

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

## Supported Ciphersuites

The following cipher suites are supported:

| ID  | Name                                                | KEM                      | AEAD             | KDF         | Hash    | Signature |
| --- | --------------------------------------------------- | ------------------------ | ---------------- | ----------- | ------- | --------- |
| 1   | MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519        | DHKEM-X25519-HKDF-SHA256 | AES128GCM        | HKDF-SHA256 | SHA-256 | Ed25519   |
| 2   | MLS_128_DHKEMP256_AES128GCM_SHA256_P256             | DHKEM-P256-HKDF-SHA256   | AES128GCM        | HKDF-SHA256 | SHA-256 | P256      |
| 3   | MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 | DHKEM-X25519-HKDF-SHA256 | CHACHA20POLY1305 | HKDF-SHA256 | SHA-256 | Ed25519   |
| 4   | MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448            | DHKEM-X448-HKDF-SHA512   | AES256GCM        | HKDF-SHA512 | SHA-512 | Ed448     |
| 5   | MLS_256_DHKEMP521_AES256GCM_SHA512_P521             | DHKEM-P521-HKDF-SHA512   | AES256GCM        | HKDF-SHA512 | SHA-512 | P521      |
| 6   | MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448     | DHKEM-X448-HKDF-SHA512   | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | Ed448     |
| 7   | MLS_256_DHKEMP384_AES256GCM_SHA384_P384             | DHKEM-P384-HKDF-SHA384   | AES256GCM        | HKDF-SHA384 | SHA-384 | P384      |
| 77  | MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519           | ML-KEM-512               | AES256GCM        | HKDF-SHA256 | SHA-256 | Ed25519   |
| 78  | MLS_128_MLKEM512_CHACHA20POLY1305_SHA256_Ed25519    | ML-KEM-512               | CHACHA20POLY1305 | HKDF-SHA256 | SHA-256 | Ed25519   |
| 79  | MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519           | ML-KEM-768               | AES256GCM        | HKDF-SHA384 | SHA-384 | Ed25519   |
| 80  | MLS_256_MLKEM768_CHACHA20POLY1305_SHA384_Ed25519    | ML-KEM-768               | CHACHA20POLY1305 | HKDF-SHA384 | SHA-384 | Ed25519   |
| 81  | MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519          | ML-KEM-1024              | AES256GCM        | HKDF-SHA512 | SHA-512 | Ed25519   |
| 82  | MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_Ed25519   | ML-KEM-1024              | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | Ed25519   |
| 83  | MLS_256_XWING_AES256GCM_SHA512_Ed25519              | X-Wing                   | AES256GCM        | HKDF-SHA512 | SHA-512 | Ed25519   |
| 84  | MLS_256_XWING_CHACHA20POLY1305_SHA512_Ed25519       | X-Wing                   | CHACHA20POLY1305 | HKDF-SHA512 | SHA-512 | Ed25519   |

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
