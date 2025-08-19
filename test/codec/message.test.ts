import { encodeMlsMessage, decodeMlsMessage } from "../../src/message"
import { createRoundtripTest } from "./roundtrip"

describe("MLSMessage roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeMlsMessage, decodeMlsMessage)

  test("roundtrips public message", () => {
    roundtrip({
      version: "mls10",
      wireformat: "mls_public_message",
      publicMessage: {
        content: {
          contentType: "application",
          groupId: new Uint8Array([1]),
          epoch: 0n,
          sender: { senderType: "member", leafIndex: 0 },
          authenticatedData: new Uint8Array([2]),
          applicationData: new Uint8Array([3]),
        },
        auth: { contentType: "application", signature: new Uint8Array([4, 5, 6]) },
        senderType: "member",
        membershipTag: new Uint8Array([7, 8, 9]),
      },
    })
  })

  test("roundtrips private message", () => {
    roundtrip({
      version: "mls10",
      wireformat: "mls_private_message",
      privateMessage: {
        contentType: "proposal",
        groupId: new Uint8Array([1]),
        epoch: 0n,
        authenticatedData: new Uint8Array([2, 3]),
        encryptedSenderData: new Uint8Array([4, 5, 6]),
        ciphertext: new Uint8Array([7, 8, 9]),
      },
    })
  })

  test("roundtrips key package message", () => {
    roundtrip({
      version: "mls10",
      wireformat: "mls_key_package",
      keyPackage: {
        version: "mls10",
        // cipherSuite: "MLS_256_XWING_AES256GCM_SHA512_Ed25519",
        cipherSuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        initKey: new Uint8Array([]),
        leafNode: {
          hpkePublicKey: new Uint8Array([]),
          signaturePublicKey: new Uint8Array([]),
          credential: { credentialType: "basic", identity: new Uint8Array([]) },
          capabilities: {
            versions: [],
            ciphersuites: [],
            extensions: [],
            proposals: [],
            credentials: [],
          },
          leafNodeSource: "key_package",
          lifetime: { notBefore: 0n, notAfter: 0n },
          extensions: [],
          signature: new Uint8Array([]),
        },
        extensions: [],
        signature: new Uint8Array([]),
      },
    })
  })

  test("roundtrips welcome", () => {
    roundtrip({
      version: "mls10",
      wireformat: "mls_welcome",
      welcome: {
        cipherSuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        secrets: [],
        encryptedGroupInfo: new Uint8Array([1]),
      },
    })
  })

  test("roundtrips group info message", () => {
    roundtrip({
      version: "mls10",
      wireformat: "mls_group_info",
      groupInfo: {
        groupContext: {
          version: "mls10",
          // cipherSuite: "MLS_256_XWING_AES256GCM_SHA512_Ed25519",
          cipherSuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
          groupId: new Uint8Array([1, 2, 3]),
          epoch: 0n,
          treeHash: new Uint8Array([4, 5]),
          confirmedTranscriptHash: new Uint8Array([6]),
          extensions: [],
        },
        extensions: [],
        confirmationTag: new Uint8Array([7, 8]),
        signer: 0,
        signature: new Uint8Array([9]),
      },
    })
  })
})
