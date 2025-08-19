import { encodeLeafNodeData, decodeLeafNodeData, LeafNodeData } from "../../src/leafNode"
import { createRoundtripTest } from "./roundtrip"

describe("LeafNodeData roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeLeafNodeData, decodeLeafNodeData)

  test("roundtrips minimal", () => {
    const data: LeafNodeData = {
      hpkePublicKey: new Uint8Array([1, 2, 3]),
      signaturePublicKey: new Uint8Array([4, 5, 6]),
      credential: { credentialType: "basic", identity: new Uint8Array([7, 8, 9]) },
      capabilities: {
        versions: [],
        ciphersuites: [],
        extensions: [],
        proposals: [],
        credentials: [],
      },
    }
    roundtrip(data)
  })

  test("roundtrips nontrivial", () => {
    const data: LeafNodeData = {
      hpkePublicKey: new Uint8Array([10, 11, 12, 13, 14]),
      signaturePublicKey: new Uint8Array([15, 16, 17, 18, 19]),
      credential: { credentialType: "x509", certificates: [new Uint8Array([20, 21]), new Uint8Array([22, 23, 24])] },
      capabilities: {
        versions: ["mls10"],
        // ciphersuites: ["MLS_256_XWING_AES256GCM_SHA512_Ed25519"],
        ciphersuites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
        extensions: [],
        proposals: [73, 101],
        credentials: ["basic", "x509"],
      },
    }
    roundtrip(data)
  })
})
