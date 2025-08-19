import { encodeLeafNode, decodeLeafNode, LeafNode } from "../../src/leafNode"
import { createRoundtripTest } from "./roundtrip"

const minimalLeafNode: LeafNode = {
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
  leafNodeSource: "update",
  extensions: [],
  signature: new Uint8Array([]),
}

const nontrivialLeafNode: LeafNode = {
  hpkePublicKey: new Uint8Array([1, 2, 3]),
  signaturePublicKey: new Uint8Array([4, 5, 6]),
  credential: { credentialType: "basic", identity: new Uint8Array([7, 8]) },
  capabilities: {
    versions: ["mls10"],
    // ciphersuites: ["MLS_256_XWING_AES256GCM_SHA512_Ed25519"],
    ciphersuites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
    extensions: [7],
    proposals: [71],
    credentials: ["basic"],
  },
  leafNodeSource: "commit",
  parentHash: new Uint8Array([9, 10]),
  extensions: [{ extensionType: "ratchet_tree", extensionData: new Uint8Array([11, 12]) }],
  signature: new Uint8Array([13, 14]),
}

describe("LeafNode roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeLeafNode, decodeLeafNode)

  test("roundtrips minimal", () => {
    roundtrip(minimalLeafNode)
  })

  test("roundtrips nontrivial", () => {
    roundtrip(nontrivialLeafNode)
  })
})
