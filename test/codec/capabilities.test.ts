import { encodeCapabilities, decodeCapabilities, Capabilities } from "../../src/capabilities"
import { createRoundtripTest } from "./roundtrip"

describe("Capabilities roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeCapabilities, decodeCapabilities)

  test("roundtrips minimal", () => {
    const c: Capabilities = {
      versions: [],
      ciphersuites: [],
      extensions: [],
      proposals: [],
      credentials: [],
    }
    roundtrip(c)
  })

  test("roundtrips nontrivial", () => {
    const c: Capabilities = {
      versions: ["mls10"],
      // ciphersuites: ["MLS_256_XWING_AES256GCM_SHA512_Ed25519"],
      ciphersuites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
      extensions: [8, 9],
      proposals: [10, 21],
      credentials: ["basic", "x509"],
    }
    roundtrip(c)
  })
})
