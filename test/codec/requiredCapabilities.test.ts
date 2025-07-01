import {
  encodeRequiredCapabilities,
  decodeRequiredCapabilities,
  RequiredCapabilities,
} from "../../src/requiredCapabilities"
import { createRoundtripTest } from "./roundtrip"

describe("RequiredCapabilities roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeRequiredCapabilities, decodeRequiredCapabilities)

  it("roundtrips empty arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: [],
      proposalTypes: [],
      credentialTypes: [],
    }
    roundtrip(rc)
  })

  it("roundtrips non-empty arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: [7, 8],
      proposalTypes: [9, 10, 11],
      credentialTypes: ["basic", "x509"],
    }
    roundtrip(rc)
  })

  it("roundtrips single-element arrays", () => {
    const rc: RequiredCapabilities = {
      extensionTypes: [8],
      proposalTypes: [9],
      credentialTypes: ["basic"],
    }
    roundtrip(rc)
  })
})
