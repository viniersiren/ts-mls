import { encodeProtocolVersion, decodeProtocolVersion, ProtocolVersionName } from "../../src/protocolVersion"
import { createRoundtripTest } from "./roundtrip"

describe("ProtocolVersionName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeProtocolVersion, decodeProtocolVersion)

  test("roundtrips mls10", () => {
    roundtrip("mls10" as ProtocolVersionName)
  })
})
