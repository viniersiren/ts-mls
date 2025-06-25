import { encodeExtensionType, decodeExtensionType, ExtensionTypeName } from "../../src/extensionType"
import { createRoundtripTest } from "./roundtrip"

describe("ExtensionTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeExtensionType, decodeExtensionType)

  test("roundtrips application_id", () => {
    roundtrip("application_id" as ExtensionTypeName)
  })

  test("roundtrips external_senders", () => {
    roundtrip("external_senders" as ExtensionTypeName)
  })
})
