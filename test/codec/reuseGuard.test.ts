import { encodeReuseGuard, decodeReuseGuard, ReuseGuard } from "../../src/sender"
import { createRoundtripTest } from "./roundtrip"

describe("ReuseGuard roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeReuseGuard, decodeReuseGuard)

  test("roundtrips", () => {
    roundtrip(new Uint8Array([1, 2, 3, 4]) as ReuseGuard)
  })
})
