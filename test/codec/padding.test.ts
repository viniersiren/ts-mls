import { encodePrivateMessageContent, decodePrivateMessageContent } from "../../src/privateMessage"
import { createRoundtripTest } from "./roundtrip"

describe("PrivateMessageContent roundtrip with padding", () => {
  const roundtrip = createRoundtripTest(encodePrivateMessageContent, decodePrivateMessageContent("application"))

  test("roundtrips application with no padding", () => {
    roundtrip({
      contentType: "application",
      applicationData: new Uint8Array(),
      auth: {
        signature: new Uint8Array(),
        contentType: "application",
      },
      paddingNumberOfBytes: 0,
    })
  })

  test("roundtrips application with 64 bytes of padding", () => {
    roundtrip({
      contentType: "application",
      applicationData: new Uint8Array(),
      auth: {
        signature: new Uint8Array(),
        contentType: "application",
      },
      paddingNumberOfBytes: 64,
    })
  })

  test("roundtrips application with 256 bytes of padding", () => {
    roundtrip({
      contentType: "application",
      applicationData: new Uint8Array(),
      auth: {
        signature: new Uint8Array(),
        contentType: "application",
      },
      paddingNumberOfBytes: 256,
    })
  })

  test("roundtrips application with 5000 bytes of padding", () => {
    roundtrip({
      contentType: "application",
      applicationData: new Uint8Array(),
      auth: {
        signature: new Uint8Array(),
        contentType: "application",
      },
      paddingNumberOfBytes: 5000,
    })
  })

  test("roundtrips application with 80000 bytes of padding", () => {
    roundtrip({
      contentType: "application",
      applicationData: new Uint8Array(),
      auth: {
        signature: new Uint8Array(),
        contentType: "application",
      },
      paddingNumberOfBytes: 80000,
    })
  })

  test("fails to decode message with non-zero padding", () => {
    const encoded = encodePrivateMessageContent({
      contentType: "application",
      applicationData: new Uint8Array(),
      auth: {
        signature: new Uint8Array(),
        contentType: "application",
      },
      paddingNumberOfBytes: 2048,
    })

    expect(decodePrivateMessageContent("application")(encoded, 0)).toBeDefined()

    encoded[encoded.length - 1024] = 1

    expect(decodePrivateMessageContent("application")(encoded, 0)).toBeUndefined()
  })
})
