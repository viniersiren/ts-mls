import { Decoder } from "../../src/codec/tlsDecoder"
import { Encoder } from "../../src/codec/tlsEncoder"

function roundtripTest<T>(t: T, enc: Encoder<T>, dec: Decoder<T>) {
  const encoded = enc(t)

  const decoded = dec(encoded, 0)?.[0] as T

  expect(decoded).toStrictEqual(t)
}

export function createRoundtripTest<T>(enc: Encoder<T>, dec: Decoder<T>): (t: T) => void {
  return (t) => {
    const encoded = enc(t)

    const decoded = dec(encoded, 0)?.[0] as T

    expect(decoded).toStrictEqual(t)
  }
}
