import { randomBytes } from "@noble/ciphers/webcrypto"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "../../src/codec/variableLength"
import { createRoundtripTest } from "./roundtrip"
import { Encoder } from "../../src/codec/tlsEncoder"
import { Decoder } from "../../src/codec/tlsDecoder"
import { decodeUint64, decodeUint8, encodeUint64, encodeUint8 } from "../../src/codec/number"
import { decodeOptional, encodeOptional } from "../../src/codec/optional"

test("encode and decode works for 1 random byte", () => {
  varLenRoundtrip(randomBytes(1))
})

test("encode and decode works for 2 random bytes", () => {
  varLenRoundtrip(randomBytes(2))
})

test("encode and decode works for 3 random bytes", () => {
  varLenRoundtrip(randomBytes(3))
})

test("encode and decode works for 4 random bytes", () => {
  varLenRoundtrip(randomBytes(4))
})

test("encode and decode works for 8 random bytes", () => {
  varLenRoundtrip(randomBytes(8))
})

test("encode and decode works for 16 random bytes", () => {
  varLenRoundtrip(randomBytes(16))
})

test("encode and decode works for 64 random bytes", () => {
  varLenRoundtrip(randomBytes(64))
})

test("encode and decode works for 256 random bytes", () => {
  varLenRoundtrip(randomBytes(256))
})

test("encode and decode works for 1024 random bytes", () => {
  varLenRoundtrip(randomBytes(1024))
})

test("encode and decode works for 9999 random bytes", () => {
  varLenRoundtrip(randomBytes(9999))
})

test("encode and decode works for 9999 random bytes", () => {
  varLenRoundtrip(randomBytes(9999))
})

test("encode and decode works for array of random bytes", () => {
  arrayRoundtrip(encodeVarLenData, decodeVarLenData, [
    randomBytes(9999),
    randomBytes(9999),
    randomBytes(9999),
    randomBytes(9999),
  ])
})

test("encode and decode works for array of uint8", () => {
  arrayRoundtrip(encodeUint8, decodeUint8, [1, 2, 3, 4, 5])
})

test("encode and decode works for array of uint64", () => {
  arrayRoundtrip(encodeUint64, decodeUint64, [1n, 2n, 3n, 4n, 5n, 3945349583495384533409534n])
})

test("encode and decode works for array of optional random bytes", () => {
  arrayRoundtrip(encodeOptional(encodeVarLenData), decodeOptional(decodeVarLenData), [
    randomBytes(99),
    undefined,
    randomBytes(99),
    undefined,
    undefined,
    randomBytes(99),
    randomBytes(99),
  ])
})

const varLenRoundtrip = createRoundtripTest(encodeVarLenData, decodeVarLenData)

function arrayRoundtrip<T>(enc: Encoder<T>, dec: Decoder<T>, ts: T[]) {
  return createRoundtripTest(encodeVarLenType(enc), decodeVarLenType(dec))
}
