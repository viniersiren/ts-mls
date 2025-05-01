import { randomBytes } from "@noble/ciphers/webcrypto"
import { bytesToHex } from "@noble/ciphers/utils"
import { decodeVarLenData, encodeVarLenData } from "../src/codec/vector"

function varLenRoundtrip(source: Uint8Array) {
  const encoded = encodeVarLenData(source)

  const decoded = decodeVarLenData(encoded, 0)

  expect(bytesToHex(decoded.data)).toBe(bytesToHex(source))
}

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
