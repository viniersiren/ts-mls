import json from "../../test_vectors/deserialization.json"
import { bytesToHex, hexToBytes } from "@noble/ciphers/utils"
import { decodeVarLenData, determineLength, encodeVarLenData } from "../../src/codec/vector"

function varLenRoundtrip(header: string, len: number) {
  const { length } = determineLength(hexToBytes(header))
  expect(length).toBe(len)
}

test("deserialization test vectors", () => {
  for (const x of json) {
    varLenRoundtrip(x.vlbytes_header, x.length)
  }
})
