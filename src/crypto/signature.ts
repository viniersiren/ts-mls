import { ed25519 } from "@noble/curves/ed25519"
import { ed448 } from "@noble/curves/ed448"
import { p256, p384, p521 } from "@noble/curves/nist"
import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/variableLength"

export interface Signature {
  sign(signKey: Uint8Array, message: Uint8Array): Uint8Array
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean
}

export type SignatureAlgorithm = "Ed25519" | "Ed448" | "P256" | "P384" | "P521"

export function signWithLabel(signKey: Uint8Array, label: string, content: Uint8Array, s: Signature): Uint8Array {
  return s.sign(
    signKey,
    new Uint8Array([...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)), ...encodeVarLenData(content)]),
  )
}

export function verifyWithLabel(
  publicKey: Uint8Array,
  label: string,
  content: Uint8Array,
  signature: Uint8Array,
  s: Signature,
): boolean {
  return s.verify(
    publicKey,
    new Uint8Array([...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)), ...encodeVarLenData(content)]),
    signature,
  )
}

export function makeNobleSignatureImpl(alg: SignatureAlgorithm): Signature {
  return {
    sign(signKey, message) {
      switch (alg) {
        case "Ed25519":
          return ed25519.sign(message, signKey)
        case "Ed448":
          return ed448.sign(message, signKey)
        case "P256":
          return p256.sign(message, signKey, { prehash: true }).toCompactRawBytes()
        case "P384":
          return p384.sign(message, signKey, { prehash: true }).toCompactRawBytes()
        case "P521":
          return p521.sign(message, signKey, { prehash: true }).toCompactRawBytes()
      }
    },
    verify(publicKey, message, signature) {
      switch (alg) {
        case "Ed25519":
          return ed25519.verify(signature, message, publicKey)
        case "Ed448":
          return ed448.verify(signature, message, publicKey)
        case "P256":
          return p256.verify(signature, message, publicKey, { prehash: true })
        case "P384":
          return p384.verify(signature, message, publicKey, { prehash: true })
        case "P521":
          return p521.verify(signature, message, publicKey, { prehash: true })
      }
    },
  }
}
