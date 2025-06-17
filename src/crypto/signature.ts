import { ed25519 } from "@noble/curves/ed25519"
import { ed448 } from "@noble/curves/ed448"
import { p256, p384, p521 } from "@noble/curves/nist"
import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/variableLength"
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa"

export interface Signature {
  sign(signKey: Uint8Array, message: Uint8Array): Uint8Array
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean
  keygen(): { publicKey: Uint8Array; signKey: Uint8Array }
}

export type SignatureAlgorithm = "Ed25519" | "Ed448" | "P256" | "P384" | "P521" | "ML-DSA-87"

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
        case "ML-DSA-87":
          return ml_dsa87.sign(signKey, message)
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
        case "ML-DSA-87":
          return ml_dsa87.verify(publicKey, message, signature)
      }
    },
    keygen() {
      switch (alg) {
        case "Ed25519": {
          const signKey = ed25519.utils.randomPrivateKey()
          return { signKey, publicKey: ed25519.getPublicKey(signKey) }
        }
        case "Ed448": {
          const signKey = ed448.utils.randomPrivateKey()
          return { signKey, publicKey: ed448.getPublicKey(signKey) }
        }
        case "P256": {
          const signKey = p256.utils.randomPrivateKey()
          return { signKey, publicKey: p256.getPublicKey(signKey) }
        }
        case "P384": {
          const signKey = p384.utils.randomPrivateKey()
          return { signKey, publicKey: p384.getPublicKey(signKey) }
        }
        case "P521": {
          const signKey = p521.utils.randomPrivateKey()
          return { signKey, publicKey: p521.getPublicKey(signKey) }
        }
        case "ML-DSA-87": {
          const keys = ml_dsa87.keygen(crypto.getRandomValues(new Uint8Array(32)))
          return { signKey: keys.secretKey, publicKey: keys.publicKey }
        }
      }
    },
  }
}
