import { encodeVarLenData } from "../codec/variableLength"
import { webCryptoRng } from "./rng"
// Static imports for @noble packages since they are now regular dependencies
import { ed25519 } from "@noble/curves/ed25519"
import { ed448 } from "@noble/curves/ed448"
import { p256, p384, p521 } from "@noble/curves/nist"
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa"

export interface Signature {
  sign(signKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>
  keygen(): Promise<{ publicKey: Uint8Array; signKey: Uint8Array }>
}

export type SignatureAlgorithm = "Ed25519" | "Ed448" | "P256" | "P384" | "P521" | "ML-DSA-87"

export async function signWithLabel(
  signKey: Uint8Array,
  label: string,
  content: Uint8Array,
  s: Signature,
): Promise<Uint8Array> {
  return s.sign(
    signKey,
    new Uint8Array([...encodeVarLenData(new TextEncoder().encode(`MLS 1.0 ${label}`)), ...encodeVarLenData(content)]),
  )
}

export async function verifyWithLabel(
  publicKey: Uint8Array,
  label: string,
  content: Uint8Array,
  signature: Uint8Array,
  s: Signature,
): Promise<boolean> {
  return s.verify(
    publicKey,
    new Uint8Array([...encodeVarLenData(new TextEncoder().encode(`MLS 1.0 ${label}`)), ...encodeVarLenData(content)]),
    signature,
  )
}

export async function makeNobleSignatureImpl(alg: SignatureAlgorithm): Promise<Signature> {
  switch (alg) {
    case "Ed25519":
      return {
        async sign(signKey, message) {
          return ed25519.sign(message, signKey)
        },
        async verify(publicKey, message, signature) {
          return ed25519.verify(signature, message, publicKey)
        },
        async keygen() {
          const signKey = ed25519.utils.randomPrivateKey()
          return { signKey, publicKey: ed25519.getPublicKey(signKey) }
        },
      }

    case "Ed448":
      return {
        async sign(signKey, message) {
          return ed448.sign(message, signKey)
        },
        async verify(publicKey, message, signature) {
          return ed448.verify(signature, message, publicKey)
        },
        async keygen() {
          const signKey = ed448.utils.randomPrivateKey()
          return { signKey, publicKey: ed448.getPublicKey(signKey) }
        },
      }

    case "P256":
      return {
        async sign(signKey, message) {
          return p256.sign(message, signKey, { prehash: true }).toCompactRawBytes()
        },
        async verify(publicKey, message, signature) {
          return p256.verify(signature, message, publicKey, { prehash: true })
        },
        async keygen() {
          const signKey = p256.utils.randomPrivateKey()
          return { signKey, publicKey: p256.getPublicKey(signKey) }
        },
      }
    case "P384":
      return {
        async sign(signKey, message) {
          return p384.sign(message, signKey, { prehash: true }).toCompactRawBytes()
        },
        async verify(publicKey, message, signature) {
          return p384.verify(signature, message, publicKey, { prehash: true })
        },
        async keygen() {
          const signKey = p384.utils.randomPrivateKey()
          return { signKey, publicKey: p384.getPublicKey(signKey) }
        },
      }
    case "P521":
      return {
        async sign(signKey, message) {
          return p521.sign(message, signKey, { prehash: true }).toCompactRawBytes()
        },
        async verify(publicKey, message, signature) {
          return p521.verify(signature, message, publicKey, { prehash: true })
        },
        async keygen() {
          const signKey = p521.utils.randomPrivateKey()
          return { signKey, publicKey: p521.getPublicKey(signKey) }
        },
      }
    case "ML-DSA-87":
      return {
        async sign(signKey, message) {
          return ml_dsa87.sign(signKey, message)
        },
        async verify(publicKey, message, signature) {
          return ml_dsa87.verify(publicKey, message, signature)
        },
        async keygen() {
          const keys = ml_dsa87.keygen(webCryptoRng.randomBytes(32))
          return { signKey: keys.secretKey, publicKey: keys.publicKey }
        },
      }
  }
}
