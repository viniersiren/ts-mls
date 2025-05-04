import { makeNobleSignatureImpl, Signature, SignatureAlgorithm } from "./signature"
import { Hash, HashAlgorithm, makeHashImpl } from "./hash"
import { Kdf, makeKdf, makeKdfImpl } from "./kdf"
import { Hpke, HpkeAlgorithm, makeHpke, makeHpkeCiphersuite } from "./hpke"
import { contramapEncoder, Encoder } from "../codec/tlsEncoder"
import { decodeUint16, encodeUint16 } from "../codec/number"
import { Decoder, mapDecoderOption } from "../codec/tlsDecoder"
import { enumNumberToKey } from "../util/enumHelpers"

export type CiphersuiteImpl = {
  hash: Hash
  hpke: Hpke
  signature: Signature
  kdf: Kdf
}

const ciphersuites = {
  MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519: 1,
  MLS_128_DHKEMP256_AES128GCM_SHA256_P256: 2,
  MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519: 3,
  MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448: 4,
  MLS_256_DHKEMP521_AES256GCM_SHA512_P521: 5,
  MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448: 6,
  MLS_256_DHKEMP384_AES256GCM_SHA384_P384: 7,
} as const

export type CiphersuiteName = keyof typeof ciphersuites
export type CiphersuiteId = (typeof ciphersuites)[CiphersuiteName]

export const encodeCiphersuite: Encoder<CiphersuiteName> = contramapEncoder(encodeUint16, (t) => ciphersuites[t])

export const decodeCiphersuite: Decoder<CiphersuiteName> = mapDecoderOption(decodeUint16, enumNumberToKey(ciphersuites))

export function getCiphersuite(name: CiphersuiteName): Ciphersuite {
  return ciphersuiteValues[ciphersuites[name]]
}

export function getCiphersuiteFromId(id: CiphersuiteId): Ciphersuite {
  return ciphersuiteValues[id]
}

export function getCiphersuiteImpl(cs: Ciphersuite): CiphersuiteImpl {
  const sc = crypto.subtle
  return {
    kdf: makeKdfImpl(makeKdf(cs.hpke.kdf)),
    hash: makeHashImpl(sc, cs.hash),
    signature: makeNobleSignatureImpl(cs.signature),
    hpke: makeHpke(makeHpkeCiphersuite(cs.hpke)),
  }
}

const ciphersuiteValues: Record<CiphersuiteId, Ciphersuite> = {
  1: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-X25519-HKDF-SHA256",
      aead: "AES128GCM",
      kdf: "HKDF-SHA256",
    },
    signature: "Ed25519",
  },
  2: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-P256-HKDF-SHA256",
      aead: "AES128GCM",
      kdf: "HKDF-SHA256",
    },
    signature: "P256",
  },
  3: {
    hash: "SHA-256",
    hpke: {
      kem: "DHKEM-X25519-HKDF-SHA256",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA256",
    },
    signature: "Ed25519",
  },
  4: {
    hash: "SHA-512",
    hpke: {
      kem: "DHKEM-X448-HKDF-SHA512",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed448",
  },
  5: {
    hash: "SHA-512",
    hpke: {
      kem: "DHKEM-P521-HKDF-SHA512",
      aead: "AES256GCM",
      kdf: "HKDF-SHA512",
    },
    signature: "P521",
  },
  6: {
    hash: "SHA-512",
    hpke: {
      kem: "DHKEM-X448-HKDF-SHA512",
      aead: "CHACHA20POLY1305",
      kdf: "HKDF-SHA512",
    },
    signature: "Ed448",
  },
  7: {
    hash: "SHA-384",
    hpke: {
      kem: "DHKEM-P384-HKDF-SHA384",
      aead: "AES256GCM",
      kdf: "HKDF-SHA384",
    },
    signature: "P384",
  },
} as const

type Ciphersuite = {
  hash: HashAlgorithm
  hpke: HpkeAlgorithm
  signature: SignatureAlgorithm
}

export type PublicKey = CryptoKey & { type: "public" }
export type SecretKey = CryptoKey & { type: "secret" }
export type PrivateKey = CryptoKey & { type: "prviate" }
