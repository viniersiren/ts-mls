import { CiphersuiteImpl, getCiphersuiteFromName, getCiphersuiteFromId } from "./ciphersuite"
import { makeNobleHashImpl } from "./nobleHash"
import { makeKdfImpl, makeKdf } from "./kdf"
import { makeNobleSignatureImpl } from "./signature"
import { makeHpke } from "./hpke"
import { nobleRng } from "./nobleRng"

/**
 * Creates a complete noble-based ciphersuite implementation
 * This replaces all WebCrypto dependencies with noble implementations
 */
export async function getNobleCiphersuiteImpl(cs: Parameters<typeof getCiphersuiteFromId>[0]): Promise<CiphersuiteImpl> {
  // Get the actual ciphersuite configuration
  const ciphersuite = getCiphersuiteFromId(cs)

  return {
    kdf: makeKdfImpl(makeKdf(ciphersuite.hpke.kdf)),
    hash: makeNobleHashImpl(ciphersuite.hash),
    signature: await makeNobleSignatureImpl(ciphersuite.signature),
    hpke: await makeHpke(ciphersuite.hpke),
    rng: nobleRng,
    name: ciphersuite.name,
  }
}

/**
 * Alternative function that accepts a ciphersuite name and returns the noble implementation
 */
export async function getNobleCiphersuiteImplByName(name: string): Promise<CiphersuiteImpl> {
  const ciphersuite = getCiphersuiteFromName(name as any)
  return getNobleCiphersuiteImpl(ciphersuite as any)
}

/**
 * Factory function to create noble crypto implementations
 * This can be used to create custom crypto providers
 */
export class NobleCryptoProvider {
  static async createCiphersuiteImpl(cs: Parameters<typeof getCiphersuiteFromId>[0]): Promise<CiphersuiteImpl> {
    return getNobleCiphersuiteImpl(cs)
  }

  static getRng() {
    return nobleRng
  }

  static async getHash(algorithm: "SHA-512" | "SHA-384" | "SHA-256") {
    return makeNobleHashImpl(algorithm)
  }

  static async getKdf(algorithm: "HKDF-SHA256" | "HKDF-SHA384" | "HKDF-SHA512") {
    return makeKdfImpl(makeKdf(algorithm))
  }

  static async getSignature(algorithm: "Ed25519" | "Ed448" | "P256" | "P384" | "P521" | "ML-DSA-87") {
    return makeNobleSignatureImpl(algorithm)
  }

  static async getHpke(kem: string, kdf: string, aead: string) {
    return makeHpke({ kem: kem as any, kdf: kdf as any, aead: aead as any })
  }
}