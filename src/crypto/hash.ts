import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/variableLength"
import { sha256, sha384, sha512 } from '@noble/hashes/sha2'
import { hmac } from '@noble/hashes/hmac'

export type HashAlgorithm = "SHA-512" | "SHA-384" | "SHA-256"

export function makeHashImpl(_sc: SubtleCrypto | null, h: HashAlgorithm): Hash {
  return {
    async digest(data) {
      switch (h) {
        case "SHA-256":
          return sha256(data)
        case "SHA-384":
          return sha384(data)
        case "SHA-512":
          return sha512(data)
        default:
          throw new Error(`Unsupported hash algorithm: ${h}`)
      }
    },
    async mac(key, data) {
      switch (h) {
        case "SHA-256":
          return hmac(sha256, key, data)
        case "SHA-384":
          return hmac(sha384, key, data)
        case "SHA-512":
          return hmac(sha512, key, data)
        default:
          throw new Error(`Unsupported hash algorithm: ${h}`)
      }
    },
    async verifyMac(key, mac, data) {
      const expectedMac = await this.mac(key, data)
      return mac.length === expectedMac.length &&
             mac.every((byte, i) => byte === expectedMac[i])
    },
  }
}

export interface Hash {
  digest(data: Uint8Array): Promise<Uint8Array>
  mac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>
  verifyMac(key: Uint8Array, mac: Uint8Array, data: Uint8Array): Promise<boolean>
}

export function refhash(label: string, value: Uint8Array, h: Hash) {
  return h.digest(encodeRefHash(label, value))
}

function encodeRefHash(label: string, value: Uint8Array) {
  const labelBytes = utf8ToBytes(label)
  return new Uint8Array([...encodeVarLenData(labelBytes), ...encodeVarLenData(value)])
}
