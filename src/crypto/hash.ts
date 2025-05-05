import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/variableLength"

export type HashAlgorithm = "SHA-512" | "SHA-384" | "SHA-256"

export function makeHashImpl(sc: SubtleCrypto, h: HashAlgorithm): Hash {
  return {
    digest(data) {
      return sc.digest(h, data)
    },
    async mac(key, data) {
      return sc.sign("HMAC", await importMacKey(key, h), data)
    },
    async verifyMac(key, mac, data) {
      return sc.verify("HMAC", await importMacKey(key, h), mac, data)
    },
  }
}

function importMacKey(rawKey: Uint8Array, h: HashAlgorithm): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    rawKey,
    {
      name: "HMAC",
      hash: { name: h },
    },
    false,
    ["sign", "verify"],
  )
}

export interface Hash {
  digest(data: BufferSource): Promise<ArrayBuffer>
  mac(key: Uint8Array, data: BufferSource): Promise<ArrayBuffer>
  verifyMac(key: Uint8Array, mac: BufferSource, data: BufferSource): Promise<boolean>
}

export function refhash(label: string, value: Uint8Array, h: Hash) {
  return h.digest(encodeRefHash(label, value))
}

function encodeRefHash(label: string, value: Uint8Array) {
  const labelBytes = utf8ToBytes(label)
  return new Uint8Array([...encodeVarLenData(labelBytes), ...encodeVarLenData(value)])
}
