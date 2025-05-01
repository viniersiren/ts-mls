import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/vector"

export type HashAlgorithm = "SHA-512" | "SHA-384" | "SHA-256"

export function makeHashImpl(sc: SubtleCrypto, h: HashAlgorithm): Hash {
  return {
    digest(data) {
      return sc.digest(h, data)
    },
  }
}

export interface Hash {
  digest(data: BufferSource): Promise<ArrayBuffer>
}

export function refhash(label: string, value: Uint8Array, h: Hash) {
  return h.digest(encodeRefHash(label, value))
}

function encodeRefHash(label: string, value: Uint8Array) {
  const labelBytes = utf8ToBytes(label)
  return new Uint8Array([...encodeVarLenData(labelBytes), ...encodeVarLenData(value)])
}
