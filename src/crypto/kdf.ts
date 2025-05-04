import { KdfInterface } from "hpke-js"
import { utf8ToBytes } from "@noble/ciphers/utils"
import { HkdfSha256, HkdfSha384, HkdfSha512 } from "@hpke/core"
import { encodeVarLenData } from "../codec/variableLength"
import { encodeUint16, encodeUint32 } from "../codec/number"

export interface Kdf {
  extract(salt: ArrayBuffer, ikm: ArrayBuffer): Promise<ArrayBuffer>
  expand(prk: BufferSource, info: ArrayBuffer, len: number): Promise<ArrayBuffer>
  size: number
}

export type KdfAlgorithm = "HKDF-SHA256" | "HKDF-SHA384" | "HKDF-SHA512"

export function makeKdfImpl(k: KdfInterface): Kdf {
  return {
    extract(salt: ArrayBuffer, ikm: ArrayBuffer): Promise<ArrayBuffer> {
      return k.extract(salt, ikm)
    },
    expand(prk: ArrayBuffer, info: ArrayBuffer, len: number): Promise<ArrayBuffer> {
      return k.expand(prk, info, len)
    },
    size: k.hashSize,
  }
}

export function makeKdf(kdfAlg: KdfAlgorithm): KdfInterface {
  switch (kdfAlg) {
    case "HKDF-SHA256":
      return new HkdfSha256()
    case "HKDF-SHA384":
      return new HkdfSha384()
    case "HKDF-SHA512":
      return new HkdfSha512()
  }
}

export function expandWithLabel(
  secret: BufferSource,
  label: string,
  context: Uint8Array,
  length: number,
  kdf: Kdf,
): Promise<ArrayBuffer> {
  return kdf.expand(
    secret,
    new Uint8Array([
      ...encodeUint16(length),
      ...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)),
      ...encodeVarLenData(context),
    ]).buffer,
    length,
  )
}

export function deriveSecret(secret: BufferSource, label: string, kdf: Kdf): Promise<ArrayBuffer> {
  return expandWithLabel(secret, label, new Uint8Array(), kdf.size, kdf)
}

export function deriveTreeSecret(
  secret: BufferSource,
  label: string,
  generation: number,
  length: number,
  kdf: Kdf,
): Promise<ArrayBuffer> {
  return expandWithLabel(secret, label, encodeUint32(generation), length, kdf)
}
