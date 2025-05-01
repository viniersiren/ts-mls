import { KdfInterface } from "hpke-js"
import { utf8ToBytes } from "@noble/ciphers/utils"
import { HkdfSha256, HkdfSha384, HkdfSha512 } from "@hpke/core"
import { encodeVarLenData } from "../codec/vector"

export interface Kdf {
  extract(salt: ArrayBuffer, ikm: ArrayBuffer): Promise<ArrayBuffer>
  expand(prk: BufferSource, info: ArrayBuffer, len: number): Promise<ArrayBuffer>
  keysize: number
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
    keysize: k.hashSize,
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
      ...lengthToBytes(length),
      ...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)),
      ...encodeVarLenData(context),
    ]).buffer,
    length,
  )
}

function lengthToBytes(length: number): Uint8Array {
  const buffer = new ArrayBuffer(2)
  const view = new DataView(buffer)
  view.setUint16(0, length)
  return new Uint8Array(buffer)
}

function generationToBytes(generation: number): Uint8Array {
  const buffer = new ArrayBuffer(4)
  const view = new DataView(buffer)
  view.setUint32(0, generation)
  return new Uint8Array(buffer)
}

export function deriveSecret(secret: BufferSource, label: string, kdf: Kdf): Promise<ArrayBuffer> {
  return expandWithLabel(secret, label, new Uint8Array(), kdf.keysize, kdf)
}

export function deriveTreeSecret(
  secret: BufferSource,
  label: string,
  generation: number,
  kdf: Kdf,
): Promise<ArrayBuffer> {
  return expandWithLabel(secret, label, generationToBytes(generation), kdf.keysize, kdf)
}
