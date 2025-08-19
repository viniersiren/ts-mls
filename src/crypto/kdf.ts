import { KdfInterface, KdfId, KemId, CipherSuite, AeadId } from "hpke-js"
import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/variableLength"
import { encodeUint16, encodeUint32 } from "../codec/number"
import { bytesToBuffer } from "../util/byteArray"

export interface Kdf {
  extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>
  expand(prk: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array>
  size: number
}

export type KdfAlgorithm = "HKDF-SHA256" | "HKDF-SHA384" | "HKDF-SHA512"

export function makeKdfImpl(k: KdfInterface): Kdf {
  return {
    async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
      const result = await k.extract(bytesToBuffer(salt), bytesToBuffer(ikm))
      return new Uint8Array(result)
    },
    async expand(prk: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
      const result = await k.expand(bytesToBuffer(prk), bytesToBuffer(info), len)
      return new Uint8Array(result)
    },
    size: k.hashSize,
  }
}

export function makeKdf(kdfAlg: KdfAlgorithm): KdfInterface {
  switch (kdfAlg) {
    case "HKDF-SHA256":
      return new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      }).kdf
    case "HKDF-SHA384":
      return new CipherSuite({
        kem: KemId.DhkemP384HkdfSha384,
        kdf: KdfId.HkdfSha384,
        aead: AeadId.Aes128Gcm,
      }).kdf
    case "HKDF-SHA512":
      return new CipherSuite({
        kem: KemId.DhkemP521HkdfSha512,
        kdf: KdfId.HkdfSha512,
        aead: AeadId.Aes128Gcm,
      }).kdf
  }
}

export function expandWithLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
  kdf: Kdf,
): Promise<Uint8Array> {
  return kdf.expand(
    secret,
    new Uint8Array([
      ...encodeUint16(length),
      ...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)),
      ...encodeVarLenData(context),
    ]),
    length,
  )
}

export async function deriveSecret(secret: Uint8Array, label: string, kdf: Kdf): Promise<Uint8Array> {
  return expandWithLabel(secret, label, new Uint8Array(), kdf.size, kdf)
}

export async function deriveTreeSecret(
  secret: Uint8Array,
  label: string,
  generation: number,
  length: number,
  kdf: Kdf,
): Promise<Uint8Array> {
  return expandWithLabel(secret, label, encodeUint32(generation), length, kdf)
}
