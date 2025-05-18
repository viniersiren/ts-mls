import { CipherSuite } from "hpke-js"
import { AeadAlgorithm, decryptAead, encryptAead, makeAead } from "./aead"
import { KdfAlgorithm, makeKdf } from "./kdf"
import { KemAlgorithm, makeDhKem } from "./kem"
import { PrivateKey, PublicKey } from "./ciphersuite"
import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/variableLength"
import { bytesToBuffer } from "../util/byteArray"

export type HpkeAlgorithm = {
  kem: KemAlgorithm
  kdf: KdfAlgorithm
  aead: AeadAlgorithm
}

export function encryptWithLabel(
  publicKey: PublicKey,
  label: string,
  context: Uint8Array,
  plaintext: Uint8Array,
  hpke: Hpke,
): Promise<{ ct: Uint8Array; enc: Uint8Array }> {
  return hpke.seal(
    publicKey,
    plaintext,
    new Uint8Array([...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)), ...encodeVarLenData(context)]),
    new Uint8Array(),
  )
}

export function decryptWithLabel(
  privateKey: PrivateKey,
  label: string,
  context: Uint8Array,
  kemOutput: Uint8Array,
  ciphertext: Uint8Array,
  hpke: Hpke,
): Promise<Uint8Array> {
  return hpke.open(
    privateKey,
    kemOutput,
    ciphertext,
    new Uint8Array([...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)), ...encodeVarLenData(context)]),
  )
}

export function makeHpke(hpkealg: HpkeAlgorithm): Hpke {
  const cs = new CipherSuite({
    kem: makeDhKem(hpkealg.kem),
    kdf: makeKdf(hpkealg.kdf),
    aead: makeAead(hpkealg.aead),
  })

  return {
    async open(privateKey, kemOutput, ciphertext, info, aad) {
      const result = await cs.open(
        { recipientKey: privateKey, enc: bytesToBuffer(kemOutput), info: bytesToBuffer(info) },
        bytesToBuffer(ciphertext),
        aad ? bytesToBuffer(aad) : new ArrayBuffer(),
      )
      return new Uint8Array(result)
    },
    async seal(publicKey, plaintext, info, aad) {
      const result = await cs.seal(
        { recipientPublicKey: publicKey, info: bytesToBuffer(info) },
        bytesToBuffer(plaintext),
        aad ? bytesToBuffer(aad) : new ArrayBuffer(),
      )
      return {
        ct: new Uint8Array(result.ct),
        enc: new Uint8Array(result.enc),
      }
    },
    async importPrivateKey(k) {
      return (await cs.kem.deserializePrivateKey(bytesToBuffer(k))) as PrivateKey
    },
    async importPublicKey(k) {
      return (await cs.kem.deserializePublicKey(bytesToBuffer(k))) as PublicKey
    },
    async exportPublicKey(k) {
      return new Uint8Array(await cs.kem.serializePublicKey(k))
    },
    async exportPrivateKey(k) {
      return new Uint8Array(await cs.kem.serializePrivateKey(k))
    },
    async encryptAead(key, nonce, aad, plaintext) {
      return encryptAead(key, nonce, aad ? aad : new Uint8Array(), plaintext, hpkealg.aead)
    },
    async decryptAead(key, nonce, aad, ciphertext) {
      return decryptAead(key, nonce, aad ? aad : new Uint8Array(), ciphertext, hpkealg.aead)
    },
    async deriveKeyPair(ikm) {
      const kp = await cs.kem.deriveKeyPair(bytesToBuffer(ikm))
      return { privateKey: kp.privateKey as PrivateKey, publicKey: kp.publicKey as PublicKey }
    },
    keyLength: cs.aead.keySize,
    nonceLength: cs.aead.nonceSize,
  }
}

export interface Hpke {
  open(
    privateKey: PrivateKey,
    kemOutput: Uint8Array,
    ciphertext: Uint8Array,
    info: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array>
  seal(
    publicKey: PublicKey,
    plaintext: Uint8Array,
    info: Uint8Array,
    aad?: Uint8Array,
  ): Promise<{ ct: Uint8Array; enc: Uint8Array }>
  importPrivateKey(k: Uint8Array): Promise<PrivateKey>
  importPublicKey(k: Uint8Array): Promise<PublicKey>
  exportPublicKey(k: PublicKey): Promise<Uint8Array>
  exportPrivateKey(k: PrivateKey): Promise<Uint8Array>
  encryptAead(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array | undefined,
    plaintext: Uint8Array,
  ): Promise<Uint8Array>
  decryptAead(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array | undefined,
    ciphertext: Uint8Array,
  ): Promise<Uint8Array>
  deriveKeyPair(ikm: Uint8Array): Promise<{ privateKey: PrivateKey; publicKey: PublicKey }>
  keyLength: number
  nonceLength: number
}
