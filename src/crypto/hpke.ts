import { CipherSuite, CipherSuiteSealResponse } from "hpke-js"
import { AeadAlgorithm, decryptAead, encryptAead, makeAead } from "./aead"
import { KdfAlgorithm, makeKdf } from "./kdf"
import { KemAlgorithm, makeDhKem } from "./kem"
import { PrivateKey, PublicKey } from "./ciphersuite"
import { utf8ToBytes } from "@noble/ciphers/utils"
import { encodeVarLenData } from "../codec/variableLength"

export type HpkeAlgorithm = {
  kem: KemAlgorithm
  kdf: KdfAlgorithm
  aead: AeadAlgorithm
}

export function encryptWithLabel(
  publicKey: PublicKey,
  label: string,
  context: Uint8Array,
  plaintext: ArrayBuffer,
  hpke: Hpke,
): Promise<CipherSuiteSealResponse> {
  return hpke.seal(
    publicKey,
    plaintext,
    new Uint8Array([...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)), ...encodeVarLenData(context)]).buffer,
    new ArrayBuffer(),
  )
}

export function decryptWithLabel(
  privateKey: PrivateKey,
  label: string,
  context: Uint8Array,
  kemOutput: ArrayBuffer,
  ciphertext: ArrayBuffer,
  hpke: Hpke,
): Promise<ArrayBuffer> {
  return hpke.open(
    privateKey,
    kemOutput,
    ciphertext,
    new Uint8Array([...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)), ...encodeVarLenData(context)]).buffer,
  )
}

export function makeHpke(hpkealg: HpkeAlgorithm): Hpke {
  const cs = new CipherSuite({
    kem: makeDhKem(hpkealg.kem),
    kdf: makeKdf(hpkealg.kdf),
    aead: makeAead(hpkealg.aead),
  })

  return {
    open(privateKey, kemOutput, ciphertext, info, aad) {
      return cs.open({ recipientKey: privateKey, enc: kemOutput, info: info }, ciphertext, aad)
    },
    seal(publicKey, plaintext, info, aad) {
      return cs.seal({ recipientPublicKey: publicKey, info: info }, plaintext, aad)
    },
    async importPrivateKey(k) {
      return (await cs.kem.deserializePrivateKey(k)) as PrivateKey
    },
    async importPublicKey(k) {
      return (await cs.kem.deserializePublicKey(k)) as PublicKey
    },
    exportPublicKey(k) {
      return cs.kem.serializePublicKey(k)
    },
    async encryptAead(key, nonce, aad, plaintext) {
      return encryptAead(key, nonce, aad, plaintext, hpkealg.aead)
    },
    async decryptAead(key, nonce, aad, ciphertext) {
      return decryptAead(key, nonce, aad, ciphertext, hpkealg.aead)
    },
    async deriveKeyPair(ikm) {
      const kp = await cs.kem.deriveKeyPair(ikm)
      return { privateKey: kp.privateKey as PrivateKey, publicKey: kp.publicKey as PublicKey }
    },
    keyLength: cs.aead.keySize,
    nonceLength: cs.aead.nonceSize,
  }
}

export interface Hpke {
  open(
    privateKey: PrivateKey,
    kemOutput: ArrayBuffer,
    ciphertext: ArrayBuffer,
    info: ArrayBuffer,
    aad?: ArrayBuffer,
  ): Promise<ArrayBuffer>
  seal(
    publicKey: PublicKey,
    plaintext: ArrayBuffer,
    info: ArrayBuffer,
    aad?: ArrayBuffer,
  ): Promise<{ ct: ArrayBuffer; enc: ArrayBuffer }>
  importPrivateKey(k: ArrayBuffer): Promise<PrivateKey>
  importPublicKey(k: ArrayBuffer): Promise<PublicKey>
  exportPublicKey(k: PublicKey): Promise<ArrayBuffer>
  encryptAead(key: ArrayBuffer, nonce: ArrayBuffer, aad: ArrayBuffer, plaintext: ArrayBuffer): Promise<ArrayBuffer>
  decryptAead(key: ArrayBuffer, nonce: ArrayBuffer, aad: ArrayBuffer, ciphertext: ArrayBuffer): Promise<ArrayBuffer>
  deriveKeyPair(ikm: ArrayBuffer): Promise<{ privateKey: PrivateKey; publicKey: PublicKey }>
  keyLength: number
  nonceLength: number
}
