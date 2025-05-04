import { CipherSuite, CipherSuiteSealResponse } from "hpke-js"
import { AeadAlgorithm, makeAead } from "./aead"
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

export function makeHpkeCiphersuite(hpkealg: HpkeAlgorithm) {
  return new CipherSuite({
    kem: makeDhKem(hpkealg.kem),
    kdf: makeKdf(hpkealg.kdf),
    aead: makeAead(hpkealg.aead),
  })
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
  ciphertext: ArrayBuffer,
  kemOutput: ArrayBuffer,
  hpke: Hpke,
): Promise<ArrayBuffer> {
  return hpke.open(
    privateKey,
    kemOutput,
    ciphertext,
    new Uint8Array([...encodeVarLenData(utf8ToBytes(`MLS 1.0 ${label}`)), ...encodeVarLenData(context)]).buffer,
  )
}

export function makeHpke(cs: CipherSuite): Hpke {
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
  keyLength: number
  nonceLength: number
}
