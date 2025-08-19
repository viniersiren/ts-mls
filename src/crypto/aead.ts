import { AeadInterface, AeadId, CipherSuite, KemId, KdfId } from "hpke-js"
import { gcm } from "@noble/ciphers/aes"
import { chacha20poly1305 } from "@noble/ciphers/chacha"

export type AeadAlgorithm = "AES128GCM" | "CHACHA20POLY1305" | "AES256GCM"

export interface Aead {
  hpkeInterface(): AeadInterface
  encrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>
  decrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>
}

export async function makeAead(aeadAlg: AeadAlgorithm): Promise<Aead> {
  switch (aeadAlg) {
    case "AES128GCM":
      return {
        hpkeInterface() {
          return new CipherSuite({
            kem: KemId.DhkemP256HkdfSha256,
            kdf: KdfId.HkdfSha256,
            aead: AeadId.Aes128Gcm,
          }).aead
        },
        encrypt(key, nonce, aad, plaintext) {
          return encryptAesGcm(key, nonce, aad, plaintext)
        },
        decrypt(key, nonce, aad, ciphertext) {
          return decryptAesGcm(key, nonce, aad, ciphertext)
        },
      }
    case "AES256GCM":
      return {
        hpkeInterface() {
          return new CipherSuite({
            kem: KemId.DhkemP256HkdfSha256,
            kdf: KdfId.HkdfSha256,
            aead: AeadId.Aes256Gcm,
          }).aead
        },
        encrypt(key, nonce, aad, plaintext) {
          return encryptAesGcm(key, nonce, aad, plaintext)
        },
        decrypt(key, nonce, aad, ciphertext) {
          return decryptAesGcm(key, nonce, aad, ciphertext)
        },
      }
    case "CHACHA20POLY1305":
      return {
        hpkeInterface() {
          return new CipherSuite({
            kem: KemId.DhkemP256HkdfSha256,
            kdf: KdfId.HkdfSha256,
            aead: AeadId.Chacha20Poly1305,
          }).aead
        },
        async encrypt(key, nonce, aad, plaintext) {
          return chacha20poly1305(key, nonce, aad).encrypt(plaintext)
        },
        async decrypt(key, nonce, aad, ciphertext) {
          return chacha20poly1305(key, nonce, aad).decrypt(ciphertext)
        },
      }
  }
}

async function encryptAesGcm(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cipher = gcm(key, nonce, aad)
  return cipher.encrypt(plaintext)
}

async function decryptAesGcm(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cipher = gcm(key, nonce, aad)
  return cipher.decrypt(ciphertext)
}
