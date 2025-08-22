import { Aead, AeadAlgorithm } from "./aead"
import { gcm } from "@noble/ciphers/aes"
import { chacha20poly1305 } from "@noble/ciphers/chacha"

export async function makeNobleAead(aeadAlg: AeadAlgorithm): Promise<Aead> {
  switch (aeadAlg) {
    case "AES128GCM":
      return {
        encrypt(key, nonce, aad, plaintext) {
          return encryptAesGcm(key, nonce, aad, plaintext)
        },
        decrypt(key, nonce, aad, ciphertext) {
          return decryptAesGcm(key, nonce, aad, ciphertext)
        },
      }
    case "AES256GCM":
      return {
        encrypt(key, nonce, aad, plaintext) {
          return encryptAesGcm(key, nonce, aad, plaintext)
        },
        decrypt(key, nonce, aad, ciphertext) {
          return decryptAesGcm(key, nonce, aad, ciphertext)
        },
      }
    case "CHACHA20POLY1305":
      return {
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