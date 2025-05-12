import { Aes128Gcm, Aes256Gcm } from "@hpke/core"
import { AeadInterface } from "hpke-js"
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305"
import { chacha20poly1305 } from "@noble/ciphers/chacha"
import { bytesToBuffer } from "../util/byteArray"

export type AeadAlgorithm = "AES128GCM" | "CHACHA20POLY1305" | "AES256GCM"

export function makeAead(aeadAlg: AeadAlgorithm): AeadInterface {
  switch (aeadAlg) {
    case "AES128GCM":
      return new Aes128Gcm()
    case "AES256GCM":
      return new Aes256Gcm()
    case "CHACHA20POLY1305":
      return new Chacha20Poly1305()
  }
}

export async function encryptAead(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
  alg: AeadAlgorithm,
): Promise<Uint8Array> {
  switch (alg) {
    case "AES128GCM":
    case "AES256GCM": {
      const cryptoKey = await crypto.subtle.importKey("raw", bytesToBuffer(key), { name: "AES-GCM" }, false, [
        "encrypt",
      ])
      const result = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: bytesToBuffer(nonce),
          additionalData: aad.length > 0 ? bytesToBuffer(aad) : undefined,
        },
        cryptoKey,
        bytesToBuffer(plaintext),
      )
      return new Uint8Array(result)
    }
    case "CHACHA20POLY1305":
      return chacha20poly1305(key, nonce, aad).encrypt(plaintext)
  }
}

export async function decryptAead(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
  alg: AeadAlgorithm,
): Promise<Uint8Array> {
  switch (alg) {
    case "AES128GCM":
    case "AES256GCM": {
      const cryptoKey = await crypto.subtle.importKey("raw", bytesToBuffer(key), { name: "AES-GCM" }, false, [
        "decrypt",
      ])
      const result = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: bytesToBuffer(nonce),
          additionalData: aad.length > 0 ? bytesToBuffer(aad) : undefined,
        },
        cryptoKey,
        bytesToBuffer(ciphertext),
      )
      return new Uint8Array(result)
    }
    case "CHACHA20POLY1305":
      return chacha20poly1305(key, nonce, aad).decrypt(ciphertext)
  }
}
