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
  key: ArrayBuffer,
  nonce: ArrayBuffer,
  aad: ArrayBuffer,
  plaintext: ArrayBuffer,
  alg: AeadAlgorithm,
): Promise<ArrayBuffer> {
  switch (alg) {
    case "AES128GCM":
    case "AES256GCM":
      return await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad },
        await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]),
        plaintext,
      )
    case "CHACHA20POLY1305":
      return bytesToBuffer(
        chacha20poly1305(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(aad)).encrypt(
          new Uint8Array(plaintext),
        ),
      )
  }
}

export async function decryptAead(
  key: ArrayBuffer,
  nonce: ArrayBuffer,
  aad: ArrayBuffer,
  ciphertext: ArrayBuffer,
  alg: AeadAlgorithm,
): Promise<ArrayBuffer> {
  switch (alg) {
    case "AES128GCM":
    case "AES256GCM":
      const x = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"])
      return await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, x, ciphertext)
    case "CHACHA20POLY1305":
      return bytesToBuffer(
        chacha20poly1305(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(aad)).decrypt(
          new Uint8Array(ciphertext),
        ),
      )
  }
}
