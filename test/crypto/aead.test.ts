import { encryptAead, decryptAead } from "../../src/crypto/aead"
import { randomBytes } from "crypto"

const key128 = randomBytes(16)
const key256 = randomBytes(32)
const nonce = randomBytes(12)
const aad = randomBytes(12)
const plaintext = new TextEncoder().encode("Hello world!")

test("AES128-GCM encryption and decryption", async () => {
  const ciphertext = await encryptAead(key128, nonce, new Uint8Array(), plaintext, "AES128GCM")
  const decrypted = await decryptAead(key128, nonce, new Uint8Array(), ciphertext, "AES128GCM")

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("AES256-GCM encryption and decryption", async () => {
  const ciphertext = await encryptAead(key256, nonce, new Uint8Array(), plaintext, "AES256GCM")
  const decrypted = await decryptAead(key256, nonce, new Uint8Array(), ciphertext, "AES256GCM")

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("ChaCha20-Poly1305 encryption and decryption", async () => {
  const ciphertext = await encryptAead(key256, nonce, new Uint8Array(), plaintext, "CHACHA20POLY1305")
  const decrypted = await decryptAead(key256, nonce, new Uint8Array(), ciphertext, "CHACHA20POLY1305")

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("AES128-GCM encryption and decryption with aad", async () => {
  const ciphertext = await encryptAead(key128, nonce, aad, plaintext, "AES128GCM")
  const decrypted = await decryptAead(key128, nonce, aad, ciphertext, "AES128GCM")

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("AES256-GCM encryption and decryption with aad", async () => {
  const ciphertext = await encryptAead(key256, nonce, aad, plaintext, "AES256GCM")
  const decrypted = await decryptAead(key256, nonce, aad, ciphertext, "AES256GCM")

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})

test("ChaCha20-Poly1305 encryption and decryption with aad", async () => {
  const ciphertext = await encryptAead(key256, nonce, aad, plaintext, "CHACHA20POLY1305")
  const decrypted = await decryptAead(key256, nonce, aad, ciphertext, "CHACHA20POLY1305")

  expect(new TextDecoder().decode(decrypted)).toBe("Hello world!")
})
