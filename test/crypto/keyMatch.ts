import { Hpke } from "../../src/crypto/hpke"
import { Signature } from "../../src/crypto/signature"

export async function hpkeKeysMatch(publicKey: Uint8Array, privateKey: Uint8Array, hpke: Hpke): Promise<boolean> {
  const encoder = new TextEncoder()
  const plaintext = encoder.encode("test")
  const info = encoder.encode("key check")

  try {
    const { ct, enc } = await hpke.seal(await hpke.importPublicKey(publicKey), plaintext, info)

    const decrypted = await hpke.open(await hpke.importPrivateKey(privateKey), enc, ct, info)

    return new TextDecoder().decode(decrypted) === "test"
  } catch (err) {
    return false
  }
}

export function signatureKeysMatch(publicKey: Uint8Array, privateKey: Uint8Array, s: Signature): boolean {
  const testMessage = new TextEncoder().encode("test")
  const signature = s.sign(privateKey, testMessage)
  return s.verify(publicKey, testMessage, signature)
}
