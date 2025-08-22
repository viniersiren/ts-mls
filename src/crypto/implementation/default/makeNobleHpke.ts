import { Hpke, HpkeAlgorithm, PrivateKey, PublicKey } from "../../hpke"
import { makeNobleAead } from "../../nobleAead"
import { makeKdf } from "./makeKdfImpl"
import { makeDhKem } from "./makeDhKem"
import { bytesToBuffer, concatUint8Arrays } from "../../../util/byteArray"
import { CryptoError } from "../../../mlsError"
import { CipherSuite } from "@hpke/core"

export async function makeNobleHpke(hpkealg: HpkeAlgorithm): Promise<Hpke> {
  const nobleAead = await makeNobleAead(hpkealg.aead)
  const kem = await makeDhKem(hpkealg.kem)

  const cs = new CipherSuite({
    kem: kem,
    kdf: makeKdf(hpkealg.kdf),
    aead: {
      keySize: 32,
      nonceSize: 12,
      encrypt: async (key: ArrayBuffer, nonce: ArrayBuffer, plaintext: ArrayBuffer, aad?: ArrayBuffer) => {
        return nobleAead.encrypt(
          new Uint8Array(key),
          new Uint8Array(nonce),
          aad ? new Uint8Array(aad) : new Uint8Array(),
          new Uint8Array(plaintext)
        )
      },
      decrypt: async (key: ArrayBuffer, nonce: ArrayBuffer, ciphertext: ArrayBuffer, aad?: ArrayBuffer) => {
        return nobleAead.decrypt(
          new Uint8Array(key),
          new Uint8Array(nonce),
          aad ? new Uint8Array(aad) : new Uint8Array(),
          new Uint8Array(ciphertext)
        )
      }
    } as any
  })

  return {
    async open(privateKey, kemOutput, ciphertext, info, aad) {
      try {
        const context = await cs.createRecipientContext({
          recipientKey: privateKey,
          info: bytesToBuffer(info),
          enc: bytesToBuffer(kemOutput),
        })

        const result = await context.open(bytesToBuffer(ciphertext), aad ? bytesToBuffer(aad) : new ArrayBuffer())
        return new Uint8Array(result)
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },

    async seal(publicKey, plaintext, info, aad) {
      try {
        const context = await cs.createSenderContext({
          recipientPublicKey: publicKey,
          info: bytesToBuffer(info),
        })

        const result = await context.seal(bytesToBuffer(plaintext), aad ? bytesToBuffer(aad) : new ArrayBuffer())

        return {
          ct: new Uint8Array((result as any).ct),
          enc: new Uint8Array((result as any).enc),
        }
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },

    async exportSecret(publicKey, exporterContext, length, info) {
      try {
        const context = await cs.createSenderContext({
          recipientPublicKey: publicKey,
          info: bytesToBuffer(info),
        })

        return {
          enc: new Uint8Array(context.enc),
          secret: new Uint8Array(await context.export(bytesToBuffer(exporterContext), length)),
        }
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },

    async importSecret(privateKey, exporterContext, kemOutput, length, info) {
      try {
        const context = await cs.createRecipientContext({
          recipientKey: privateKey,
          info: bytesToBuffer(info),
          enc: bytesToBuffer(kemOutput),
        })

        return new Uint8Array(await context.export(bytesToBuffer(exporterContext), length))
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },

    async importPrivateKey(k) {
      try {
        const key = hpkealg.kem === "DHKEM-P521-HKDF-SHA512" ? prepadPrivateKeyP521(k) : k
        return (await kem.deserializePrivateKey(bytesToBuffer(key))) as PrivateKey
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },

    async importPublicKey(k) {
      try {
        return (await kem.deserializePublicKey(bytesToBuffer(k))) as PublicKey
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },

    async exportPublicKey(k) {
      return new Uint8Array(await kem.serializePublicKey(k))
    },

    async exportPrivateKey(k) {
      return new Uint8Array(await kem.serializePrivateKey(k))
    },

    async encryptAead(key, nonce, aad, plaintext) {
      return nobleAead.encrypt(key, nonce, aad ? aad : new Uint8Array(), plaintext)
    },

    async decryptAead(key, nonce, aad, ciphertext) {
      try {
        return await nobleAead.decrypt(key, nonce, aad ? aad : new Uint8Array(), ciphertext)
      } catch (e) {
        throw new CryptoError(`${e}`)
      }
    },

    async deriveKeyPair(ikm) {
      const kp = await kem.deriveKeyPair(bytesToBuffer(ikm))
      return { privateKey: kp.privateKey as PrivateKey, publicKey: kp.publicKey as PublicKey }
    },

    async generateKeyPair() {
      const kp = await kem.generateKeyPair()
      return { privateKey: kp.privateKey as PrivateKey, publicKey: kp.publicKey as PublicKey }
    },

    keyLength: 32,
    nonceLength: 12,
  }
}

function prepadPrivateKeyP521(k: Uint8Array) {
  const lengthDifference = 66 - k.byteLength
  return concatUint8Arrays(new Uint8Array(lengthDifference), k)
}