import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { hexToBytes } from "@noble/ciphers/utils"
import json from "../../test_vectors/secret-tree.json"
import { expandSenderDataKey, expandSenderDataNonce } from "../../src/sender"
import { createSecretTree, deriveKey, deriveNext, deriveNonce, deriveRatchetRoot } from "../../src/ratchetTree"

test("secret-tree test vectors", async () => {
  for (const x of json) {
    const impl = getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testSecretTree(
      x.sender_data.sender_data_secret,
      x.sender_data.ciphertext,
      x.sender_data.key,
      x.sender_data.nonce,
      x.encryption_secret,
      x.leaves,
      impl,
    )
  }
})

type Leaf = {
  generation: number
  handshake_key: string
  handshake_nonce: string
  application_key: string
  application_nonce: string
}

async function testSecretTree(
  senderSecret: string,
  ciphertext: string,
  key: string,
  nonce: string,
  encryptionSecret: string,
  leaves: Leaf[][],
  impl: CiphersuiteImpl,
) {
  // key == sender_data_key(sender_data_secret, ciphertext)
  const derivedKey = await expandSenderDataKey(impl, hexToBytes(senderSecret), hexToBytes(ciphertext))
  expect(new Uint8Array(derivedKey)).toStrictEqual(hexToBytes(key))

  //nonce == sender_data_nonce(sender_data_secret, ciphertext)
  const derivedNonce = await expandSenderDataNonce(impl, hexToBytes(senderSecret), hexToBytes(ciphertext))
  expect(new Uint8Array(derivedNonce)).toStrictEqual(hexToBytes(nonce))

  const tree = await createSecretTree(leaves.length, hexToBytes(encryptionSecret), impl.kdf)
  for (const [index, leaf] of leaves.entries()) {
    const nodeIndex = index * 2
    const handshakeSecret = await deriveRatchetRoot(tree, nodeIndex, "handshake", impl.kdf)
    for (const gen of leaf) {
      const generationDifference = gen.generation - handshakeSecret.generation
      const ratcheted = await repeatAsync(
        (s) => deriveNext(s.secret, s.generation, impl.kdf),
        handshakeSecret,
        generationDifference,
      )
      expect(ratcheted.generation).toBe(gen.generation)

      //handshake_key = handshake_ratchet_key_[i]_[generation]
      const handshakeKey = await deriveKey(new Uint8Array(ratcheted.secret), ratcheted.generation, impl)
      expect(handshakeKey).toStrictEqual(hexToBytes(gen.handshake_key))

      // handshake_nonce = handshake_ratchet_nonce_[i]_[generation]
      const handshakeNonce = await deriveNonce(new Uint8Array(ratcheted.secret), ratcheted.generation, impl)
      expect(handshakeNonce).toStrictEqual(hexToBytes(gen.handshake_nonce))
    }

    const applicationSecret = await deriveRatchetRoot(tree, nodeIndex, "application", impl.kdf)
    for (const gen of leaf) {
      const generationDifference = gen.generation - applicationSecret.generation
      const ratcheted = await repeatAsync(
        (s) => deriveNext(new Uint8Array(s.secret), s.generation, impl.kdf),
        applicationSecret,
        generationDifference,
      )
      expect(ratcheted.generation).toBe(gen.generation)

      //pplication_key = application_ratchet_key_[i]_[generation]
      const applicationKey = await deriveKey(new Uint8Array(ratcheted.secret), ratcheted.generation, impl)
      expect(new Uint8Array(applicationKey)).toStrictEqual(hexToBytes(gen.application_key))

      // application_nonce = application_ratchet_nonce_[i]_[generation]
      const applicationNonce = await deriveNonce(new Uint8Array(ratcheted.secret), ratcheted.generation, impl)
      expect(new Uint8Array(applicationNonce)).toStrictEqual(hexToBytes(gen.application_nonce))
    }
  }
}

async function repeatAsync<T>(fn: (input: T) => Promise<T>, initial: T, times: number): Promise<T> {
  let result = initial
  for (let i = 0; i < times; i++) {
    result = await fn(result)
  }
  return result
}
