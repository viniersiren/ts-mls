import json from "../../test_vectors/crypto-basics.json"
import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { bytesToHex, hexToBytes } from "@noble/ciphers/utils"
import { signWithLabel, verifyWithLabel } from "../../src/crypto/signature"
import { refhash } from "../../src/crypto/hash"
import { deriveSecret, deriveTreeSecret, expandWithLabel } from "../../src/crypto/kdf"
import { decryptWithLabel, encryptWithLabel } from "../../src/crypto/hpke"

async function test_derive_secret(impl: CiphersuiteImpl, o: { label: string; secret: string; out: string }) {
  const res = await deriveSecret(hexToBytes(o.secret), o.label, impl.kdf)
  expect(bytesToHex(new Uint8Array(res))).toBe(o.out)
}

async function test_derive_tree_secret(
  impl: CiphersuiteImpl,
  o: { label: string; secret: string; generation: number; out: string },
) {
  const res = await deriveTreeSecret(hexToBytes(o.secret), o.label, o.generation, impl.kdf)
  expect(bytesToHex(new Uint8Array(res))).toBe(o.out)
}

async function test_expand_with_label(
  impl: CiphersuiteImpl,
  o: { label: string; secret: string; length: number; context: string; out: string },
) {
  const res = await expandWithLabel(hexToBytes(o.secret), o.label, hexToBytes(o.context), o.length, impl.kdf)
  expect(bytesToHex(new Uint8Array(res))).toBe(o.out)
}

async function test_ref_hash(impl: CiphersuiteImpl, o: { label: string; value: string; out: string }) {
  const res = await refhash(o.label, hexToBytes(o.value), impl.hash)
  expect(bytesToHex(new Uint8Array(res))).toBe(o.out)
}

function test_sign_with_label(
  impl: CiphersuiteImpl,
  o: { label: string; content: string; priv: string; pub: string; signature: string },
) {
  const signature = signWithLabel(hexToBytes(o.priv), o.label, hexToBytes(o.content), impl.signature)
  const v = verifyWithLabel(hexToBytes(o.pub), o.label, hexToBytes(o.content), signature, impl.signature)
  const v2 = verifyWithLabel(hexToBytes(o.pub), o.label, hexToBytes(o.content), hexToBytes(o.signature), impl.signature)
  expect(v).toBe(true)
  expect(v2).toBe(true)
}

async function test_encrypt_with_label(
  impl: CiphersuiteImpl,
  o: {
    ciphertext: string
    context: string
    kem_output: string
    label: string
    plaintext: string
    priv: string
    pub: string
  },
) {
  const privateKey = await impl.hpke.importPrivateKey(hexToBytes(o.priv).buffer as ArrayBuffer)
  const publicKey = await impl.hpke.importPublicKey(hexToBytes(o.pub).buffer as ArrayBuffer)
  const decrypted = await decryptWithLabel(
    privateKey,
    o.label,
    hexToBytes(o.context),
    hexToBytes(o.ciphertext).buffer as ArrayBuffer,
    hexToBytes(o.kem_output).buffer as ArrayBuffer,
    impl.hpke,
  )

  expect(bytesToHex(new Uint8Array(decrypted))).toBe(o.plaintext)

  const { ct: ctCandidate, enc: encCandidate } = await encryptWithLabel(
    publicKey,
    o.label,
    hexToBytes(o.context),
    hexToBytes(o.plaintext).buffer as ArrayBuffer,
    impl.hpke,
  )

  const plaintext = await decryptWithLabel(
    privateKey,
    o.label,
    hexToBytes(o.context),
    ctCandidate,
    encCandidate,
    impl.hpke,
  )
  expect(bytesToHex(new Uint8Array(plaintext))).toBe(o.plaintext)
}
test("crypto basics", async () => {
  for (const x of json) {
    const impl = getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await test_ref_hash(impl, x.ref_hash)
    await test_derive_secret(impl, x.derive_secret)
    await test_derive_tree_secret(impl, x.derive_tree_secret)
    await test_expand_with_label(impl, x.expand_with_label)
    await test_encrypt_with_label(impl, x.encrypt_with_label)
    test_sign_with_label(impl, x.sign_with_label)
  }
})
