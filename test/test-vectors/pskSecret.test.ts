import json from "../../test_vectors/psk_secret.json"
import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { computePskSecret, PreSharedKeyID, PreSharedKeyIdExternal, pskTypes } from "../../src/presharedkey"
import { bytesToHex, hexToBytes } from "@noble/ciphers/utils"

test("psk_secret test vectors", async () => {
  for (const x of json) {
    const impl = getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testPskSecret(x.psk_secret, x.psks, impl)
  }
})

type Psk = {
  psk_id: string
  psk: string
  psk_nonce: string
}

function toExternalPsk(p: Psk): [PreSharedKeyIdExternal, Uint8Array] {
  return [
    { psktype: "external", pskinfo: { pskId: hexToBytes(p.psk_id) }, pskNonce: hexToBytes(p.psk_nonce) },
    hexToBytes(p.psk),
  ]
}

async function testPskSecret(secret: string, psks: Psk[], impl: CiphersuiteImpl) {
  const computedSecret = await computePskSecret(psks.map(toExternalPsk), impl)
  expect(bytesToHex(computedSecret)).toBe(secret)
}
