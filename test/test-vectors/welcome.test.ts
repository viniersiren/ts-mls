import {
  CiphersuiteId,
  CiphersuiteImpl,
  getCiphersuiteFromId,
  getCiphersuiteImpl,
  PrivateKey,
} from "../../src/crypto/ciphersuite"
import { hexToBytes } from "@noble/ciphers/utils"
import json from "../../test_vectors/welcome.json"
import { expandSenderDataKey, expandSenderDataNonce } from "../../src/sender"
import { createSecretTree, deriveKey, deriveNext, deriveNonce, deriveRatchetRoot } from "../../src/ratchetTree"
import { decodeMlsMessage } from "../../src/message"
import { decodeGroupSecrets, decryptGroupSecrets } from "../../src/groupSecrets"
import { makeKeyPackageRef } from "../../src/keyPackage"
import { constantTimeEqual } from "../../src/util/constantTimeCompare"
import { encodeVarLenData } from "../../src/codec/variableLength"
import { decryptWithLabel } from "../../src/crypto/hpke"
import { bytesToBuffer } from "../../src/util/byteArray"
import { decryptGroupInfo, signGroupInfo, verifyConfirmationTag, verifyGroupInfoSignature } from "../../src/groupInfo"

test("welcome test vectors", async () => {
  for (const x of json) {
    const impl = getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testWelcome(x.init_priv, x.key_package, x.signer_pub, x.welcome, impl)
  }
})

type Leaf = {
  generation: number
  handshake_key: string
  handshake_nonce: string
  application_key: string
  application_nonce: string
}

async function testWelcome(
  init_priv: string,
  key_package: string,
  signer_pub: string,
  welcome: string,
  impl: CiphersuiteImpl,
) {
  const x = decodeMlsMessage(hexToBytes(welcome), 0)
  if (x === undefined || x[0].wireformat !== "mls_welcome") throw new Error("Couldn't decode to welcome")

  const w = x[0].welcome

  const y = decodeMlsMessage(hexToBytes(key_package), 0)
  if (y === undefined || y[0].wireformat !== "mls_key_package") throw new Error("Couldn't decode to key package")

  const keyPackageRef = await makeKeyPackageRef(y[0].keyPackage, impl.hash)

  const secret = w.secrets.find((s) => constantTimeEqual(s.newMember, new Uint8Array(keyPackageRef)))

  if (secret === undefined) throw new Error("No matching secret found")

  const privKey: PrivateKey = await impl.hpke.importPrivateKey(bytesToBuffer(hexToBytes(init_priv)))
  const groupSecrets = await decryptGroupSecrets(privKey, new Uint8Array(keyPackageRef), w, impl.hpke)

  if (groupSecrets === undefined) throw new Error("Could not decrypt group secrets")

  const pskSecret = new Uint8Array(impl.kdf.size)

  const gi = await decryptGroupInfo(w, groupSecrets.joinerSecret, pskSecret, impl)
  if (gi === undefined) throw new Error("Could not decrypt group info")

  const tagOk = await verifyConfirmationTag(gi, groupSecrets.joinerSecret, pskSecret, impl)
  expect(tagOk).toBe(true)

  const signatureOk = verifyGroupInfoSignature(gi, hexToBytes(signer_pub), impl.signature)
  expect(signatureOk).toBe(true)
}
