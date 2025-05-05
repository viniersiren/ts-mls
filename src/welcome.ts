import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CiphersuiteImpl, CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite"
import { expandWithLabel } from "./crypto/kdf"

export type HPKECiphertext = Readonly<{
  kemOutput: Uint8Array
  ciphertext: Uint8Array
}>

export const encodeHpkeCiphertext: Encoder<HPKECiphertext> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData],
  (egs) => [egs.kemOutput, egs.ciphertext] as const,
)

export const decodeHpkeCiphertext: Decoder<HPKECiphertext> = mapDecoders(
  [decodeVarLenData, decodeVarLenData],
  (kemOutput, ciphertext) => ({ kemOutput, ciphertext }),
)

type EncryptedGroupSecrets = Readonly<{
  newMember: Uint8Array
  encryptedGroupSecrets: HPKECiphertext
}>

export const encodeEncryptedGroupSecrets: Encoder<EncryptedGroupSecrets> = contramapEncoders(
  [encodeVarLenData, encodeHpkeCiphertext],
  (egs) => [egs.newMember, egs.encryptedGroupSecrets] as const,
)

export const decodeEncryptedGroupSecrets: Decoder<EncryptedGroupSecrets> = mapDecoders(
  [decodeVarLenData, decodeHpkeCiphertext],
  (newMember, encryptedGroupSecrets) => ({ newMember, encryptedGroupSecrets }),
)

export type Welcome = Readonly<{
  cipherSuite: CiphersuiteName
  secrets: EncryptedGroupSecrets[]
  encryptedGroupInfo: Uint8Array
}>

export const encodeWelcome: Encoder<Welcome> = contramapEncoders(
  [encodeCiphersuite, encodeVarLenType(encodeEncryptedGroupSecrets), encodeVarLenData],
  (welcome) => [welcome.cipherSuite, welcome.secrets, welcome.encryptedGroupInfo] as const,
)

export const decodeWelcome: Decoder<Welcome> = mapDecoders(
  [decodeCiphersuite, decodeVarLenType(decodeEncryptedGroupSecrets), decodeVarLenData],
  (cipherSuite, secrets, encryptedGroupInfo) => ({ cipherSuite, secrets, encryptedGroupInfo }),
)

export function welcomeNonce(welcomeSecret: Uint8Array, cs: CiphersuiteImpl) {
  return expandWithLabel(welcomeSecret, "nonce", new Uint8Array(), cs.hpke.nonceLength, cs.kdf)
}

export function welcomeKey(welcomeSecret: Uint8Array, cs: CiphersuiteImpl) {
  return expandWithLabel(welcomeSecret, "key", new Uint8Array(), cs.hpke.keyLength, cs.kdf)
}
