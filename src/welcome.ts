import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite"

type KeypackageRef = Uint8Array

export type HPKECiphertext = Readonly<{
  ciphertext: Uint8Array
  kemOutput: Uint8Array
}>

export const encodeHpkeCiphertext: Encoder<HPKECiphertext> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData],
  (egs) => [egs.ciphertext, egs.kemOutput] as const,
)

export const decodeHpkeCiphertext: Decoder<HPKECiphertext> = mapDecoders(
  [decodeVarLenData, decodeVarLenData],
  (ciphertext, kemOutput) => ({ ciphertext, kemOutput }),
)

type EncryptedGroupSecrets = Readonly<{
  newMember: KeypackageRef
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
