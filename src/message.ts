import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { encodeVarLenData } from "./codec/variableLength"
import { CiphersuiteName } from "./crypto/ciphersuite"

export type Welcome = Readonly<{
  cipherSuite: CiphersuiteName
  secrets: EncryptedGroupSecrets[]
  encryptedGroupInfo: Uint8Array
}>

type KeypackageRef = Uint8Array

export type HPKECiphertext = Readonly<{
  ciphertext: Uint8Array
  kemOutput: Uint8Array
}>

export const encodeHpkeCiphertext: Encoder<HPKECiphertext> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData],
  (egs) => [egs.ciphertext, egs.kemOutput] as const,
)

type EncryptedGroupSecrets = Readonly<{
  newMember: KeypackageRef
  encryptedGroupSecrets: HPKECiphertext
}>

export const encodeEncryptedGroupSecrets: Encoder<EncryptedGroupSecrets> = contramapEncoders(
  [encodeVarLenData, encodeHpkeCiphertext],
  (egs) => [egs.newMember, egs.encryptedGroupSecrets] as const,
)
