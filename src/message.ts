import { Encoder } from "./codec/tlsEncoder"
import { encodeVarLenData } from "./codec/variableLength"
import { CiphersuiteName } from "./crypto/ciphersuite"

export type Welcome = Readonly<{
  cipherSuite: CiphersuiteName
  secrets: EncryptedGroupSecrets[]
  encryptedGroupInfo: Uint8Array
}>

type KeypackageRef = Uint8Array

type EncryptedGroupSecrets = Readonly<{
  newMember: KeypackageRef
  encryptedGroupSecrets: HPKECiphertext
}>

export const encodeEncryptedGroupSecrets: Encoder<EncryptedGroupSecrets> = (egs) => {
  return new Uint8Array([...egs.newMember])
}

export type HPKECiphertext = Readonly<{
  ciphertext: Uint8Array
  kemOutput: Uint8Array
}>

export const encodeHpkeCiphertext: Encoder<HPKECiphertext> = (ct) => {
  return new Uint8Array([...encodeVarLenData(ct.kemOutput), ...encodeVarLenData(ct.ciphertext)])
}
