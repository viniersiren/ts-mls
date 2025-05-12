import { decodeOptional, encodeOptional } from "./codec/optional"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { PrivateKey, PublicKey } from "./crypto/ciphersuite"
import { constantTimeEqual } from "./util/constantTimeCompare"
import { decryptWithLabel, encryptWithLabel, Hpke } from "./crypto/hpke"
import { decodePskId, encodePskId, PreSharedKeyID } from "./presharedkey"
import { Welcome } from "./welcome"

export type GroupSecrets = Readonly<{
  joinerSecret: Uint8Array
  pathSecret: Uint8Array | undefined
  psks: PreSharedKeyID[]
}>

export const encodeGroupSecrets: Encoder<GroupSecrets> = contramapEncoders(
  [encodeVarLenData, encodeOptional(encodeVarLenData), encodeVarLenType(encodePskId)],
  (gs) => [gs.joinerSecret, gs.pathSecret, gs.psks] as const,
)

export const decodeGroupSecrets: Decoder<GroupSecrets> = mapDecoders(
  [decodeVarLenData, decodeOptional(decodeVarLenData), decodeVarLenType(decodePskId)],
  (joinerSecret, pathSecret, psks) => ({ joinerSecret, pathSecret, psks }),
)

export function encryptGroupSecrets(
  initKey: PublicKey,
  encryptedGroupInfo: Uint8Array,
  groupSecrets: GroupSecrets,
  hpke: Hpke,
) {
  return encryptWithLabel(initKey, "Welcome", encryptedGroupInfo, encodeGroupSecrets(groupSecrets), hpke)
}

export async function decryptGroupSecrets(
  initPrivateKey: PrivateKey,
  keyPackageRef: Uint8Array,
  welcome: Welcome,
  hpke: Hpke,
): Promise<GroupSecrets | undefined> {
  const secret = welcome.secrets.find((s) => constantTimeEqual(s.newMember, keyPackageRef))
  if (secret === undefined) throw new Error("No matching secret found")
  const decrypted = await decryptWithLabel(
    initPrivateKey,
    "Welcome",
    welcome.encryptedGroupInfo,
    secret.encryptedGroupSecrets.kemOutput,
    secret.encryptedGroupSecrets.ciphertext,
    hpke,
  )
  return decodeGroupSecrets(decrypted, 0)?.[0]
}
