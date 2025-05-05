import { decodeOptional, encodeOptional } from "./codec/optional"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { PrivateKey, PublicKey } from "./crypto/ciphersuite"
import { constantTimeEqual } from "./util/constantTimeCompare"
import { decryptWithLabel, encryptWithLabel, Hpke } from "./crypto/hpke"
import { decodePskId, encodePskId, PreSharedKeyID } from "./presharedkey"
import { Welcome } from "./welcome"
import { bytesToBuffer } from "./util/byteArray"

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
  return encryptWithLabel(initKey, "Welcome", encryptedGroupInfo, bytesToBuffer(encodeGroupSecrets(groupSecrets)), hpke)
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
    bytesToBuffer(secret.encryptedGroupSecrets.kemOutput),
    bytesToBuffer(secret.encryptedGroupSecrets.ciphertext),
    hpke,
  )
  return decodeGroupSecrets(new Uint8Array(decrypted), 0)?.[0]
}
