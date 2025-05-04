import { decodeUint32, encodeUint32 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { decodeExtension, encodeExtension, Extension } from "./extension"
import { decodeGroupContext, encodeGroupContext, GroupContext } from "./groupContext"

export type GroupInfoTBS = Readonly<{
  groupContext: GroupContext
  extensions: Extension[]
  confirmationTag: Uint8Array
  signer: number
}>

export const encodeGroupInfoTBS: Encoder<GroupInfoTBS> = contramapEncoders(
  [
    encodeGroupContext,
    encodeVarLenType(encodeExtension), // extensions
    encodeVarLenData, // confirmationTag
    encodeUint32, // signer
  ],
  (g) => [g.groupContext, g.extensions, g.confirmationTag, g.signer] as const,
)

export const decodeGroupInfoTBS: Decoder<GroupInfoTBS> = mapDecoders(
  [decodeGroupContext, decodeVarLenType(decodeExtension), decodeVarLenData, decodeUint32],
  (groupContext, extensions, confirmationTag, signer) => ({
    groupContext,
    extensions,
    confirmationTag,
    signer,
  }),
)

export type GroupInfo = GroupInfoTBS &
  Readonly<{
    signature: Uint8Array
  }>

export const encodeGroupInfo: Encoder<GroupInfo> = contramapEncoders(
  [encodeGroupInfoTBS, encodeVarLenData],
  (g) => [g, g.signature] as const,
)

export const decodeGroupInfo: Decoder<GroupInfo> = mapDecoders(
  [decodeGroupInfoTBS, decodeVarLenData],
  (tbs, signature) => ({
    ...tbs,
    signature,
  }),
)
