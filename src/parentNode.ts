import { encodeUint32, decodeUint32 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder"
import { encodeVarLenData, encodeVarLenType, decodeVarLenData, decodeVarLenType } from "./codec/variableLength"

export type ParentNode = { encryptionKey: Uint8Array; parentHash: Uint8Array; unmergedLeaves: number[] }

export const encodeParentNode: Encoder<ParentNode> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData, encodeVarLenType(encodeUint32)],
  (node) => [node.encryptionKey, node.parentHash, node.unmergedLeaves] as const,
)

export const decodeParentNode: Decoder<ParentNode> = mapDecoders(
  [decodeVarLenData, decodeVarLenData, decodeVarLenType(decodeUint32)],
  (encryptionKey, parentHash, unmergedLeaves) => ({
    encryptionKey,
    parentHash,
    unmergedLeaves,
  }),
)
