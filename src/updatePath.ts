import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { decodeLeafNode, encodeLeafNode, LeafNode } from "./leafNode"
import { decodeHpkeCiphertext, encodeHpkeCiphertext, HPKECiphertext } from "./welcome" //todo move this

export type UpdatePathNode = Readonly<{
  encryptionKey: Uint8Array
  encryptedPathSecret: HPKECiphertext[]
}>

export const encodeUpdatePathNode: Encoder<UpdatePathNode> = contramapEncoders(
  [encodeVarLenData, encodeVarLenType(encodeHpkeCiphertext)],
  (node) => [node.encryptionKey, node.encryptedPathSecret] as const,
)

export const decodeUpdatePathNode: Decoder<UpdatePathNode> = mapDecoders(
  [decodeVarLenData, decodeVarLenType(decodeHpkeCiphertext)],
  (encryptionKey, encryptedPathSecret) => ({ encryptionKey, encryptedPathSecret }),
)

export type UpdatePath = Readonly<{
  leafNode: LeafNode
  nodes: UpdatePathNode[]
}>

export const encodeUpdatePath: Encoder<UpdatePath> = contramapEncoders(
  [encodeLeafNode, encodeVarLenType(encodeUpdatePathNode)],
  (path) => [path.leafNode, path.nodes] as const,
)

export const decodeUpdatePath: Decoder<UpdatePath> = mapDecoders(
  [decodeLeafNode, decodeVarLenType(decodeUpdatePathNode)],
  (leafNode, nodes) => ({ leafNode, nodes }),
)
