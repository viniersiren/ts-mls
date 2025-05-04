import { decodeUint8, encodeUint8 } from "./codec/number"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder"
import { enumNumberToKey } from "./util/enumHelpers"

const nodeTypes = {
  leaf: 1,
  parent: 2,
} as const

export type NodeTypeName = keyof typeof nodeTypes
export type NodeTypeValue = (typeof nodeTypes)[NodeTypeName]

export const encodeNodeType: Encoder<NodeTypeName> = contramapEncoder(encodeUint8, (t) => nodeTypes[t])

export const decodeNodeType: Decoder<NodeTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(nodeTypes))
