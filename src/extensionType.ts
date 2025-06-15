import { decodeUint16, encodeUint16 } from "./codec/number"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder"
import { openEnumNumberEncoder, openEnumNumberToKey } from "./util/enumHelpers"

const extensionTypes = {
  application_id: 1,
  ratchet_tree: 2,
  required_capabilities: 3,
  external_pub: 4,
  external_senders: 5,
} as const

export type ExtensionTypeName = keyof typeof extensionTypes
export type ExtensionTypeValue = (typeof extensionTypes)[ExtensionTypeName]

export const encodeExtensionType: Encoder<ExtensionTypeName> = contramapEncoder(
  encodeUint16,
  openEnumNumberEncoder(extensionTypes),
)

export const decodeExtensionType: Decoder<ExtensionTypeName> = mapDecoderOption(
  decodeUint16,
  openEnumNumberToKey(extensionTypes),
)
