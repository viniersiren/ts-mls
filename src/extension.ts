import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { decodeExtensionType, encodeExtensionType, ExtensionTypeName } from "./extensionType"

export type Extension = {
  extensionType: ExtensionTypeName
  extensionData: Uint8Array
}

export const encodeExtension: Encoder<Extension> = contramapEncoders(
  [encodeExtensionType, encodeVarLenData],
  (e) => [e.extensionType, e.extensionData] as const,
)

export const decodeExtension: Decoder<Extension> = mapDecoders(
  [decodeExtensionType, decodeVarLenData],
  (extensionType, extensionData) => ({ extensionType, extensionData }),
)
