import { decodeUint16, encodeUint16 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"

export type Extension = {
  extensionType: number
  extensionData: Uint8Array
}

export const encodeExtension: Encoder<Extension> = contramapEncoders(
  [encodeUint16, encodeVarLenData],
  (e) => [e.extensionType, e.extensionData] as const,
)

export const decodeExtension: Decoder<Extension> = mapDecoders(
  [decodeUint16, decodeVarLenData],
  (extensionType, extensionData) => ({ extensionType, extensionData }),
)
