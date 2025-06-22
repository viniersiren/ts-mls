import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { decodeExtensionType, encodeExtensionType, ExtensionTypeName } from "./extensionType"
import { constantTimeEqual } from "./util/constantTimeCompare"

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

export function extensionEqual(a: Extension, b: Extension): boolean {
  return a.extensionType === b.extensionType && constantTimeEqual(a.extensionData, b.extensionData)
}

export function extensionsEqual(a: Extension[], b: Extension[]): boolean {
  if (a.length !== b.length) return false
  return a.every((val, i) => extensionEqual(val, b[i]!))
}
