import { decodeUint16, encodeUint16 } from "./codec/number"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder"
import { openEnumNumberEncoder, openEnumNumberToKey } from "./util/enumHelpers"

const credentialTypes = {
  basic: 1,
  x509: 2,
} as const

export type CredentialTypeName = keyof typeof credentialTypes
export type CredentialTypeValue = (typeof credentialTypes)[CredentialTypeName]

export const encodeCredentialType: Encoder<CredentialTypeName> = contramapEncoder(
  encodeUint16,
  openEnumNumberEncoder(credentialTypes),
)

export const decodeCredentialType: Decoder<CredentialTypeName> = mapDecoderOption(
  decodeUint16,
  openEnumNumberToKey(credentialTypes),
)
