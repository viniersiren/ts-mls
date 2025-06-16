import { CredentialTypeName, decodeCredentialType, encodeCredentialType } from "./credentialType"
import { CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite"
import { decodeProposalType, encodeProposalType, ProposalTypeName } from "./proposalType"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"
import { Encoder, contramapEncoders } from "./codec/tlsEncoder"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { decodeVarLenType, encodeVarLenType } from "./codec/variableLength"
import { decodeExtensionType, encodeExtensionType, ExtensionTypeName } from "./extensionType"

export type Capabilities = {
  versions: ProtocolVersionName[]
  ciphersuites: CiphersuiteName[]
  extensions: ExtensionTypeName[]
  proposals: ProposalTypeName[]
  credentials: CredentialTypeName[]
}

export const encodeCapabilities: Encoder<Capabilities> = contramapEncoders(
  [
    encodeVarLenType(encodeProtocolVersion),
    encodeVarLenType(encodeCiphersuite),
    encodeVarLenType(encodeExtensionType),
    encodeVarLenType(encodeProposalType),
    encodeVarLenType(encodeCredentialType),
  ],
  (cap) => [cap.versions, cap.ciphersuites, cap.extensions, cap.proposals, cap.credentials] as const,
)

export const decodeCapabilities: Decoder<Capabilities> = mapDecoders(
  [
    decodeVarLenType(decodeProtocolVersion),
    decodeVarLenType(decodeCiphersuite),
    decodeVarLenType(decodeExtensionType),
    decodeVarLenType(decodeProposalType),
    decodeVarLenType(decodeCredentialType),
  ],
  (versions, ciphersuites, extensions, proposals, credentials) => ({
    versions,
    ciphersuites,
    extensions,
    proposals,
    credentials,
  }),
)
