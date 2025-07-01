import { decodeUint16, encodeUint16 } from "./codec/number"
import { Decoder, mapDecoderOption } from "./codec/tlsDecoder"
import { contramapEncoder, Encoder } from "./codec/tlsEncoder"
import { openEnumNumberEncoder, openEnumNumberToKey } from "./util/enumHelpers"

export const proposalTypes = {
  add: 1,
  update: 2,
  remove: 3,
  psk: 4,
  reinit: 5,
  external_init: 6,
  group_context_extensions: 7,
} as const

export type ProposalTypeName = keyof typeof proposalTypes
export type ProposalTypeValue = (typeof proposalTypes)[ProposalTypeName]

export const encodeProposalType: Encoder<ProposalTypeName> = contramapEncoder(
  encodeUint16,
  openEnumNumberEncoder(proposalTypes),
)

export const decodeProposalType: Decoder<ProposalTypeName> = mapDecoderOption(
  decodeUint16,
  openEnumNumberToKey(proposalTypes),
)
