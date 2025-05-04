import { decodeUint32, decodeUint8, encodeUint32, encodeUint8 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { enumNumberToKey } from "./util/enumHelpers"

const senderTypes = {
  member: 1,
  external: 2,
  new_member_proposal: 3,
  new_member_commit: 4,
} as const

export type SenderTypeName = keyof typeof senderTypes
export type SenderTypeValue = (typeof senderTypes)[SenderTypeName]

export const encodeSenderType: Encoder<SenderTypeName> = contramapEncoder(encodeUint8, (t) => senderTypes[t])

export const decodeSenderType: Decoder<SenderTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(senderTypes))

export type Sender = SenderMember | SenderExternal | SenderNewMemberProposal | SenderNewMemberCommit

type SenderMember = { senderType: "member"; leafIndex: number }

type SenderExternal = { senderType: "external"; senderIndex: number }
type SenderNewMemberProposal = { senderType: "new_member_proposal" }
type SenderNewMemberCommit = { senderType: "new_member_commit" }

export const encodeSender: Encoder<Sender> = (s) => {
  switch (s.senderType) {
    case "member":
      return contramapEncoders(
        [encodeSenderType, encodeUint32],
        (s: SenderMember) => [s.senderType, s.leafIndex] as const,
      )(s)
    case "external":
      return contramapEncoders(
        [encodeSenderType, encodeUint32],
        (s: SenderExternal) => [s.senderType, s.senderIndex] as const,
      )(s)
    case "new_member_proposal":
    case "new_member_commit":
      return encodeSenderType(s.senderType)
  }
}

export const decodeSender: Decoder<Sender> = flatMapDecoder(decodeSenderType, (senderType): Decoder<Sender> => {
  switch (senderType) {
    case "member":
      return mapDecoder(decodeUint32, (leafIndex) => ({
        senderType,
        leafIndex,
      }))
    case "external":
      return mapDecoder(decodeUint32, (senderIndex) => ({
        senderType,
        senderIndex,
      }))
    case "new_member_proposal":
      return mapDecoder(
        () => [undefined, 0],
        () => ({
          senderType,
        }),
      )
    case "new_member_commit":
      return mapDecoder(
        () => [undefined, 0],
        () => ({
          senderType,
        }),
      )
  }
})
