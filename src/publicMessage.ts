import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import {
  decodeFramedContent,
  decodeFramedContentAuthData,
  encodeFramedContent,
  encodeFramedContentAuthData,
  FramedContent,
  FramedContentAuthData,
} from "./framedContent"
import { SenderTypeName } from "./sender"

type PublicMessageInfo = PublicMessageInfoMember | PublicMessageInfoMemberOther
type PublicMessageInfoMember = { senderType: "member"; membershipTag: Uint8Array }
type PublicMessageInfoMemberOther = { senderType: Exclude<SenderTypeName, "member"> }

export const encodePublicMessageInfo: Encoder<PublicMessageInfo> = (info) => {
  switch (info.senderType) {
    case "member":
      return encodeVarLenData(info.membershipTag)
    case "external":
    case "new_member_proposal":
    case "new_member_commit":
      return new Uint8Array()
  }
}

export function decodePublicMessageInfo(senderType: SenderTypeName): Decoder<PublicMessageInfo> {
  switch (senderType) {
    case "member":
      return mapDecoder(decodeVarLenData, (membershipTag) => ({
        senderType,
        membershipTag,
      }))
    case "external":
    case "new_member_proposal":
    case "new_member_commit":
      return succeedDecoder({ senderType })
  }
}

export type PublicMessage = { content: FramedContent; auth: FramedContentAuthData } & PublicMessageInfo

export const encodePublicMessage: Encoder<PublicMessage> = contramapEncoders(
  [encodeFramedContent, encodeFramedContentAuthData, encodePublicMessageInfo],
  (msg) => [msg.content, msg.auth, msg] as const,
)

export const decodePublicMessage: Decoder<PublicMessage> = flatMapDecoder(decodeFramedContent, (content) =>
  mapDecoders(
    [decodeFramedContentAuthData(content.contentType), decodePublicMessageInfo(content.sender.senderType)],
    (auth, info) => ({
      ...info,
      content,
      auth,
    }),
  ),
)
