import { decodeUint64, encodeUint64 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { Commit, decodeCommit, encodeCommit } from "./commit"
import { ContentTypeName, decodeContentType, encodeContentType } from "./contentType"
import { decodeGroupContext, encodeGroupContext, GroupContext } from "./groupContext"
import { decodeWireformat, encodeWireformat, WireformatName } from "./message"
import { decodeProposal, encodeProposal, Proposal } from "./proposal"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"
import { decodeSender, decodeSenderType, encodeSender, encodeSenderType, Sender } from "./sender"

type FramedContentInfo = FramedContentApplicationData | FramedContentProposalData | FramedContentCommitData

type FramedContentApplicationData = { contentType: "application"; applicationData: Uint8Array }
type FramedContentProposalData = { contentType: "proposal"; proposal: Proposal }
type FramedContentCommitData = { contentType: "commit"; proposal: Commit }

export const encodeFramedContentApplicationData: Encoder<FramedContentApplicationData> = contramapEncoders(
  [encodeContentType, encodeVarLenData],
  (f) => [f.contentType, f.applicationData] as const,
)

export const encodeFramedContentProposalData: Encoder<FramedContentProposalData> = contramapEncoders(
  [encodeContentType, encodeProposal],
  (f) => [f.contentType, f.proposal] as const,
)

export const encodeFramedContentCommitData: Encoder<FramedContentCommitData> = contramapEncoders(
  [encodeContentType, encodeCommit],
  (f) => [f.contentType, f.proposal] as const,
)

export const encodeFramedContentInfo: Encoder<FramedContentInfo> = (fc) => {
  switch (fc.contentType) {
    case "application":
      return encodeFramedContentApplicationData(fc)
    case "proposal":
      return encodeFramedContentProposalData(fc)
    case "commit":
      return encodeFramedContentCommitData(fc)
  }
}

export const decodeFramedContentApplicationData: Decoder<FramedContentApplicationData> = mapDecoder(
  decodeVarLenData,
  (applicationData) => ({ contentType: "application", applicationData }),
)

export const decodeFramedContentProposalData: Decoder<FramedContentProposalData> = mapDecoder(
  decodeProposal,
  (proposal) => ({ contentType: "proposal", proposal }),
)

export const decodeFramedContentCommitData: Decoder<FramedContentCommitData> = mapDecoder(decodeCommit, (proposal) => ({
  contentType: "commit",
  proposal,
}))

export const decodeFramedContentInfo: Decoder<FramedContentInfo> = flatMapDecoder(
  decodeContentType,
  (contentType): Decoder<FramedContentInfo> => {
    switch (contentType) {
      case "application":
        return decodeFramedContentApplicationData
      case "proposal":
        return decodeFramedContentProposalData
      case "commit":
        return decodeFramedContentCommitData
    }
  },
)

export type FramedContent = FramedContentData & FramedContentInfo
type FramedContentData = Readonly<{
  groupId: Uint8Array
  epoch: bigint
  sender: Sender
  authenticatedData: Uint8Array
}>

export type FramedContentCommit = FramedContentData & FramedContentCommitData

export const encodeFramedContent: Encoder<FramedContent> = contramapEncoders(
  [encodeVarLenData, encodeUint64, encodeSender, encodeVarLenData, encodeFramedContentInfo],
  (fc) => [fc.groupId, fc.epoch, fc.sender, fc.authenticatedData, fc] as const,
)

export const decodeFramedContent: Decoder<FramedContent> = mapDecoders(
  [decodeVarLenData, decodeUint64, decodeSender, decodeVarLenData, decodeFramedContentInfo],
  (groupId, epoch, sender, authenticatedData, info) => ({
    groupId,
    epoch,
    sender,
    authenticatedData,
    ...info,
  }),
)

type SenderInfo = SenderInfoMember | SenderInfoNewMemberCommit | SenderInfoExternal | SenderInfoNewMemberProposal
type SenderInfoMember = { senderType: "member"; context: GroupContext }
type SenderInfoNewMemberCommit = { senderType: "new_member_commit"; context: GroupContext }
type SenderInfoExternal = { senderType: "external" }
type SenderInfoNewMemberProposal = { senderType: "new_member_proposal" }

export const encodeSenderInfo: Encoder<SenderInfo> = (info) => {
  switch (info.senderType) {
    case "member":
      return contramapEncoders(
        [encodeSenderType, encodeGroupContext],
        (i: SenderInfoMember) => [i.senderType, i.context] as const,
      )(info)
    case "new_member_commit":
      return contramapEncoders(
        [encodeSenderType, encodeGroupContext],
        (i: SenderInfoNewMemberCommit) => [i.senderType, i.context] as const,
      )(info)
    case "external":
    case "new_member_proposal":
      return encodeSenderType(info.senderType)
  }
}

export const decodeSenderInfo: Decoder<SenderInfo> = flatMapDecoder(
  decodeSenderType,
  (senderType): Decoder<SenderInfo> => {
    switch (senderType) {
      case "member":
        return mapDecoder(decodeGroupContext, (context): SenderInfo => ({ senderType, context }))
      case "new_member_commit":
        return mapDecoder(decodeGroupContext, (context): SenderInfo => ({ senderType, context }))
      case "external":
        return succeedDecoder({ senderType })
      case "new_member_proposal":
        return succeedDecoder({ senderType })
    }
  },
)

export type FramedContentTBS = Readonly<{
  protocolVersion: ProtocolVersionName
  wireformat: WireformatName
  content: FramedContent
  senderContext: SenderInfo
}>

export const encodeFramedContentTBS: Encoder<FramedContentTBS> = contramapEncoders(
  [encodeProtocolVersion, encodeWireformat, encodeFramedContent, encodeSenderInfo],
  (f) => [f.protocolVersion, f.wireformat, f.content, f.senderContext] as const,
)

export const decodeFramedContentTBS: Decoder<FramedContentTBS> = mapDecoders(
  [decodeProtocolVersion, decodeWireformat, decodeFramedContent, decodeSenderInfo],
  (protocolVersion, wireformat, content, senderContext) => ({ protocolVersion, wireformat, content, senderContext }),
)

export type FramedContentAuthData = { signature: Uint8Array } & FramedContentAuthDataContent
type FramedContentAuthDataContent =
  | FramedContentAuthDataContentCommit
  | FramedContentAuthDataContentApplicationOrProposal
type FramedContentAuthDataContentCommit = { contentType: "commit"; confirmationTag: Uint8Array }
type FramedContentAuthDataContentApplicationOrProposal = { contentType: Exclude<ContentTypeName, "commit"> }

const encodeFramedContentAuthDataContent: Encoder<FramedContentAuthDataContent> = (authData) => {
  switch (authData.contentType) {
    case "commit":
      return encodeFramedContentAuthDataCommit(authData)
    case "application":
    case "proposal":
      return new Uint8Array()
  }
}

const encodeFramedContentAuthDataCommit: Encoder<FramedContentAuthDataContentCommit> = contramapEncoder(
  encodeVarLenData,
  (data) => data.confirmationTag,
)

export const encodeFramedContentAuthData: Encoder<FramedContentAuthData> = contramapEncoders(
  [encodeVarLenData, encodeFramedContentAuthDataContent],
  (d) => [d.signature, d] as const,
)

const decodeFramedContentAuthDataCommit: Decoder<FramedContentAuthDataContentCommit> = mapDecoder(
  decodeVarLenData,
  (confirmationTag) => ({
    contentType: "commit",
    confirmationTag,
  }),
)

export function decodeFramedContentAuthData(contentType: ContentTypeName): Decoder<FramedContentAuthData> {
  switch (contentType) {
    case "commit":
      return mapDecoders([decodeVarLenData, decodeFramedContentAuthDataCommit], (signature, commitData) => ({
        signature,
        ...commitData,
      }))
    case "application":
    case "proposal":
      return mapDecoder(decodeVarLenData, (signature) => ({
        signature,
        contentType,
      }))
  }
}
