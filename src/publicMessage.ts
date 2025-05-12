import {
  AuthenticatedContent,
  AuthenticatedContentTBM,
  createMembershipTag,
  verifyMembershipTag,
} from "./authenticatedContent"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { Commit } from "./commit"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import {
  decodeFramedContent,
  decodeFramedContentAuthData,
  encodeFramedContent,
  encodeFramedContentAuthData,
  FramedContent,
  FramedContentAuthData,
  signFramedContentApplicationOrProposal,
  signFramedContentCommit,
  toTbs,
} from "./framedContent"
import { GroupContext } from "./groupContext"
import { Proposal } from "./proposal"
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
export type MemberPublicMessage = PublicMessage & PublicMessageInfoMember
export type ExternalPublicMessage = PublicMessage & PublicMessageInfoMemberOther

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

export async function createMemberPublicMessage(
  membershipKey: Uint8Array,
  content: AuthenticatedContentTBM,
  cs: CiphersuiteImpl,
): Promise<MemberPublicMessage> {
  const tag = await createMembershipTag(membershipKey, content, cs.hash)

  return {
    content: content.contentTbs.content,
    auth: content.auth,
    senderType: "member",
    membershipTag: tag,
  }
}

export async function protectProposalPublic(
  signKey: Uint8Array,
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  authenticatedData: Uint8Array,
  proposal: Proposal,
  cs: CiphersuiteImpl,
  leafIndex: number,
): Promise<PublicMessage> {
  const framedContent: FramedContent = {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    sender: { senderType: "member", leafIndex },
    contentType: "proposal",
    authenticatedData,
    proposal,
  }

  const tbs = {
    protocolVersion: groupContext.version,
    wireformat: "mls_public_message",
    content: framedContent,
    senderType: "member",
    context: groupContext,
  } as const

  const auth = signFramedContentApplicationOrProposal(signKey, tbs, cs)

  const authenticatedContent: AuthenticatedContent = {
    wireformat: "mls_public_message",
    content: framedContent,
    auth,
  }

  return protectPublicMessage(membershipKey, groupContext, authenticatedContent, cs)
}

export async function protectCommitPublic(
  signKey: Uint8Array,
  membershipKey: Uint8Array,
  confirmationKey: Uint8Array,
  groupContext: GroupContext,
  authenticatedData: Uint8Array,
  commit: Commit,
  cs: CiphersuiteImpl,
  leafIndex: number,
): Promise<PublicMessage> {
  const framedContent: FramedContent = {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    sender: { senderType: "member", leafIndex },
    contentType: "commit",
    authenticatedData,
    commit,
  }

  const tbs = {
    protocolVersion: groupContext.version,
    wireformat: "mls_public_message",
    content: framedContent,
    senderType: "member",
    context: groupContext,
  } as const

  const auth = await signFramedContentCommit(signKey, confirmationKey, groupContext.confirmedTranscriptHash, tbs, cs)

  const authenticatedContent: AuthenticatedContent = {
    wireformat: "mls_public_message",
    content: framedContent,
    auth,
  }

  return protectPublicMessage(membershipKey, groupContext, authenticatedContent, cs)
}

export async function protectPublicMessage(
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  content: AuthenticatedContent,
  cs: CiphersuiteImpl,
): Promise<PublicMessage> {
  if (content.content.contentType === "application") throw new Error("Can't make an application message public")

  if (content.content.sender.senderType == "member") {
    const authenticatedContent: AuthenticatedContentTBM = {
      contentTbs: toTbs(content.content, "mls_public_message", groupContext),
      auth: content.auth,
    }

    const tag = await createMembershipTag(membershipKey, authenticatedContent, cs.hash)
    return {
      content: content.content,
      auth: content.auth,
      senderType: "member",
      membershipTag: tag,
    }
  }

  return {
    content: content.content,
    auth: content.auth,
    senderType: content.content.sender.senderType,
  }
}

export async function unprotectPublicMessage(
  membershipKey: Uint8Array,
  groupContext: GroupContext,
  msg: PublicMessage,
  cs: CiphersuiteImpl,
): Promise<AuthenticatedContent> {
  if (msg.content.contentType === "application") throw new Error("Can't make an application message public")

  if (msg.senderType == "member") {
    const authenticatedContent: AuthenticatedContentTBM = {
      contentTbs: toTbs(msg.content, "mls_public_message", groupContext),
      auth: msg.auth,
    }

    if (!(await verifyMembershipTag(membershipKey, authenticatedContent, msg.membershipTag, cs.hash)))
      throw new Error("Could not verify membership")
  }

  //todo verify signature & MAC

  return {
    wireformat: "mls_public_message",
    content: msg.content,
    auth: msg.auth,
  }
}
