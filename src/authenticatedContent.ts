import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Hash } from "./crypto/hash"
import {
  decodeFramedContent,
  decodeFramedContentAuthData,
  decodeFramedContentTBS,
  encodeFramedContent,
  encodeFramedContentAuthData,
  encodeFramedContentTBS,
  FramedContent,
  FramedContentAuthData,
  FramedContentTBS,
  FramedContentTBSExternal,
  signFramedContent,
  toTbs,
  verifyFramedContent,
} from "./framedContent"
import { GroupContext } from "./groupContext"
import { decodeWireformat, encodeWireformat, WireformatName } from "./wireformat"
import { MemberPublicMessage, PublicMessage } from "./publicMessage"

export type AuthenticatedContent = Readonly<{
  wireformat: WireformatName
  content: FramedContent
  auth: FramedContentAuthData
}>

export const encodeAuthenticatedContent: Encoder<AuthenticatedContent> = contramapEncoders(
  [encodeWireformat, encodeFramedContent, encodeFramedContentAuthData],
  (a) => [a.wireformat, a.content, a.auth] as const,
)

export const decodeAuthenticatedContent: Decoder<AuthenticatedContent> = mapDecoders(
  [
    decodeWireformat,
    flatMapDecoder(decodeFramedContent, (content) => {
      return mapDecoder(decodeFramedContentAuthData(content.contentType), (auth) => ({ content, auth }))
    }),
  ],
  (wireformat, contentAuth) => ({
    wireformat,
    ...contentAuth,
  }),
)

export function toTbm(content: AuthenticatedContent, context: GroupContext): AuthenticatedContentTBM {
  return { auth: content.auth, contentTbs: toTbs(content.content, content.wireformat, context) }
}

export type AuthenticatedContentTBM = {
  contentTbs: FramedContentTBS
  auth: FramedContentAuthData
}

export const encodeAuthenticatedContentTBM: Encoder<AuthenticatedContentTBM> = contramapEncoders(
  [encodeFramedContentTBS, encodeFramedContentAuthData],
  (t) => [t.contentTbs, t.auth] as const,
)

export const decodeAuthenticatedContentTBM: Decoder<AuthenticatedContentTBM> = flatMapDecoder(
  decodeFramedContentTBS,
  (contentTbs) =>
    mapDecoder(decodeFramedContentAuthData(contentTbs.content.contentType), (auth) => ({
      contentTbs,
      auth,
    })),
)

export async function createPublicMessage(
  signKey: Uint8Array,
  confirmationKey: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  tbs: FramedContentTBSExternal,
  cs: CiphersuiteImpl,
): Promise<PublicMessage> {
  const auth = await signFramedContent(signKey, confirmationKey, confirmedTranscriptHash, tbs, cs)
  return { auth, content: tbs.content, senderType: tbs.senderType }
}

export async function verifyPublicMessage(
  signKey: Uint8Array,
  confirmationKey: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  tbs: FramedContentTBSExternal,
  msg: PublicMessage,
  cs: CiphersuiteImpl,
): Promise<boolean> {
  return verifyFramedContent(signKey, confirmationKey, confirmedTranscriptHash, tbs, msg.auth, cs)
}

export async function createPublicMessageMember(
  signKey: Uint8Array,
  confirmationKey: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  membershipKey: Uint8Array,
  tbs: FramedContentTBS,
  cs: CiphersuiteImpl,
): Promise<MemberPublicMessage> {
  const auth = await signFramedContent(signKey, confirmationKey, confirmedTranscriptHash, tbs, cs)
  const tbm = { auth, contentTbs: tbs }

  const tag = await createMembershipTag(membershipKey, tbm, cs.hash)

  return { auth, content: tbs.content, senderType: "member", membershipTag: new Uint8Array(tag) }
}

export async function verifyPublicMessageMember(
  signKey: Uint8Array,
  confirmationKey: Uint8Array,
  confirmedTranscriptHash: Uint8Array,
  membershipKey: Uint8Array,
  tbs: FramedContentTBS,
  msg: MemberPublicMessage,
  cs: CiphersuiteImpl,
): Promise<boolean> {
  return (
    (await verifyMembershipTag(membershipKey, { auth: msg.auth, contentTbs: tbs }, msg.membershipTag, cs.hash)) &&
    verifyFramedContent(signKey, confirmationKey, confirmedTranscriptHash, tbs, msg.auth, cs)
  )
}

export function createMembershipTag(
  membershipKey: Uint8Array,
  tbm: AuthenticatedContentTBM,
  h: Hash,
): Promise<ArrayBuffer> {
  return h.mac(membershipKey, encodeAuthenticatedContentTBM(tbm))
}

export function verifyMembershipTag(
  membershipKey: Uint8Array,
  tbm: AuthenticatedContentTBM,
  tag: Uint8Array,
  h: Hash,
): Promise<boolean> {
  return h.verifyMac(membershipKey, tag, encodeAuthenticatedContentTBM(tbm))
}
