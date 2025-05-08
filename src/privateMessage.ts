import { AuthenticatedContent } from "./authenticatedContent"
import { decodeUint64, encodeUint64 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { Commit, decodeCommit, encodeCommit } from "./commit"
import { ContentTypeName, decodeContentType, encodeContentType } from "./contentType"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import {
  decodeFramedContent,
  decodeFramedContentAuthDataCommit,
  encodeFramedContentAuthData,
  FramedContent,
  FramedContentApplicationData,
  FramedContentAuthDataApplicationOrProposal,
  FramedContentAuthDataCommit,
  FramedContentCommitData,
  FramedContentProposalData,
  FramedContentTBSApplicationOrProposal,
  FramedContentTBSCommit,
  signFramedContentApplicationOrProposal,
  signFramedContentCommit,
} from "./framedContent"
import { GroupContext } from "./groupContext"
import { decodeProposal, encodeProposal, Proposal } from "./proposal"
import { deriveKey, deriveNonce, deriveRatchetRoot, GenerationSecret, ratchetUntil, SecretTree } from "./ratchetTree"
import {
  decodeSenderData,
  encodeSenderData,
  encodeSenderDataAAD,
  expandSenderDataKey,
  expandSenderDataNonce,
  ReuseGuard,
  SenderData,
  SenderDataAAD,
} from "./sender"
import { leafToNodeIndex } from "./treemath"
import { bytesToBuffer } from "./util/byteArray"

export type PrivateMessage = Readonly<{
  groupId: Uint8Array
  epoch: bigint
  contentType: ContentTypeName
  authenticatedData: Uint8Array
  encryptedSenderData: Uint8Array
  ciphertext: Uint8Array
}>

export const encodePrivateMessage: Encoder<PrivateMessage> = contramapEncoders(
  [encodeVarLenData, encodeUint64, encodeContentType, encodeVarLenData, encodeVarLenData, encodeVarLenData],
  (msg) =>
    [msg.groupId, msg.epoch, msg.contentType, msg.authenticatedData, msg.encryptedSenderData, msg.ciphertext] as const,
)

export const decodePrivateMessage: Decoder<PrivateMessage> = mapDecoders(
  [decodeVarLenData, decodeUint64, decodeContentType, decodeVarLenData, decodeVarLenData, decodeVarLenData],
  (groupId, epoch, contentType, authenticatedData, encryptedSenderData, ciphertext) => ({
    groupId,
    epoch,
    contentType,
    authenticatedData,
    encryptedSenderData,
    ciphertext,
  }),
)

type PrivateContentAAD = Readonly<{
  groupId: Uint8Array
  epoch: bigint
  contentType: ContentTypeName
  authenticatedData: Uint8Array
}>

export const encodePrivateContentAAD: Encoder<PrivateContentAAD> = contramapEncoders(
  [encodeVarLenData, encodeUint64, encodeContentType, encodeVarLenData],
  (aad) => [aad.groupId, aad.epoch, aad.contentType, aad.authenticatedData] as const,
)

export const decodePrivateContentAAD: Decoder<PrivateContentAAD> = mapDecoders(
  [decodeVarLenData, decodeUint64, decodeContentType, decodeVarLenData],
  (groupId, epoch, contentType, authenticatedData) => ({
    groupId,
    epoch,
    contentType,
    authenticatedData,
  }),
)

export type PrivateMessageContent =
  | PrivateMessageContentApplication
  | PrivateMessageContentProposal
  | PrivateMessageContentCommit
type PrivateMessageContentApplication = FramedContentApplicationData & {
  auth: FramedContentAuthDataApplicationOrProposal
}
type PrivateMessageContentProposal = FramedContentProposalData & { auth: FramedContentAuthDataApplicationOrProposal }
type PrivateMessageContentCommit = FramedContentCommitData & { auth: FramedContentAuthDataCommit }

//todo padding?
export function decodePrivateMessageContent(contentType: ContentTypeName): Decoder<PrivateMessageContent> {
  switch (contentType) {
    case "application":
      return mapDecoders([decodeVarLenData, decodeVarLenData], (applicationData, signature) => ({
        contentType,
        applicationData,
        auth: { contentType, signature },
      }))
    case "proposal":
      return mapDecoders([decodeProposal, decodeVarLenData], (proposal, signature) => ({
        contentType,
        proposal,
        auth: { contentType, signature },
      }))
    case "commit":
      return mapDecoders(
        [decodeCommit, decodeVarLenData, decodeFramedContentAuthDataCommit],
        (commit, signature, auth) => ({
          contentType,
          commit,
          auth: { ...auth, signature, contentType },
        }),
      )
  }
}

export const encodePrivateMessageContent: Encoder<PrivateMessageContent> = (msg) => {
  switch (msg.contentType) {
    case "application":
      return contramapEncoders(
        [encodeVarLenData, encodeFramedContentAuthData],
        (m: PrivateMessageContentApplication) => [m.applicationData, m.auth] as const,
      )(msg)

    case "proposal":
      return contramapEncoders(
        [encodeProposal, encodeFramedContentAuthData],
        (m: PrivateMessageContentProposal) => [m.proposal, m.auth] as const,
      )(msg)

    case "commit":
      return contramapEncoders(
        [encodeCommit, encodeFramedContentAuthData],
        (m: PrivateMessageContentCommit) => [m.commit, m.auth] as const,
      )(msg)
  }
}

export async function decryptSenderData(
  msg: PrivateMessage,
  senderDataSecret: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<SenderData | undefined> {
  const key = await expandSenderDataKey(cs, senderDataSecret, msg.ciphertext)
  const nonce = await expandSenderDataNonce(cs, senderDataSecret, msg.ciphertext)

  const aad: SenderDataAAD = {
    groupId: msg.groupId,
    epoch: msg.epoch,
    contentType: msg.contentType,
  }

  const decrypted = await cs.hpke.decryptAead(
    key,
    nonce,
    bytesToBuffer(encodeSenderDataAAD(aad)),
    bytesToBuffer(msg.encryptedSenderData),
  )
  return decodeSenderData(new Uint8Array(decrypted), 0)?.[0]
}

export async function encryptSenderData(
  senderDataSecret: Uint8Array,
  senderData: SenderData,
  aad: SenderDataAAD,
  ciphertext: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<Uint8Array> {
  const key = await expandSenderDataKey(cs, senderDataSecret, ciphertext)
  const nonce = await expandSenderDataNonce(cs, senderDataSecret, ciphertext)

  return new Uint8Array(
    await cs.hpke.encryptAead(
      key,
      nonce,
      bytesToBuffer(encodeSenderDataAAD(aad)),
      bytesToBuffer(encodeSenderData(senderData)),
    ),
  )
  //return decodeSenderData(new Uint8Array(decrypted), 0)?.[0]
}

// export async function encryptContent(
//   plaintext: Uint8Array,
//   secret: GenerationSecret,
//   senderDataSecret: Uint8Array,
//   cs: CiphersuiteImpl,
// ) {

// }

export async function decryptContent(
  msg: PrivateMessage,
  secret: GenerationSecret,
  reuseGuard: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<FramedContent | undefined> {
  const key = await deriveKey(secret.secret, secret.generation, cs)
  const nonce = await derivePrivateMessageNonce(secret, reuseGuard, cs)

  const aad: PrivateContentAAD = {
    groupId: msg.groupId,
    epoch: msg.epoch,
    contentType: msg.contentType,
    authenticatedData: msg.authenticatedData,
  }

  const decrypted = await cs.hpke.decryptAead(
    bytesToBuffer(key),
    bytesToBuffer(nonce),
    bytesToBuffer(encodePrivateContentAAD(aad)),
    bytesToBuffer(msg.ciphertext),
  )

  return decodeFramedContent(new Uint8Array(decrypted), 0)?.[0]
}

export async function derivePrivateMessageNonce(
  secret: GenerationSecret,
  reuseGuard: Uint8Array,
  cs: CiphersuiteImpl,
): Promise<Uint8Array> {
  const nonce = await deriveNonce(secret.secret, secret.generation, cs)

  if (nonce.length >= 4 && reuseGuard.length >= 4) {
    for (let i = 0; i < 4; i++) {
      nonce[i]! ^= reuseGuard[i]!
    }
  } else throw new Error("Reuse guard or nonce incorrect length")

  return nonce
}

function labelForContentType(contentType: ContentTypeName): string {
  switch (contentType) {
    case "application":
      return "application"
    case "proposal":
      return "handshake"
    case "commit":
      return "handshake"
  }
}

export function toAuthenticatedContent(
  content: PrivateMessageContent,
  msg: PrivateMessage,
  leafIndex: number,
): AuthenticatedContent {
  return {
    wireformat: "mls_private_message",
    content: {
      groupId: msg.groupId,
      epoch: msg.epoch,
      sender: {
        senderType: "member",
        leafIndex: leafIndex,
      },
      authenticatedData: msg.authenticatedData,
      ...content,
    },
    auth: content.auth,
  }
}

export function privateMessageContentToAuthenticatedContent(
  c: PrivateMessageContent,
  groupContext: GroupContext,
  leafIndex: number,
  authenticatedData: Uint8Array,
): AuthenticatedContent {
  return {
    wireformat: "mls_private_message",
    content: {
      ...c,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender: { senderType: "member", leafIndex },
      authenticatedData,
    },
    auth: c.auth,
  }
}

export async function protectApplicationData(
  signKey: Uint8Array,
  senderDataSecret: Uint8Array,
  applicationData: Uint8Array,
  authenticatedData: Uint8Array,
  groupContext: GroupContext,
  secretTree: SecretTree,
  leafIndex: number,
  generation: number,
  cs: CiphersuiteImpl,
): Promise<PrivateMessage> {
  const tbs: FramedContentTBSApplicationOrProposal = {
    protocolVersion: groupContext.version,
    wireformat: "mls_private_message",
    content: {
      contentType: "application",
      applicationData,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender: {
        senderType: "member",
        leafIndex: leafIndex,
      },
      authenticatedData,
    },
    senderType: "member",
    context: groupContext,
  }

  const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)

  const content = {
    ...tbs.content,
    auth,
  }

  return protect(senderDataSecret, authenticatedData, groupContext, secretTree, content, leafIndex, generation, cs)
}

export async function protectCommit(
  signKey: Uint8Array,
  senderDataSecret: Uint8Array,
  confirmationKey: Uint8Array,
  c: Commit,
  authenticatedData: Uint8Array,
  groupContext: GroupContext,
  secretTree: SecretTree,
  leafIndex: number,
  generation: number,
  cs: CiphersuiteImpl,
): Promise<PrivateMessage> {
  const tbs: FramedContentTBSCommit = {
    protocolVersion: groupContext.version,
    wireformat: "mls_private_message",
    content: {
      contentType: "commit",
      commit: c,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender: {
        senderType: "member",
        leafIndex: leafIndex,
      },
      authenticatedData,
    },
    senderType: "member",
    context: groupContext,
  }

  const auth = await signFramedContentCommit(signKey, confirmationKey, groupContext.confirmedTranscriptHash, tbs, cs)

  const content = {
    ...tbs.content,
    auth,
  }

  return protect(senderDataSecret, authenticatedData, groupContext, secretTree, content, leafIndex, generation, cs)
}

export async function protectProposal(
  signKey: Uint8Array,
  senderDataSecret: Uint8Array,
  p: Proposal,
  authenticatedData: Uint8Array,
  groupContext: GroupContext,
  secretTree: SecretTree,
  leafIndex: number,
  generation: number,
  cs: CiphersuiteImpl,
): Promise<PrivateMessage> {
  const tbs: FramedContentTBSApplicationOrProposal = {
    protocolVersion: groupContext.version,
    wireformat: "mls_private_message",
    content: {
      contentType: "proposal",
      proposal: p,
      groupId: groupContext.groupId,
      epoch: groupContext.epoch,
      sender: {
        senderType: "member",
        leafIndex: leafIndex,
      },
      authenticatedData,
    },
    senderType: "member",
    context: groupContext,
  }

  const auth = await signFramedContentApplicationOrProposal(signKey, tbs, cs)

  const content = {
    ...tbs.content,
    auth,
  }

  return protect(senderDataSecret, authenticatedData, groupContext, secretTree, content, leafIndex, generation, cs)
}

export async function protect(
  senderDataSecret: Uint8Array,
  authenticatedData: Uint8Array,
  groupContext: GroupContext,
  secretTree: SecretTree,
  content: PrivateMessageContent,
  leafIndex: number,
  generation: number,
  cs: CiphersuiteImpl,
): Promise<PrivateMessage> {
  const root = await deriveRatchetRoot(
    secretTree,
    leafToNodeIndex(leafIndex),
    labelForContentType(content.contentType),
    cs.kdf,
  )
  const secret = await ratchetUntil(root, generation, cs.kdf)
  const key = await deriveKey(secret.secret, secret.generation, cs)
  const reuseGuard = crypto.getRandomValues(new Uint8Array(4)) as ReuseGuard
  const nonce = await derivePrivateMessageNonce(secret, reuseGuard, cs)

  const aad: PrivateContentAAD = {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    contentType: content.contentType,
    authenticatedData: authenticatedData,
  }

  const ciphertext = new Uint8Array(
    await cs.hpke.encryptAead(
      bytesToBuffer(key),
      bytesToBuffer(nonce),
      bytesToBuffer(encodePrivateContentAAD(aad)),
      bytesToBuffer(encodePrivateMessageContent(content)),
    ),
  )

  const senderData: SenderData = {
    leafIndex,
    generation,
    reuseGuard,
  }

  const senderAad: SenderDataAAD = {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    contentType: content.contentType,
  }

  const encryptedSenderData = await encryptSenderData(senderDataSecret, senderData, senderAad, ciphertext, cs)

  return {
    groupId: groupContext.groupId,
    epoch: groupContext.epoch,
    encryptedSenderData,
    contentType: content.contentType,
    authenticatedData,
    ciphertext,
  }
}

export async function unprotectPrivateMessage(
  senderDataSecret: Uint8Array,
  msg: PrivateMessage,
  secretTree: SecretTree,
  cs: CiphersuiteImpl,
): Promise<PrivateMessageContent | undefined> {
  const senderData = await decryptSenderData(msg, senderDataSecret, cs)

  if (senderData === undefined) throw new Error("Could not decrypt senderdata")

  const root = await deriveRatchetRoot(
    secretTree,
    leafToNodeIndex(senderData.leafIndex),
    labelForContentType(msg.contentType),
    cs.kdf,
  )
  const secret = await ratchetUntil(root, senderData.generation, cs.kdf)
  const key = await deriveKey(secret.secret, secret.generation, cs)
  const nonce = await derivePrivateMessageNonce(secret, senderData.reuseGuard, cs)

  const aad: PrivateContentAAD = {
    groupId: msg.groupId,
    epoch: msg.epoch,
    contentType: msg.contentType,
    authenticatedData: msg.authenticatedData,
  }

  const decrypted = await cs.hpke.decryptAead(
    bytesToBuffer(key),
    bytesToBuffer(nonce),
    bytesToBuffer(encodePrivateContentAAD(aad)),
    bytesToBuffer(msg.ciphertext),
  )

  //todo verify signature & MAC

  return decodePrivateMessageContent(msg.contentType)(new Uint8Array(decrypted), 0)?.[0]
}
