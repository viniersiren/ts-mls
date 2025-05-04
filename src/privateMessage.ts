import { decodeUint64, encodeUint64 } from "./codec/number"
import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { ContentTypeName, decodeContentType, encodeContentType } from "./contentType"

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
