import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
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
} from "./framedContent"
import { decodeWireformat, encodeWireformat, WireformatName } from "./message"

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
    flatMapDecoder(decodeFramedContent, (content) =>
      mapDecoder(decodeFramedContentAuthData(content.contentType), (auth) => ({ content, auth })),
    ),
  ],
  (wireformat, contentAuth) => ({
    wireformat,
    ...contentAuth,
  }),
)

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
