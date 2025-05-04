import { decodeUint16, encodeUint16 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"
import { enumNumberToKey } from "./util/enumHelpers"
import { decodeWelcome, encodeWelcome, Welcome } from "./welcome"

const wireformats = {
  // mls_public_message: 1,
  mls_private_message: 2,
  mls_welcome: 3,
  // mls_group_info: 4,
  // mls_key_package: 5,
} as const

export type WireformatName = keyof typeof wireformats
export type WireformatValue = (typeof wireformats)[WireformatName]

export const encodeWireformat: Encoder<WireformatName> = contramapEncoder(encodeUint16, (t) => wireformats[t])

export const decodeWireformat: Decoder<WireformatName> = mapDecoderOption(decodeUint16, enumNumberToKey(wireformats))

type MLSMessage = MlsMessageProtocol & MlsMessageContent

type MlsMessageProtocol = { version: ProtocolVersionName }
type MlsMessageContent = WelcomeMessage | PrivateMessage
type WelcomeMessage = { wireformat: "mls_welcome"; publicMessage: Welcome }
type PrivateMessage = { wireformat: "mls_private_message"; privateMessage: Uint8Array }

//  (msg) => {
//   const x = encodeProtocolVersion(msg.version)
//   const y = encodeMlsMessageContent(msg)
//   return new Uint8Array([...x, ...y])
// }

export const encodeMlsMessageContent: Encoder<MlsMessageContent> = (mc) => {
  switch (mc.wireformat) {
    case "mls_welcome":
      return encodeWelcomeMessage(mc)
    case "mls_private_message":
      return encodePrivateMessage(mc)
  }
}

export const encodeWelcomeMessage: Encoder<WelcomeMessage> = contramapEncoders(
  [encodeWireformat, encodeWelcome],
  (wm) => [wm.wireformat, wm.publicMessage] as const,
)

export const encodePrivateMessage: Encoder<PrivateMessage> = contramapEncoders(
  [encodeWireformat, encodeVarLenData],
  (pm) => [pm.wireformat, pm.privateMessage] as const,
)

function decodeMlsMessageContent(wireformat: WireformatName): Decoder<MlsMessageContent> {
  switch (wireformat) {
    // case "mls_public_message": return mapDecoder(decodeWelcome, (w) => ({wireformat: wf, publicMessage: w}))
    case "mls_private_message":
      return mapDecoder(decodeVarLenData, (privateMessage) => ({ wireformat, privateMessage }))
    case "mls_welcome":
      return mapDecoder(decodeWelcome, (publicMessage) => ({ wireformat, publicMessage }))
    // case "mls_group_info":return mapDecoder(decodeWelcome, (w) => ({wireformat: wf, publicMessage: w}))
    // case "mls_key_package":return mapDecoder(decodeWelcome, (w) => ({wireformat: wf, publicMessage: w}))
  }
}

export const encodeMlsMessagee: Encoder<MLSMessage> = contramapEncoders(
  [encodeProtocolVersion, encodeMlsMessageContent],
  (w) => [w.version, w] as const,
)

export const decodeMlsMessage: Decoder<MLSMessage> = mapDecoders(
  [decodeProtocolVersion, flatMapDecoder(decodeWireformat, decodeMlsMessageContent)],
  (version, mc) => ({ ...mc, version }),
)
//mapDecoders([decodeProtocolVersion, decodeWireformat, decodeWelcome], (version, wireformat, publicMessage) => ({version, wireformat, publicMessage}))

// type MLSMessageContent<W extends Wireformat> = W extends "mls_public_message"
//   ? { publicMessage: PublicMessage<ContentType, SenderType> }
//   : W extends "mls_private_message"
//     ? { publicMessage: PrivateMessage }
//     : W extends "mls_welcome"
//       ? { publicMessage: Welcome }
//       : W extends "mls_group_info"
//         ? { publicMessage: GroupInfo }
//         : W extends "mls_key_package"
//           ? { publicMessage: KeyPackage }
//           : {}
