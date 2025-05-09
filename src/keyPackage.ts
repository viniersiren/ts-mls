import { Decoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { CiphersuiteName, decodeCiphersuite, encodeCiphersuite } from "./crypto/ciphersuite"
import { Hash, refhash } from "./crypto/hash"
import { Signature } from "./crypto/signature"
import { decodeExtension, encodeExtension, Extension } from "./extension"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"
import { decodeLeafNode, encodeLeafNode, LeafNode } from "./leafNode"

type KeyPackageTBS = Readonly<{
  version: ProtocolVersionName
  cipherSuite: CiphersuiteName
  initKey: Uint8Array
  leafNode: LeafNode
  extensions: Extension[]
}>

export const encodeKeyPackageTBS: Encoder<KeyPackageTBS> = contramapEncoders(
  [encodeProtocolVersion, encodeCiphersuite, encodeVarLenData, encodeLeafNode, encodeVarLenType(encodeExtension)],
  (keyPackageTBS) =>
    [
      keyPackageTBS.version,
      keyPackageTBS.cipherSuite,
      keyPackageTBS.initKey,
      keyPackageTBS.leafNode,
      keyPackageTBS.extensions,
    ] as const,
)

export const decodeKeyPackageTBS: Decoder<KeyPackageTBS> = mapDecoders(
  [decodeProtocolVersion, decodeCiphersuite, decodeVarLenData, decodeLeafNode, decodeVarLenType(decodeExtension)],
  (version, cipherSuite, initKey, leafNode, extensions) => ({
    version,
    cipherSuite,
    initKey,
    leafNode,
    extensions,
  }),
)

export type KeyPackage = KeyPackageTBS & Readonly<{ signature: Uint8Array }>

export const encodeKeyPackage: Encoder<KeyPackage> = contramapEncoders(
  [encodeKeyPackageTBS, encodeVarLenData],
  (keyPackage) => [keyPackage, keyPackage.signature] as const,
)

export const decodeKeyPackage: Decoder<KeyPackage> = mapDecoders(
  [decodeKeyPackageTBS, decodeVarLenData],
  (keyPackageTBS, signature) => ({
    ...keyPackageTBS,
    signature,
  }),
)

export function verifySignature(kp: KeyPackage, s: Signature): boolean {
  return s.verify(kp.leafNode.signatureKey, encodeKeyPackageTBS(kp), kp.signature)
}

export function makeKeyPackageRef(value: KeyPackage, h: Hash) {
  return refhash("MLS 1.0 KeyPackage Reference", encodeKeyPackage(value), h)
}
