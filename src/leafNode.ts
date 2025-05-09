import { Capabilities, decodeCapabilities, encodeCapabilities } from "./capabilities"
import { encodeUint32, decodeUint32 } from "./codec/number"
import { Decoder, mapDecoders, mapDecoder, flatMapDecoder, succeedDecoder, decodeVoid } from "./codec/tlsDecoder"
import { Encoder, contramapEncoders, contramapEncoder } from "./codec/tlsEncoder"
import { encodeVarLenData, decodeVarLenData, encodeVarLenType, decodeVarLenType } from "./codec/variableLength"
import { encodeCredential, decodeCredential, Credential } from "./credential"
import { Extension, encodeExtension, decodeExtension } from "./extension"
import { encodeLeafNodeSource, decodeLeafNodeSource, LeafNodeSourceName } from "./leafNodeSource"
import { Lifetime, encodeLifetime, decodeLifetime } from "./lifetime"

export type LeafNodeData = {
  encryptionKey: Uint8Array
  signatureKey: Uint8Array
  credential: Credential
  capabilities: Capabilities
}

export const encodeLeafNodeData: Encoder<LeafNodeData> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData, encodeCredential, encodeCapabilities],
  (data) => [data.encryptionKey, data.signatureKey, data.credential, data.capabilities] as const,
)

export const decodeLeafNodeData: Decoder<LeafNodeData> = mapDecoders(
  [decodeVarLenData, decodeVarLenData, decodeCredential, decodeCapabilities],
  (encryptionKey, signatureKey, credential, capabilities) => ({
    encryptionKey,
    signatureKey,
    credential,
    capabilities,
  }),
)

export type LeafNodeInfo = LeafNodeInfoKeyPackage | LeafNodeInfoUpdate | LeafNodeInfoCommit
export type LeafNodeInfoKeyPackage = { leafNodeSource: "key_package"; lifetime: Lifetime }
export type LeafNodeInfoUpdate = { leafNodeSource: "update" }
export type LeafNodeInfoCommit = { leafNodeSource: "commit"; parentHash: Uint8Array }

export const encodeLeafNodeInfoLifetime: Encoder<LeafNodeInfoKeyPackage> = contramapEncoders(
  [encodeLeafNodeSource, encodeLifetime],
  (info) => ["key_package", info.lifetime] as const,
)

export const encodeLeafNodeInfoUpdate: Encoder<LeafNodeInfoUpdate> = contramapEncoder(
  encodeLeafNodeSource,
  (i) => i.leafNodeSource,
)

export const encodeLeafNodeInfoCommit: Encoder<LeafNodeInfoCommit> = contramapEncoders(
  [encodeLeafNodeSource, encodeVarLenData],
  (info) => ["commit", info.parentHash] as const,
)

export const encodeLeafNodeInfo: Encoder<LeafNodeInfo> = (info) => {
  switch (info.leafNodeSource) {
    case "key_package":
      return encodeLeafNodeInfoLifetime(info)
    case "update":
      return encodeLeafNodeInfoUpdate(info)
    case "commit":
      return encodeLeafNodeInfoCommit(info)
  }
}

export const decodeLeafNodeInfoLifetime: Decoder<LeafNodeInfoKeyPackage> = mapDecoder(decodeLifetime, (lifetime) => ({
  leafNodeSource: "key_package",
  lifetime,
}))

export const decodeLeafNodeInfoCommit: Decoder<LeafNodeInfoCommit> = mapDecoders([decodeVarLenData], (parentHash) => ({
  leafNodeSource: "commit",
  parentHash,
}))

export const decodeLeafNodeInfo: Decoder<LeafNodeInfo> = flatMapDecoder(
  decodeLeafNodeSource,
  (leafNodeSource): Decoder<LeafNodeInfo> => {
    switch (leafNodeSource) {
      case "key_package":
        return decodeLeafNodeInfoLifetime
      case "update":
        return succeedDecoder({ leafNodeSource })
      case "commit":
        return decodeLeafNodeInfoCommit
    }
  },
)

export type LeafNodeExtensions = { extensions: Extension[] }

export const encodeLeafNodeExtensions: Encoder<LeafNodeExtensions> = contramapEncoder(
  encodeVarLenType(encodeExtension),
  (ext) => ext.extensions,
)

export const decodeLeafNodeExtensions: Decoder<LeafNodeExtensions> = mapDecoder(
  decodeVarLenType(decodeExtension),
  (extensions) => ({ extensions }),
)

type GroupIdLeafIndex = Readonly<{
  groupId: Uint8Array
  leafIndex: number
}>

export const encodeGroupIdLeafIndex: Encoder<GroupIdLeafIndex> = contramapEncoders(
  [encodeVarLenData, encodeUint32],
  (g) => [g.groupId, g.leafIndex] as const,
)

export const decodeGroupIdLeafIndex: Decoder<GroupIdLeafIndex> = mapDecoders(
  [decodeVarLenData, decodeUint32],
  (groupId, leafIndex) => ({ groupId, leafIndex }),
)

export type LeafNodeGroupInfo = GroupIdLeafIndex | {}

export const encodeLeafNodeGroupInfo: Encoder<LeafNodeGroupInfo> = (info) => {
  if ("groupId" in info) {
    return encodeGroupIdLeafIndex(info)
  }
  // If the object is an empty object, we simply return an empty array (i.e., no data to encode)
  return new Uint8Array()
}

export function decodeLeafNodeGroupInfo(lns: LeafNodeSourceName): Decoder<LeafNodeGroupInfo> {
  switch (lns) {
    case "key_package":
      return mapDecoder(decodeVoid, () => ({}))
    case "update":
      return decodeGroupIdLeafIndex
    case "commit":
      return decodeGroupIdLeafIndex
  }
}

export type LeafNodeTBS = LeafNodeData & LeafNodeInfo & LeafNodeExtensions & LeafNodeGroupInfo

export const encodeLeafNodeTBS: Encoder<LeafNodeTBS> = contramapEncoders(
  [encodeLeafNodeData, encodeLeafNodeInfo, encodeLeafNodeExtensions, encodeLeafNodeGroupInfo],
  (tbs) => [tbs, tbs, tbs, tbs] as const,
)

export const decodeLeafNodeTBS: Decoder<LeafNodeTBS> = flatMapDecoder(decodeLeafNodeData, (leafNodeData) =>
  flatMapDecoder(decodeLeafNodeInfo, (leafNodeInfo) =>
    flatMapDecoder(decodeLeafNodeExtensions, (leafNodeExtensions) =>
      mapDecoder(decodeLeafNodeGroupInfo(leafNodeInfo.leafNodeSource), (leafNodeGroupInfo) => ({
        ...leafNodeData,
        ...leafNodeInfo,
        ...leafNodeExtensions,
        ...leafNodeGroupInfo,
      })),
    ),
  ),
)

export type LeafNode = LeafNodeData & LeafNodeInfo & LeafNodeExtensions & Readonly<{ signature: Uint8Array }>

export const encodeLeafNode: Encoder<LeafNode> = contramapEncoders(
  [encodeLeafNodeData, encodeLeafNodeInfo, encodeLeafNodeExtensions, encodeVarLenData],
  (leafNode) => [leafNode, leafNode, leafNode, leafNode.signature] as const,
)

export const decodeLeafNode: Decoder<LeafNode> = mapDecoders(
  [decodeLeafNodeData, decodeLeafNodeInfo, decodeLeafNodeExtensions, decodeVarLenData],
  (data, info, extensions, signature) => ({
    ...data,
    ...info,
    ...extensions,
    signature,
  }),
)
