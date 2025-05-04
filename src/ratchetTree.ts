import { Capabilities, decodeCapabilities, encodeCapabilities } from "./capabilities"
import { Encoder, contramapEncoder, contramapEncoders } from "./codec/tlsEncoder"
import { Decoder, decodeVoid, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from "./codec/tlsDecoder"
import { decodeExtension, encodeExtension, Extension } from "./extension"

import { decodeVarLenData, decodeVarLenType, encodeVarLenData, encodeVarLenType } from "./codec/variableLength"
import { Credential, decodeCredential, encodeCredential } from "./credential"
import { decodeLifetime, encodeLifetime, Lifetime } from "./lifetime"
import { decodeLeafNodeSource, encodeLeafNodeSource, LeafNodeSourceName } from "./leafNodeSource"
import { decodeUint32, encodeUint32 } from "./codec/number"
import { decodeNodeType, encodeNodeType } from "./nodeType"
import { decodeOptional, encodeOptional } from "./codec/optional"
import { deriveTreeSecret, expandWithLabel, Kdf } from "./crypto/kdf"
import { leftOrLeaf, nodeWidth, right, root } from "./treemath"
import { CiphersuiteImpl } from "./crypto/ciphersuite"

export type LeafNodeData = {
  encryptionKey: Uint8Array
  signatureKey: Uint8Array
  credential: Credential
  capabilities: Capabilities
}

// Encoder
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

export type ParentNode = { encryptionKey: Uint8Array; parentHash: Uint8Array; unmergedLeaves: number[] }

export const encodeParentNode: Encoder<ParentNode> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData, encodeVarLenType(encodeUint32)],
  (node) => [node.encryptionKey, node.parentHash, node.unmergedLeaves] as const,
)

export const decodeParentNode: Decoder<ParentNode> = mapDecoders(
  [decodeVarLenData, decodeVarLenData, decodeVarLenType(decodeUint32)],
  (encryptionKey, parentHash, unmergedLeaves) => ({
    encryptionKey,
    parentHash,
    unmergedLeaves,
  }),
)

export type Node = NodeParent | NodeLeaf
type NodeParent = { nodeType: "parent"; parent: ParentNode }
type NodeLeaf = { nodeType: "leaf"; leaf: LeafNode }

export const encodeNode: Encoder<Node> = (node) => {
  switch (node.nodeType) {
    case "parent":
      return contramapEncoders(
        [encodeNodeType, encodeParentNode],
        (n: NodeParent) => [n.nodeType, n.parent] as const,
      )(node)
    case "leaf":
      return contramapEncoders([encodeNodeType, encodeLeafNode], (n: NodeLeaf) => [n.nodeType, n.leaf] as const)(node)
  }
}

export const decodeNode: Decoder<Node> = flatMapDecoder(decodeNodeType, (nodeType): Decoder<Node> => {
  switch (nodeType) {
    case "parent":
      return mapDecoder(decodeParentNode, (parent) => ({
        nodeType,
        parent,
      }))
    case "leaf":
      return mapDecoder(decodeLeafNode, (leaf) => ({
        nodeType,
        leaf,
      }))
  }
})

export type RatchetTree = (Node | undefined)[]

export const encodeRatchetTree: Encoder<RatchetTree> = encodeVarLenType(encodeOptional(encodeNode))

export const decodeRatchetTree: Decoder<RatchetTree> = decodeVarLenType(decodeOptional(decodeNode))

//function deriveSecretTree(totalLeaves: number, encryptionSecret: Uint8Array, )

type SecretTree = Uint8Array[]
export function setSecret(tree: SecretTree, nodeIndex: number, secret: Uint8Array): SecretTree {
  return [...tree.slice(0, nodeIndex), secret, ...tree.slice(nodeIndex + 1)]
}

export function createSecretTree(totalLeaves: number, encryptionSecret: Uint8Array, kdf: Kdf): Promise<SecretTree> {
  const tree = new Array(nodeWidth(totalLeaves))
  const rootIndex = root(totalLeaves)

  const parentInhabited = setSecret(tree, rootIndex, encryptionSecret)
  return deriveChildren(parentInhabited, rootIndex, kdf)
}

export async function deriveChildren(tree: SecretTree, nodeIndex: number, kdf: Kdf): Promise<SecretTree> {
  const l = leftOrLeaf(nodeIndex)
  if (l === undefined) return tree

  const r = right(nodeIndex)

  const parentSecret = tree[nodeIndex]
  if (parentSecret === undefined) throw new Error("Bad node index for secret tree")
  const leftSecret = await expandWithLabel(parentSecret, "tree", new TextEncoder().encode("left"), kdf.size, kdf)

  const rightSecret = await expandWithLabel(parentSecret, "tree", new TextEncoder().encode("right"), kdf.size, kdf)

  const currentTree = setSecret(setSecret(tree, l, new Uint8Array(leftSecret)), r, new Uint8Array(rightSecret))

  return deriveChildren(await deriveChildren(currentTree, l, kdf), r, kdf)
}

export async function deriveNonce(secret: Uint8Array, generation: number, cs: CiphersuiteImpl) {
  return await deriveTreeSecret(secret, "nonce", generation, cs.hpke.nonceLength, cs.kdf)
}

export async function deriveNext(secret: Uint8Array, generation: number, kdf: Kdf) {
  const s = await deriveTreeSecret(secret, "secret", generation, kdf.size, kdf)
  return { secret: s, generation: generation + 1 }
}

export async function deriveKey(secret: Uint8Array, generation: number, cs: CiphersuiteImpl) {
  return await deriveTreeSecret(secret, "key", generation, cs.hpke.keyLength, cs.kdf)
}

export async function deriveRatchetRoot(tree: SecretTree, nodeIndex: number, label: string, kdf: Kdf) {
  const node = tree[nodeIndex]
  if (node === undefined) throw new Error("Bad node index for secret tree")
  const secret = await expandWithLabel(node, label, new Uint8Array(), kdf.size, kdf)
  return { secret, generation: 0 }
}
