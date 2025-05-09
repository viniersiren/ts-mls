import { Encoder, contramapEncoder, contramapEncoders } from "./codec/tlsEncoder"
import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder"

import { decodeVarLenType, encodeVarLenType } from "./codec/variableLength"
import { decodeNodeType, encodeNodeType } from "./nodeType"
import { decodeOptional, encodeOptional } from "./codec/optional"
import { ParentNode, encodeParentNode, decodeParentNode } from "./parentNode"
import { directPath, isLeaf, leafToNodeIndex, leafWidth, nodeToLeafIndex } from "./treemath"
import { LeafNode, encodeLeafNode, decodeLeafNode } from "./leafNode"

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

export function extendRatchetTree(tree: RatchetTree): RatchetTree {
  const lastIndex = tree.length - 1

  if (tree[lastIndex] === undefined) {
    throw new Error("The last node in the ratchet tree must be non-blank.")
  }

  // Compute the smallest full binary tree size >= current length
  const neededSize = nextFullBinaryTreeSize(tree.length)

  // Fill with `undefined` until tree has the needed size
  const copy = tree.slice()
  while (copy.length < neededSize) {
    copy.push(undefined)
  }

  return copy
}

// Compute the smallest 2^(d + 1) - 1 >= n
function nextFullBinaryTreeSize(n: number): number {
  let d = 0
  while ((1 << (d + 1)) - 1 < n) {
    d++
  }
  return (1 << (d + 1)) - 1
}

export function stripToMinimalCompleteTree(tree: RatchetTree): RatchetTree {
  const lastNonBlankIndex = findLastNonBlankIndex(tree)

  // Find the smallest 2^(d+1)-1 that is >= lastNonBlankIndex + 1
  // Then subtract one power to go to the next smaller full tree size
  let fullSize = 1
  while (fullSize <= lastNonBlankIndex) {
    fullSize = 2 * fullSize + 1
  }

  // Go one step back to get the last complete tree size <= lastNonBlankIndex
  let trimmedSize = Math.floor((fullSize - 1) / 2)

  return tree.slice(0, trimmedSize + 1)
}

function findLastNonBlankIndex(tree: RatchetTree): number {
  for (let i = tree.length - 1; i >= 0; i--) {
    if (tree[i] !== undefined) return i
  }
  return 0
}

/**
 * If the tree has 2d leaves, then it has 2d+1 - 1 nodes.
 * The ratchet_tree vector logically has this number of entries, but the sender MUST NOT include blank nodes after the last non-blank node.
 * The receiver MUST check that the last node in ratchet_tree is non-blank, and then extend the tree to the right until it has a length of the form 2d+1 - 1, adding the minimum number of blank values possible.
 * (Obviously, this may be done "virtually", by synthesizing blank nodes when required, as opposed to actually changing the structure in memory.)
 */
export function stripBlankNodes(tree: RatchetTree): RatchetTree {
  let lastNonBlank = tree.length - 1
  while (lastNonBlank >= 0 && tree[lastNonBlank] === undefined) {
    lastNonBlank--
  }

  return tree.slice(0, lastNonBlank + 1)
}

export const encodeRatchetTree: Encoder<RatchetTree> = contramapEncoder(
  encodeVarLenType(encodeOptional(encodeNode)),
  stripBlankNodes,
)

export const decodeRatchetTree: Decoder<RatchetTree> = mapDecoder(
  decodeVarLenType(decodeOptional(decodeNode)),
  extendRatchetTree,
)

function findBlankLeafNodeIndex(tree: RatchetTree): number | undefined {
  const nodeIndex = tree.findIndex((node, nodeIndex) => node === undefined && isLeaf(nodeIndex))
  if (nodeIndex < 0) return undefined
  else return nodeIndex
}

export function extendTree(tree: RatchetTree, leafNode: LeafNode): [RatchetTree, number] {
  const newRoot = undefined
  const insertedNodeIndex = tree.length + 1
  const newTree: RatchetTree = [...tree, newRoot, { nodeType: "leaf", leaf: leafNode }, ...new Array(tree.length - 1)]
  return [newTree, insertedNodeIndex]
}

export function addLeafNode(tree: RatchetTree, leafNode: LeafNode): [RatchetTree, number] {
  const blankLeaf = findBlankLeafNodeIndex(tree)
  if (blankLeaf === undefined) {
    return extendTree(tree, leafNode)
  }

  const insertedLeafIndex = nodeToLeafIndex(blankLeaf)
  const directPathWithoutRoot = directPath(blankLeaf, leafWidth(tree.length)).slice(0, -1)

  const copy = tree.slice()

  for (const nodeIndex of directPathWithoutRoot) {
    const node = tree[nodeIndex]
    if (node !== undefined) {
      const parentNode = node as NodeParent

      const updated: NodeParent = {
        nodeType: "parent",
        parent: { ...parentNode.parent, unmergedLeaves: [...parentNode.parent.unmergedLeaves, insertedLeafIndex] },
      }
      copy[nodeIndex] = updated
    }
  }

  copy[blankLeaf] = { nodeType: "leaf", leaf: leafNode }

  return [copy, blankLeaf]
}

export function updateLeafNode(tree: RatchetTree, leafNode: LeafNode, leafIndex: number): RatchetTree {
  const leafNodeIndex = leafToNodeIndex(leafIndex)
  const pathToBlank = directPath(leafNodeIndex, leafWidth(tree.length))

  const copy = tree.slice()

  for (const nodeIndex of pathToBlank) {
    const node = tree[nodeIndex]
    if (node !== undefined) {
      copy[nodeIndex] = undefined
    }
  }
  copy[leafNodeIndex] = { nodeType: "leaf", leaf: leafNode }

  return copy
}

export function removeLeafNode(tree: RatchetTree, removedLeafIndex: number) {
  const leafNodeIndex = leafToNodeIndex(removedLeafIndex)
  const pathToBlank = directPath(leafNodeIndex, leafWidth(tree.length))

  const copy = tree.slice()

  for (const nodeIndex of pathToBlank) {
    const node = tree[nodeIndex]
    if (node !== undefined) {
      copy[nodeIndex] = undefined
    }
  }
  copy[leafNodeIndex] = undefined

  return condenseRatchetTreeAfterRemove(copy)
}

/**
 * When the right subtree of the tree no longer has any non-blank nodes, it can be safely removed
 */
function condenseRatchetTreeAfterRemove(tree: RatchetTree) {
  return extendRatchetTree(stripBlankNodes(tree))
}
