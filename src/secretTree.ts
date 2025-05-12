import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Kdf, expandWithLabel, deriveTreeSecret } from "./crypto/kdf"
import { nodeWidth, root, right, isLeaf, left } from "./treemath"
import { repeatAsync } from "./util/repeat"

export type SecretTree = Uint8Array[]
export function setSecret(tree: SecretTree, nodeIndex: number, secret: Uint8Array): SecretTree {
  return [...tree.slice(0, nodeIndex), secret, ...tree.slice(nodeIndex + 1)]
}

export function createSecretTree(leafWidth: number, encryptionSecret: Uint8Array, kdf: Kdf): Promise<SecretTree> {
  const tree = new Array(nodeWidth(leafWidth))
  const rootIndex = root(leafWidth)

  const parentInhabited = setSecret(tree, rootIndex, encryptionSecret)
  return deriveChildren(parentInhabited, rootIndex, kdf)
}

export async function deriveChildren(tree: SecretTree, nodeIndex: number, kdf: Kdf): Promise<SecretTree> {
  if (isLeaf(nodeIndex)) return tree
  const l = left(nodeIndex)

  const r = right(nodeIndex)

  const parentSecret = tree[nodeIndex]
  if (parentSecret === undefined) throw new Error("Bad node index for secret tree")
  const leftSecret = await expandWithLabel(parentSecret, "tree", new TextEncoder().encode("left"), kdf.size, kdf)

  const rightSecret = await expandWithLabel(parentSecret, "tree", new TextEncoder().encode("right"), kdf.size, kdf)

  const currentTree = setSecret(setSecret(tree, l, leftSecret), r, rightSecret)

  return deriveChildren(await deriveChildren(currentTree, l, kdf), r, kdf)
}

export async function deriveNonce(secret: Uint8Array, generation: number, cs: CiphersuiteImpl) {
  return await deriveTreeSecret(secret, "nonce", generation, cs.hpke.nonceLength, cs.kdf)
}

export async function ratchetUntil(current: GenerationSecret, desiredGen: number, kdf: Kdf): Promise<GenerationSecret> {
  if (current.generation > desiredGen) throw new Error("Desired gen in the past")
  const generationDifference = desiredGen - current.generation

  return await repeatAsync((s) => deriveNext(s.secret, s.generation, kdf), current, generationDifference)
}

export async function deriveNext(secret: Uint8Array, generation: number, kdf: Kdf): Promise<GenerationSecret> {
  const s = await deriveTreeSecret(secret, "secret", generation, kdf.size, kdf)
  return { secret: s, generation: generation + 1 }
}

export async function deriveKey(secret: Uint8Array, generation: number, cs: CiphersuiteImpl) {
  return await deriveTreeSecret(secret, "key", generation, cs.hpke.keyLength, cs.kdf)
}

export type GenerationSecret = { secret: Uint8Array; generation: number }

export async function deriveRatchetRoot(
  tree: SecretTree,
  nodeIndex: number,
  label: string,
  kdf: Kdf,
): Promise<GenerationSecret> {
  const node = tree[nodeIndex]
  if (node === undefined) throw new Error("Bad node index for secret tree")
  const secret = await expandWithLabel(node, label, new Uint8Array(), kdf.size, kdf)
  return { secret: secret, generation: 0 }
}
