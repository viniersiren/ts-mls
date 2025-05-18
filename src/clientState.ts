import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { deriveSecret, Kdf } from "./crypto/kdf"
import { GroupContext } from "./groupContext"
import { KeySchedule } from "./keySchedule"
import { findFirstNonBlankAncestor } from "./ratchetTree"
import { RatchetTree } from "./ratchetTree"
import { SecretTree } from "./secretTree"
import { leafWidth, root } from "./treemath"

export type ClientState = {
  groupContext: GroupContext
  keySchedule: KeySchedule
  secretTree: SecretTree
  ratchetTree: RatchetTree
  privatePath: PrivatePath
}

/**
 * NodeSecret is a record with nodeIndex as keys and the path secret as values
 */
export type NodeSecret = Record<number, Uint8Array> //{ nodeIndex: number; pathSecret: Uint8Array }

export type PrivatePath = {
  leafIndex: number
  pathSecrets: NodeSecret
}

export type PrivateKeyPath = {
  leafIndex: number
  privateKeys: Record<number, Uint8Array>
}

export async function toPrivateKeyPath(pp: PrivatePath, cs: CiphersuiteImpl): Promise<PrivateKeyPath> {
  //todo: Object.fromEntries is pretty bad
  const privateKeys: Record<number, Uint8Array> = Object.fromEntries(
    await Promise.all(
      Object.entries(pp.pathSecrets).map(async ([nodeIndex, pathSecret]) => {
        const nodeSecret = await deriveSecret(pathSecret, "node", cs.kdf)
        const { privateKey } = await cs.hpke.deriveKeyPair(nodeSecret)

        return [Number(nodeIndex), await cs.hpke.exportPrivateKey(privateKey)]
      }),
    ),
  )

  return { leafIndex: pp.leafIndex, privateKeys }
}

export async function pathToRoot(
  tree: RatchetTree,
  nodeIndex: number,
  pathSecret: Uint8Array,
  kdf: Kdf,
): Promise<NodeSecret> {
  const rootIndex = root(leafWidth(tree.length))
  let currentIndex = nodeIndex
  let pathSecrets = { [nodeIndex]: pathSecret }
  while (currentIndex != rootIndex) {
    const nextIndex = findFirstNonBlankAncestor(tree, currentIndex)
    const nextSecret = await deriveSecret(pathSecrets[currentIndex]!, "path", kdf)

    pathSecrets[nextIndex] = nextSecret
    currentIndex = nextIndex
  }

  return pathSecrets
}
