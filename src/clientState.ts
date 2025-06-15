import { addToMap } from "./util/addToMap"
import { AuthenticatedContent, AuthenticatedContentCommit, makeProposalRef } from "./authenticatedContent"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { Hash } from "./crypto/hash"
import { decryptWithLabel } from "./crypto/hpke"
import { deriveSecret, Kdf } from "./crypto/kdf"
import { Extension } from "./extension"
import {
  createConfirmationTag,
  FramedContentAuthDataCommit,
  FramedContentCommit,
  FramedContentTBSCommit,
  signFramedContentTBS,
  verifyConfirmationTag,
} from "./framedContent"
import { encodeGroupContext, GroupContext } from "./groupContext"
import {
  GroupInfoTBS,
  ratchetTreeFromExtension,
  signGroupInfo,
  verifyGroupInfoConfirmationTag,
  verifyGroupInfoSignature,
} from "./groupInfo"
import { KeyPackage, makeKeyPackageRef, PrivateKeyPackage } from "./keyPackage"
import { deriveKeySchedule, initializeEpoch, initializeKeySchedule, KeySchedule } from "./keySchedule"
import { computePskSecret, PreSharedKeyID, updatePskSecret } from "./presharedkey"
import { PrivateMessage, protect, unprotectPrivateMessage } from "./privateMessage"
import {
  Proposal,
  ProposalAdd,
  ProposalExternalInit,
  ProposalGroupContextExtensions,
  ProposalPSK,
  ProposalReinit,
  ProposalRemove,
  ProposalUpdate,
} from "./proposal"

import { protectPublicMessage, PublicMessage, unprotectPublicMessage } from "./publicMessage"
import { addLeafNode, findFirstNonBlankAncestor, findLeafIndex, removeLeafNode, updateLeafNode } from "./ratchetTree"
import { RatchetTree } from "./ratchetTree"
import { createSecretTree, SecretTree } from "./secretTree"
import { getSenderLeafNodeIndex, Sender } from "./sender"
import { createConfirmedHash, createInterimHash } from "./transcriptHash"
import { treeHashRoot } from "./treeHash"
import { leafToNodeIndex, leafWidth, root } from "./treemath"
import {
  PathSecret,
  UpdatePath,
  applyUpdatePath,
  createUpdatePath,
  firstCommonAncestor,
  firstMatchAncestor,
} from "./updatePath"
import { base64ToBytes, bytesToBase64 } from "./util/byteArray"
import { constantTimeEqual } from "./util/constantTimeCompare"
import {
  decryptGroupInfo,
  decryptGroupSecrets,
  EncryptedGroupSecrets,
  encryptGroupInfo,
  encryptGroupSecrets,
  Welcome,
} from "./welcome"
import { WireformatName } from "./wireformat"
import { ProposalOrRef } from "./proposalOrRefType"
import { MLSMessage } from "./message"

export type ClientState = {
  groupContext: GroupContext
  keySchedule: KeySchedule
  secretTree: SecretTree
  ratchetTree: RatchetTree
  privatePath: PrivateKeyPath
  signaturePrivateKey: Uint8Array
  unappliedProposals: UnappliedProposals
  confirmationTag: Uint8Array
  historicalResumptionPsks: Map<bigint, Uint8Array>
}

export type ProposalWithSender = { proposal: Proposal; senderLeafIndex: number | undefined }
export type UnappliedProposals = Record<string, ProposalWithSender>

/**
 * NodeSecret is a record with nodeIndex as keys and the path secret as values
 */
export type NodeSecrets = Record<number, Uint8Array> //{ nodeIndex: number; pathSecret: Uint8Array }

function pathToNodeSecrets(pathSecrets: PathSecret[]): NodeSecrets {
  return pathSecrets.reduce(
    (acc, cur) => ({
      ...acc,
      [cur.nodeIndex]: cur.secret,
    }),
    {},
  )
}

export type PrivateKeyPath = {
  leafIndex: number
  privateKeys: Record<number, Uint8Array>
}

function mergePrivateKeyPaths(a: PrivateKeyPath, b: PrivateKeyPath): PrivateKeyPath {
  return { ...a, privateKeys: { ...a.privateKeys, ...b.privateKeys } }
}

export async function toPrivateKeyPath(
  nodeSecrets: NodeSecrets,
  leafIndex: number,
  cs: CiphersuiteImpl,
): Promise<PrivateKeyPath> {
  //todo: Object.fromEntries is pretty bad
  const privateKeys: Record<number, Uint8Array> = Object.fromEntries(
    await Promise.all(
      Object.entries(nodeSecrets).map(async ([nodeIndex, pathSecret]) => {
        const nodeSecret = await deriveSecret(pathSecret, "node", cs.kdf)
        const { privateKey } = await cs.hpke.deriveKeyPair(nodeSecret)

        return [Number(nodeIndex), await cs.hpke.exportPrivateKey(privateKey)]
      }),
    ),
  )

  return { leafIndex, privateKeys }
}

export async function getCommitSecret(
  tree: RatchetTree,
  nodeIndex: number,
  pathSecret: Uint8Array,
  kdf: Kdf,
): Promise<Uint8Array> {
  const rootIndex = root(leafWidth(tree.length))
  const path = await pathToRoot(tree, nodeIndex, pathSecret, kdf)
  const rootSecret = path[rootIndex]

  if (rootSecret === undefined) throw new Error("Could not find secret for root")
  return deriveSecret(rootSecret, "path", kdf)
}

export async function pathToRoot(
  tree: RatchetTree,
  nodeIndex: number,
  pathSecret: Uint8Array,
  kdf: Kdf,
): Promise<NodeSecrets> {
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

type R =
  | {
      kind: "newState"
      newState: ClientState
    }
  | { kind: "applicationMessage"; message: Uint8Array }

/**
 * Process private message and apply proposal or commit and return the updated ClientState or return an application message
 */
export async function processPrivateMessage(
  state: ClientState,
  pm: PrivateMessage,
  psks: Record<string, Uint8Array>,
  cs: CiphersuiteImpl,
): Promise<R> {
  const result = await unprotectPrivateMessage(state.keySchedule.senderDataSecret, pm, state.secretTree, cs)

  if (result.content.content.contentType === "application") {
    return { kind: "applicationMessage", message: result.content.content.applicationData }
  } else if (result.content.content.contentType === "commit") {
    return {
      kind: "newState",
      newState: await processCommit(state, result.content as AuthenticatedContentCommit, psks, cs), //todo solve with types
    }
  } else {
    return {
      kind: "newState",
      newState: await processProposal(state, result.content, result.content.content.proposal, cs.hash),
    }
  }
}

export async function processPublicMessage(
  state: ClientState,
  pm: PublicMessage,
  psks: Record<string, Uint8Array>,
  cs: CiphersuiteImpl,
): Promise<ClientState> {
  const content = await unprotectPublicMessage(state.keySchedule.membershipKey, state.groupContext, pm, cs)

  if (content === undefined) throw new Error("Could not unprotect private message")

  if (content.content.contentType === "proposal")
    return processProposal(state, content, content.content.proposal, cs.hash)
  else {
    return processCommit(state, content as AuthenticatedContentCommit, psks, cs) //todo solve with types
  }
}

async function processCommit(
  state: ClientState,
  content: AuthenticatedContentCommit,
  psks: Record<string, Uint8Array<ArrayBufferLike>>,
  cs: CiphersuiteImpl,
) {
  const senderLeafIndex = content.content.sender.senderType === "member" ? content.content.sender.leafIndex : undefined

  const result = await applyProposals(state, content.content.commit.proposals, senderLeafIndex, psks, cs)

  if (result.needsUpdatePath && content.content.commit.path === undefined) throw new Error("Update path is required")

  const groupContextWithExtensions =
    result.extensions.length === 0 ? state.groupContext : { ...state.groupContext, extensions: result.extensions }

  result.addedLeafNodes

  const [pkp, commitSecret, tree] = await applyTreeUpdate(
    content.content.commit.path,
    content.content.sender,
    result.tree,
    cs,
    state,
    groupContextWithExtensions,
    result.addedLeafNodes.map((l) => l[0]),
    cs.kdf,
  ) //: [state.privatePath, new Uint8Array(cs.kdf.size), x.tree]

  const newTreeHash = await treeHashRoot(tree, cs.hash)

  if (content.auth.contentType !== "commit") throw new Error("Received content as commit, but not auth") //todo solve this with types?
  const updatedGroupContext = await nextEpochContext(
    groupContextWithExtensions,
    "mls_public_message",
    content.content,
    content.auth.signature,
    newTreeHash,
    state.confirmationTag,
    result.extensions,
    cs.hash,
  )

  // console.log(x.pskSecret)
  // console.log(commitSecret)
  // console.log(updatedGroupContext)
  const epochSecrets = await initializeEpoch(
    state.keySchedule.initSecret,
    commitSecret,
    updatedGroupContext,
    result.pskSecret,
    cs.kdf,
  )

  // console.log(epochSecrets.keySchedule.confirmationKey)
  // console.log(updatedGroupContext.confirmedTranscriptHash)
  // console.log(content.auth.confirmationTag)

  const confirmationTagValid = await verifyConfirmationTag(
    epochSecrets.keySchedule.confirmationKey,
    content.auth.confirmationTag,
    updatedGroupContext.confirmedTranscriptHash,
    cs.hash,
  )

  if (!confirmationTagValid) throw new Error("Could not verify confirmation tag")

  return {
    ...state,
    ratchetTree: tree,
    privatePath: pkp,
    groupContext: updatedGroupContext,
    keySchedule: epochSecrets.keySchedule,
    confirmationTag: content.auth.confirmationTag,
    historicalResumptionPsks: addToMap(
      state.historicalResumptionPsks,
      state.groupContext.epoch,
      state.keySchedule.resumptionPsk,
    ),
  }
}

function filterNewLeaves(resolution: number[], excludeLeaves: number[]): number[] {
  const set = new Set(excludeLeaves)
  return resolution.filter((i) => !set.has(i))
}

async function applyTreeUpdate(
  path: UpdatePath | undefined,
  sender: Sender,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
  state: ClientState,
  groupContext: GroupContext,
  excludeLeaves: number[],
  kdf: Kdf,
): Promise<[PrivateKeyPath, Uint8Array, RatchetTree]> {
  if (path === undefined) return [state.privatePath, new Uint8Array(kdf.size), tree] as const
  if (sender.senderType === "member") {
    const updatedTree = await applyUpdatePath(tree, sender.leafIndex, path, cs.hash)

    const [pkp, commitSecret] = await updatePrivateKeyPath(
      updatedTree,
      state,
      sender.leafIndex,
      { ...groupContext, treeHash: await treeHashRoot(updatedTree, cs.hash), epoch: groupContext.epoch + 1n },
      path,
      excludeLeaves,
      cs,
    )
    return [pkp, commitSecret, updatedTree] as const
  } else {
    const [treeWithLeafNode, leafNodeIndex] = addLeafNode(tree, path.leafNode)
    const updatedTree = await applyUpdatePath(treeWithLeafNode, leafNodeIndex, path, cs.hash)
    const [pkp, commitSecret] = await updatePrivateKeyPath(
      updatedTree,
      state,
      leafNodeIndex,
      { ...groupContext, treeHash: await treeHashRoot(updatedTree, cs.hash), epoch: groupContext.epoch + 1n },
      path,
      excludeLeaves,
      cs,
    )
    return [pkp, commitSecret, updatedTree] as const
  }
}

async function updatePrivateKeyPath(
  tree: RatchetTree,
  state: ClientState,
  leafNodeIndex: number,
  groupContext: GroupContext,
  path: UpdatePath,
  excludeLeaves: number[],
  cs: CiphersuiteImpl,
): Promise<[PrivateKeyPath, Uint8Array]> {
  const secret = await applyUpdatePathSecret(
    tree,
    state.privatePath,
    leafNodeIndex,
    groupContext,
    path,
    excludeLeaves,
    cs,
  )
  const pathSecrets = await pathToRoot(tree, secret.nodeIndex, secret.pathSecret, cs.kdf)
  const newPkp = mergePrivateKeyPaths(
    state.privatePath,
    await toPrivateKeyPath(pathSecrets, state.privatePath.leafIndex, cs),
  )

  const rootIndex = root(leafWidth(tree.length))
  const rootSecret = pathSecrets[rootIndex]
  if (rootSecret === undefined) throw new Error("Could not find secret for root")

  const commitSecret = await deriveSecret(rootSecret, "path", cs.kdf)
  return [newPkp, commitSecret] as const
}

async function processProposal(
  state: ClientState,
  content: AuthenticatedContent,
  proposal: Proposal,
  h: Hash,
): Promise<ClientState> {
  const ref = await makeProposalRef(content, h)
  const r = bytesToBase64(ref)
  return {
    ...state,
    unappliedProposals: {
      ...state.unappliedProposals,
      [r]: { proposal, senderLeafIndex: getSenderLeafNodeIndex(content.content.sender) },
    },
  }
}

type Proposals = {
  add: { senderLeafIndex: number | undefined; proposal: ProposalAdd }[]
  update: { senderLeafIndex: number | undefined; proposal: ProposalUpdate }[]
  remove: { senderLeafIndex: number | undefined; proposal: ProposalRemove }[]
  psk: { senderLeafIndex: number | undefined; proposal: ProposalPSK }[]
  reinit: { senderLeafIndex: number | undefined; proposal: ProposalReinit }[]
  external_init: { senderLeafIndex: number | undefined; proposal: ProposalExternalInit }[]
  group_context_extensions: { senderLeafIndex: number | undefined; proposal: ProposalGroupContextExtensions }[]
}

const emptyProposals: Proposals = {
  add: [],
  update: [],
  remove: [],
  psk: [],
  reinit: [],
  external_init: [],
  group_context_extensions: [],
}

// type CommitResult = {
//   clientState: ClientState
//   commit: Commit
//   welcomes: Welcome[]
// }

type ApplyProposalsResult = {
  tree: RatchetTree
  extensions: Extension[]
  pskSecret: Uint8Array<ArrayBufferLike>
  pskIds: PreSharedKeyID[]
  addedLeafNodes: [number, KeyPackage][]
  needsUpdatePath: boolean
}

async function applyProposals(
  state: ClientState,
  proposals: ProposalOrRef[],
  senderLeafIndex: number | undefined,
  psks: Record<string, Uint8Array>,
  cs: CiphersuiteImpl,
): Promise<ApplyProposalsResult> {
  const allProposals = proposals.reduce((acc, cur) => {
    if (cur.proposalOrRefType === "proposal") return [...acc, { proposal: cur.proposal, senderLeafIndex }]

    const p = state.unappliedProposals[bytesToBase64(cur.reference)]
    if (p === undefined) throw new Error("Could not find proposal with supplied reference")
    return [...acc, p]
  }, [] as ProposalWithSender[])

  const grouped = allProposals.reduce((acc, cur) => {
    const proposal = acc[cur.proposal.proposalType] ?? []
    return { ...acc, [cur.proposal.proposalType]: [...proposal, cur] }
  }, emptyProposals)

  const newExtensions = grouped.group_context_extensions.reduce((acc, { proposal }) => {
    return [...acc, ...proposal.groupContextExtensions.extensions]
  }, [] as Extension[])

  const treeAfterUpdate = grouped.update.reduce((acc, { senderLeafIndex, proposal }) => {
    if (senderLeafIndex === undefined) throw new Error("No sender index found for update proposal")
    return updateLeafNode(acc, proposal.update.leafNode, senderLeafIndex)
  }, state.ratchetTree)

  const treeAfterRemove = grouped.remove.reduce((acc, { proposal }) => {
    return removeLeafNode(acc, proposal.remove.removed)
  }, treeAfterUpdate)

  const [treeAfterAdd, addedLeafNodes] = grouped.add.reduce(
    (acc, { proposal }) => {
      const [tree, ws] = acc
      const [updatedTree, leafNodeIndex] = addLeafNode(tree, proposal.add.keyPackage.leafNode)
      return [updatedTree, [...ws, [leafNodeIndex, proposal.add.keyPackage] as [number, KeyPackage]]]
    },
    [treeAfterRemove, []] as [RatchetTree, [number, KeyPackage][]],
  )

  const zeroes: Uint8Array = new Uint8Array(cs.kdf.size)

  const [updatedPskSecret, pskIds] = await grouped.psk.reduce(
    async (acc, cur, index) => {
      const [previousSecret, ids] = await acc
      const psk = findPsk(state, psks, cur.proposal.psk.preSharedKeyId)
      if (psk === undefined) throw new Error("Could not find pskId referenced in proposal")

      const pskSecret = await updatePskSecret(
        previousSecret,
        cur.proposal.psk.preSharedKeyId,
        psk,
        index,
        grouped.psk.length,
        cs,
      )
      return [pskSecret, [...ids, cur.proposal.psk.preSharedKeyId]]
    },
    Promise.resolve([zeroes, [] as PreSharedKeyID[]] as const),
  )

  const needsUpdatePath =
    allProposals.length === 0 || Object.values(grouped.update).length > 1 || Object.values(grouped.remove).length > 1

  const res = {
    tree: treeAfterAdd,
    extensions: newExtensions,
    pskSecret: updatedPskSecret,
    pskIds,
    addedLeafNodes,
    needsUpdatePath,
  }

  return res
}

export async function createCommit(
  state: ClientState,
  psks: Record<string, Uint8Array>,
  publicMessage: boolean,
  cs: CiphersuiteImpl,
) {
  const proposals: ProposalOrRef[] = Object.keys(state.unappliedProposals).map((p) => ({
    proposalOrRefType: "reference",
    reference: base64ToBytes(p),
  }))

  const res = await applyProposals(state, proposals, state.privatePath.leafIndex, psks, cs)

  const [tree, updatePath, pathSecrets] = res.needsUpdatePath
    ? await createUpdatePath(state.ratchetTree, state.privatePath.leafIndex, state.groupContext, new Uint8Array(), cs)
    : [state.ratchetTree, undefined, [] as PathSecret[]]

  const privateKeys = await toPrivateKeyPath(pathToNodeSecrets(pathSecrets), state.privatePath.leafIndex, cs)

  const lastPathSecret = pathSecrets.at(-1)

  const commitSecret =
    lastPathSecret === undefined
      ? new Uint8Array(cs.kdf.size)
      : await deriveSecret(lastPathSecret.secret, "path", cs.kdf)

  const wireformat = publicMessage ? "mls_public_message" : "mls_private_message"

  const authenticatedData = new Uint8Array()

  const tbs: FramedContentTBSCommit = {
    protocolVersion: state.groupContext.version,
    wireformat: "mls_private_message",
    content: {
      contentType: "commit",
      commit: { proposals, path: updatePath },
      groupId: state.groupContext.groupId,
      epoch: state.groupContext.epoch,
      sender: {
        senderType: "member",
        leafIndex: state.privatePath.leafIndex,
      },
      authenticatedData,
    },
    senderType: "member",
    context: state.groupContext,
  }

  const signature = signFramedContentTBS(state.signaturePrivateKey, tbs, cs.signature)

  const treeHash = await treeHashRoot(tree, cs.hash)

  const updatedGroupContext = await nextEpochContext(
    state.groupContext,
    wireformat,
    tbs.content,
    signature,
    treeHash,
    state.confirmationTag,
    res.extensions,
    cs.hash,
  )

  const epochSecrets = await initializeEpoch(
    state.keySchedule.initSecret,
    commitSecret,
    updatedGroupContext,
    res.pskSecret,
    cs.kdf,
  )

  const confirmationTag = await createConfirmationTag(
    epochSecrets.keySchedule.confirmationKey,
    updatedGroupContext.confirmedTranscriptHash,
    cs.hash,
  )

  const groupInfoTbs: GroupInfoTBS = {
    groupContext: updatedGroupContext,
    extensions: updatedGroupContext.extensions,
    confirmationTag,
    signer: state.privatePath.leafIndex,
  }

  const groupInfo = signGroupInfo(groupInfoTbs, state.signaturePrivateKey, cs.signature)

  const encryptedGroupInfo = await encryptGroupInfo(groupInfo, epochSecrets.welcomeSecret, cs)

  const encryptedGroupSecrets: EncryptedGroupSecrets[] = await Promise.all(
    res.addedLeafNodes.map(async ([leafNodeIndex, keyPackage]) => {
      const nodeIndex = firstCommonAncestor(tree, leafNodeIndex, state.privatePath.leafIndex)
      const pathSecret = pathSecrets.find((ps) => ps.nodeIndex === nodeIndex)
      const pk = await cs.hpke.importPublicKey(keyPackage.initKey)
      const egs = await encryptGroupSecrets(
        pk,
        encryptedGroupInfo,
        { joinerSecret: epochSecrets.joinerSecret, pathSecret: pathSecret?.secret, psks: res.pskIds },
        cs.hpke,
      )

      const ref = await makeKeyPackageRef(keyPackage, cs.hash)

      return { newMember: ref, encryptedGroupSecrets: { kemOutput: egs.enc, ciphertext: egs.ct } }
    }),
  )

  const welcome: Welcome = {
    cipherSuite: updatedGroupContext.cipherSuite,
    secrets: encryptedGroupSecrets,
    encryptedGroupInfo,
  }

  const authData: FramedContentAuthDataCommit = {
    contentType: tbs.content.contentType,
    signature,
    confirmationTag,
  }

  const [msg] = await protectCommit(publicMessage, state, wireformat, authenticatedData, tbs.content, authData, cs)

  const newState: ClientState = {
    groupContext: updatedGroupContext,
    ratchetTree: tree,
    secretTree: await createSecretTree(leafWidth(tree.length), epochSecrets.keySchedule.encryptionSecret, cs.kdf),
    keySchedule: epochSecrets.keySchedule,
    privatePath: privateKeys,
    unappliedProposals: {},
    historicalResumptionPsks: addToMap(
      state.historicalResumptionPsks,
      state.groupContext.epoch,
      state.keySchedule.resumptionPsk,
    ),
    confirmationTag,
    signaturePrivateKey: state.signaturePrivateKey,
  }

  return { newState, welcome, msg }
}

async function protectCommit(
  publicMessage: boolean,
  state: ClientState,
  wireformat: WireformatName,
  authenticatedData: Uint8Array,
  content: FramedContentCommit,
  authData: FramedContentAuthDataCommit,
  cs: CiphersuiteImpl,
): Promise<[MLSMessage, SecretTree]> {
  const authenticatedContent: AuthenticatedContentCommit = {
    wireformat,
    content,
    auth: authData,
  }

  if (publicMessage) {
    const msg = await protectPublicMessage(
      state.keySchedule.membershipKey,
      state.groupContext,
      authenticatedContent,
      cs,
    )

    return [{ version: "mls10", wireformat: "mls_public_message", publicMessage: msg }, state.secretTree]
  }
  const res = await protect(
    state.keySchedule.senderDataSecret,
    authenticatedData,
    state.groupContext,
    state.secretTree,
    { ...content, auth: authData },
    state.privatePath.leafIndex,
    cs,
  )

  return [
    { version: "mls10", wireformat: "mls_private_message", privateMessage: res.privateMessage },
    res.tree,
  ] as const
}

export async function applyUpdatePathSecret(
  tree: RatchetTree,
  privatePath: PrivateKeyPath,
  senderLeafIndex: number,
  gc: GroupContext,
  path: UpdatePath,
  excludeLeaves: number[],
  cs: CiphersuiteImpl,
): Promise<{ nodeIndex: number; pathSecret: Uint8Array }> {
  const {
    nodeIndex: ancestorNodeIndex,
    resolution,
    updateNode,
  } = firstMatchAncestor(tree, privatePath.leafIndex, senderLeafIndex, path)

  // console.log(resolution)
  // console.log(ancestorNodeIndex)
  // console.log(updateNode)
  // console.log(privatePath)

  for (const [i, nodeIndex] of filterNewLeaves(resolution, excludeLeaves).entries()) {
    if (privatePath.privateKeys[nodeIndex] !== undefined) {
      const key = await cs.hpke.importPrivateKey(privatePath.privateKeys[nodeIndex]!)
      const ct = updateNode?.encryptedPathSecret[i]!

      // console.log(privatePath.privateKeys[nodeIndex])
      // console.log(ct)

      const pathSecret = await decryptWithLabel(
        key,
        "UpdatePathNode",
        encodeGroupContext(gc),
        ct.kemOutput,
        ct.ciphertext,
        cs.hpke,
      )
      return { nodeIndex: ancestorNodeIndex, pathSecret }
    }
  }

  throw new Error("No overlap between provided private keys and update path")
}
function findPsk(
  state: ClientState,
  psks: Record<string, Uint8Array>,
  preSharedKeyId: PreSharedKeyID,
): Uint8Array | undefined {
  if (preSharedKeyId.psktype === "external") {
    return psks[bytesToBase64(preSharedKeyId.pskId)]
  }

  if (constantTimeEqual(preSharedKeyId.pskGroupId, state.groupContext.groupId)) {
    return state.historicalResumptionPsks.get(preSharedKeyId.pskEpoch)
  }
}

export async function nextEpochContext(
  groupContext: GroupContext,
  wireformat: WireformatName,
  content: FramedContentCommit,
  signature: Uint8Array,
  updatedTreeHash: Uint8Array,
  confirmationTag: Uint8Array,
  newExtensions: Extension[],
  h: Hash,
): Promise<GroupContext> {
  const interimTranscriptHash = await createInterimHash(groupContext.confirmedTranscriptHash, { confirmationTag }, h)
  const newConfirmedHash = await createConfirmedHash(interimTranscriptHash, { wireformat, content, signature }, h)

  return {
    ...groupContext,
    epoch: groupContext.epoch + 1n,
    treeHash: updatedTreeHash,
    extensions: newExtensions,
    confirmedTranscriptHash: newConfirmedHash,
  }
}

export async function joinGroup(
  welcome: Welcome,
  keyPackage: KeyPackage,
  privateKeys: PrivateKeyPackage,
  externalPsks: [Uint8Array, Uint8Array][],
  cs: CiphersuiteImpl,
  ratchetTree?: RatchetTree,
): Promise<ClientState> {
  const keyPackageRef = await makeKeyPackageRef(keyPackage, cs.hash)
  const privKey = await cs.hpke.importPrivateKey(privateKeys.initPrivateKey)
  const groupSecrets = await decryptGroupSecrets(privKey, keyPackageRef, welcome, cs.hpke)

  if (groupSecrets === undefined) throw new Error("Could not decrypt group secrets")

  const includesResumption = groupSecrets.psks.reduce((acc, cur) => {
    if (cur.psktype === "resumption" && (cur.usage === "branch" || cur.usage === "reinit")) {
      if (acc) throw new Error("Encountered multiple resumption PSKs")
      return true
    }
    return false
  }, false)

  const resolvedPsks = groupSecrets.psks.reduce(
    (acc, cur) => {
      if (cur.psktype === "external") {
        const psk = externalPsks.find(([id, _psk]) => constantTimeEqual(id, cur.pskId))
        return psk === undefined ? acc : [...acc, [cur, psk[1]] as [PreSharedKeyID, Uint8Array]]
      }
      return acc
    },
    [] as [PreSharedKeyID, Uint8Array][],
  )

  const pskSecret = await computePskSecret(resolvedPsks, cs)

  const gi = await decryptGroupInfo(welcome, groupSecrets.joinerSecret, pskSecret, cs)
  if (gi === undefined) throw new Error("Could not decrypt group info")

  const tree = ratchetTreeFromExtension(gi) ?? ratchetTree

  if (tree === undefined) throw new Error("No RatchetTree passed and no ratchet_tree extension")

  const signerNode = tree[gi.signer]

  if (signerNode === undefined || signerNode.nodeType === "parent") throw new Error("Expected non blank leaf node")

  const groupInfoSignatureVerified = verifyGroupInfoSignature(gi, signerNode.leaf.signaturePublicKey, cs.signature)

  if (!groupInfoSignatureVerified) throw new Error("Could not verify groupInfo signature")

  //todo more validation

  const newLeaf = findLeafIndex(tree, keyPackage.leafNode)

  if (newLeaf === undefined) throw new Error("Could not find own leaf when processing welcome")

  const privateKeyPath: PrivateKeyPath = {
    leafIndex: newLeaf,
    privateKeys: { [leafToNodeIndex(newLeaf)]: privateKeys.hpkePrivateKey },
  }

  const ancestorNodeIndex = firstCommonAncestor(tree, newLeaf, gi.signer)

  const updatedPkp =
    groupSecrets.pathSecret === undefined
      ? privateKeyPath //todo insert privateKeys.hpkePrivateKey
      : mergePrivateKeyPaths(
          await toPrivateKeyPath(
            await pathToRoot(tree, ancestorNodeIndex, groupSecrets.pathSecret, cs.kdf),
            newLeaf,
            cs,
          ),
          privateKeyPath,
        )

  const keySchedule = await deriveKeySchedule(groupSecrets.joinerSecret, pskSecret, gi.groupContext, cs.kdf)

  const confirmationTagVerified = await verifyGroupInfoConfirmationTag(gi, groupSecrets.joinerSecret, pskSecret, cs)

  if (!confirmationTagVerified) throw new Error("Could not verify confirmation tag")

  const secretTree = await createSecretTree(leafWidth(tree.length), keySchedule.encryptionSecret, cs.kdf)

  // const newInterimHash = await createInterimHash(
  //   gi.groupContext.confirmedTranscriptHash,
  //   { confirmationTag: gi.confirmationTag },
  //   cs.hash,
  // )

  const newGroupContext = { ...gi.groupContext }
  if (includesResumption) {
    //validate resumption
  }

  return {
    groupContext: newGroupContext,
    ratchetTree: tree,
    privatePath: updatedPkp,
    signaturePrivateKey: privateKeys.signaturePrivateKey,
    confirmationTag: gi.confirmationTag,
    unappliedProposals: {},
    keySchedule,
    secretTree,
    historicalResumptionPsks: new Map(),
  }
}

export async function createGroup(
  groupId: Uint8Array,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  extensions: Extension[],
  cs: CiphersuiteImpl,
): Promise<ClientState> {
  const ratchetTree: RatchetTree = [{ nodeType: "leaf", leaf: keyPackage.leafNode }]

  const privatePath: PrivateKeyPath = {
    leafIndex: 0,
    privateKeys: { [0]: privateKeyPackage.hpkePrivateKey },
  }

  const confirmedTranscriptHash = new Uint8Array()

  const groupContext: GroupContext = {
    version: "mls10",
    cipherSuite: cs.name,
    epoch: 0n,
    treeHash: await treeHashRoot(ratchetTree, cs.hash),
    groupId,
    extensions,
    confirmedTranscriptHash,
  }

  const epochSecret = cs.rng.randomBytes(cs.kdf.size)

  const keySchedule = await initializeKeySchedule(epochSecret, cs.kdf)

  const confirmationTag = await createConfirmationTag(keySchedule.confirmationKey, confirmedTranscriptHash, cs.hash)

  const secretTree = await createSecretTree(1, keySchedule.encryptionSecret, cs.kdf)

  return {
    ratchetTree,
    keySchedule,
    secretTree,
    privatePath,
    signaturePrivateKey: privateKeyPackage.signaturePrivateKey,
    unappliedProposals: {},
    historicalResumptionPsks: new Map(),
    groupContext,
    confirmationTag,
  }
}
