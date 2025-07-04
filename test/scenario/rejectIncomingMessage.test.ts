import { createGroup, joinGroup } from "../../src/clientState"
import { createCommit } from "../../src/createCommit"
import { emptyPskIndex } from "../../src/pskIndex"
import { Credential } from "../../src/credential"
import { CiphersuiteName, ciphersuites, getCiphersuiteFromName, getCiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { Proposal, ProposalAdd } from "../../src/proposal"
import { defaultLifetime } from "../../src/lifetime"
import { defaultCapabilities } from "../../src/defaultCapabilities"
import { createProposal } from "../../src"
import { processMessage } from "../../src/processMessages"
import { encodeExternalSender } from "../../src/externalSender"

for (const cs of Object.keys(ciphersuites)) {
  test(`Reject incoming message ${cs}`, async () => {
    await rejectIncomingMessagesTest(cs as CiphersuiteName)
  })
}

async function rejectIncomingMessagesTest(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities(), defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [addBobProposal], impl)

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    emptyPskIndex,
    impl,
    aliceGroup.ratchetTree,
  )

  const bobProposeExtensions: Proposal = {
    proposalType: "group_context_extensions",
    groupContextExtensions: {
      extensions: [
        {
          extensionType: "external_senders",
          extensionData: encodeExternalSender({
            credential: { credentialType: "basic", identity: new Uint8Array() },
            signaturePublicKey: new Uint8Array(),
          }),
        },
      ],
    },
  }

  const createExtensionsProposalResults = await createProposal(bobGroup, false, bobProposeExtensions, impl)

  bobGroup = createExtensionsProposalResults.newState

  if (createExtensionsProposalResults.message.wireformat !== "mls_private_message")
    throw new Error("Expected private message")

  //alice rejects the proposal
  const aliceRejectsProposalResult = await processMessage(
    createExtensionsProposalResults.message,
    aliceGroup,
    emptyPskIndex,
    () => "reject",
    impl,
  )

  aliceGroup = aliceRejectsProposalResult.newState

  expect(aliceGroup.unappliedProposals).toStrictEqual({})

  // alice commits without the proposal
  const aliceCommitResult = await createCommit(aliceGroup, emptyPskIndex, false, [], impl)

  aliceGroup = aliceCommitResult.newState

  if (aliceCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const bobRejectsAliceCommitResult = await processMessage(
    aliceCommitResult.commit,
    bobGroup,
    emptyPskIndex,
    () => "reject",
    impl,
  )

  // group context and keySchedule haven't changed since bob rejected the commit
  expect(bobRejectsAliceCommitResult.newState.groupContext).toStrictEqual(bobGroup.groupContext)
  expect(bobRejectsAliceCommitResult.newState.keySchedule).toStrictEqual(bobGroup.keySchedule)
}
