import { createGroup, createCommit, joinGroup, processPrivateMessage } from "../../src/clientState"
import { Credential } from "../../src/credential"
import { CiphersuiteName, getCiphersuiteImpl, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { checkHpkeKeysMatch } from "../crypto/keyMatch"
import { defaultCapabilities, defaultLifetime, testEveryoneCanMessageEveryone } from "./common"

for (const cs of Object.keys(ciphersuites)) {
  test(`Update ${cs}`, async () => {
    await update(cs as CiphersuiteName)
  })
}

async function update(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

  const addBobProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: bob.publicPackage,
    },
  }

  const addBobCommitResult = await createCommit(aliceGroup, {}, false, [addBobProposal], impl)

  aliceGroup = addBobCommitResult.newState

  let bobGroup = await joinGroup(
    addBobCommitResult.welcome!,
    bob.publicPackage,
    bob.privatePackage,
    [],
    impl,
    aliceGroup.ratchetTree,
  )

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  const emptyCommitResult = await createCommit(aliceGroup, {}, false, [], impl)

  if (emptyCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  aliceGroup = emptyCommitResult.newState

  const bobProcessCommitResult = await processPrivateMessage(
    bobGroup,
    emptyCommitResult.commit.privateMessage,
    {},
    impl,
  )

  bobGroup = bobProcessCommitResult.newState

  const emptyCommitResult3 = await createCommit(bobGroup, {}, false, [], impl)

  if (emptyCommitResult3.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  bobGroup = emptyCommitResult3.newState

  const aliceProcessCommitResult3 = await processPrivateMessage(
    aliceGroup,
    emptyCommitResult3.commit.privateMessage,
    {},
    impl,
  )

  aliceGroup = aliceProcessCommitResult3.newState

  await checkHpkeKeysMatch(aliceGroup, impl)
  await checkHpkeKeysMatch(bobGroup, impl)
  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup], impl)
}
