import {
  createGroup,
  createCommit,
  joinGroup,
  joinGroupExternal,
  processPublicMessage,
  createGroupInfoWithExternalPub,
} from "../../src/clientState"
import { Credential } from "../../src/credential"
import { CiphersuiteName, getCiphersuiteImpl, getCiphersuiteFromName, ciphersuites } from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { ProposalAdd } from "../../src/proposal"
import { defaultCapabilities, defaultLifetime, testEveryoneCanMessageEveryone } from "./common"

for (const cs of Object.keys(ciphersuites).slice(0, 1)) {
  test(`External join ${cs}`, async () => {
    await externalJoin(cs as CiphersuiteName)
  })
}

async function externalJoin(cipherSuite: CiphersuiteName) {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

  const aliceCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("alice") }
  const alice = await generateKeyPackage(aliceCredential, defaultCapabilities, defaultLifetime, [], impl)

  const groupId = new TextEncoder().encode("group1")

  let aliceGroup = await createGroup(groupId, alice.publicPackage, alice.privatePackage, [], impl)

  const bobCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("bob") }
  const bob = await generateKeyPackage(bobCredential, defaultCapabilities, defaultLifetime, [], impl)

  const charlieCredential: Credential = { credentialType: "basic", identity: new TextEncoder().encode("charlie") }
  const charlie = await generateKeyPackage(charlieCredential, defaultCapabilities, defaultLifetime, [], impl)

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

  const groupInfo = await createGroupInfoWithExternalPub(aliceGroup, impl)

  const charlieJoinGroupCommitResult = await joinGroupExternal(
    groupInfo,
    charlie.publicPackage,
    charlie.privatePackage,
    aliceGroup.ratchetTree,
    false,
    impl,
  )

  let charlieGroup = charlieJoinGroupCommitResult.newState

  aliceGroup = await processPublicMessage(aliceGroup, charlieJoinGroupCommitResult.publicMessage, {}, impl)

  bobGroup = await processPublicMessage(bobGroup, charlieJoinGroupCommitResult.publicMessage, {}, impl)

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)
  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(bobGroup.keySchedule.epochAuthenticator)

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}
