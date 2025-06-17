import { Capabilities } from "../../src/capabilities"
import {
  ClientState,
  createApplicationMessage,
  createCommit,
  createGroup,
  joinGroup,
  processPrivateMessage,
} from "../../src/clientState"
import { Credential } from "../../src/credential"
import {
  CiphersuiteImpl,
  CiphersuiteName,
  ciphersuites,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
} from "../../src/crypto/ciphersuite"
import { generateKeyPackage } from "../../src/keyPackage"
import { Lifetime } from "../../src/lifetime"
import { ProposalAdd } from "../../src/proposal"

const defaultCapabilities: Capabilities = {
  versions: ["mls10"],
  ciphersuites: Object.keys(ciphersuites) as CiphersuiteName[],
  extensions: ["ratchet_tree"],
  proposals: [],
  credentials: ["basic", "x509"],
}

const defaultLifetime: Lifetime = {
  notBefore: 0n,
  notAfter: 9223372036854775807n,
}

test("3-party join MLS_128_DHKEMP256_AES128GCM_SHA256_P256", async () => {
  await threePartyJoin("MLS_128_DHKEMP256_AES128GCM_SHA256_P256")
})

test("3-party join MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", async () => {
  await threePartyJoin("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
})

test("3-party join MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519", async () => {
  await threePartyJoin("MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519")
})

test("3-party join MLS_256_XWING_AES256GCM_SHA512_Ed25519", async () => {
  await threePartyJoin("MLS_256_XWING_AES256GCM_SHA512_Ed25519")
})

test("3-party join MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519", async () => {
  await threePartyJoin("MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519")
})

test("3-party join MLS_256_XWING_CHACHA20POLY1305_SHA512_MLDSA87", async () => {
  await threePartyJoin("MLS_256_XWING_CHACHA20POLY1305_SHA512_MLDSA87")
})

async function threePartyJoin(cipherSuite: CiphersuiteName) {
  const impl = getCiphersuiteImpl(getCiphersuiteFromName(cipherSuite))

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

  const addCharlieProposal: ProposalAdd = {
    proposalType: "add",
    add: {
      keyPackage: charlie.publicPackage,
    },
  }

  const addCharlieCommitResult = await createCommit(aliceGroup, {}, false, [addCharlieProposal], impl)

  aliceGroup = addCharlieCommitResult.newState

  if (addCharlieCommitResult.commit.wireformat !== "mls_private_message") throw new Error("Expected private message")

  const res = await processPrivateMessage(bobGroup, addCharlieCommitResult.commit.privateMessage, {}, impl)

  bobGroup = res.newState

  expect(bobGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  let charlieGroup = await joinGroup(
    addCharlieCommitResult.welcome!,
    charlie.publicPackage,
    charlie.privatePackage,
    [],
    impl,
    aliceGroup.ratchetTree,
  )

  expect(charlieGroup.keySchedule.epochAuthenticator).toStrictEqual(aliceGroup.keySchedule.epochAuthenticator)

  await testEveryoneCanMessageEveryone([aliceGroup, bobGroup, charlieGroup], impl)
}

async function testEveryoneCanMessageEveryone(clients: ClientState[], impl: CiphersuiteImpl) {
  const encoder = new TextEncoder()
  const updatedGroups = [...clients]

  for (const [senderIndex, senderGroup] of updatedGroups.entries()) {
    const messageText = `Hello from member ${senderIndex}`
    const encodedMessage = encoder.encode(messageText)

    const { privateMessage, newState: newSenderState } = await createApplicationMessage(
      senderGroup,
      encodedMessage,
      impl,
    )
    updatedGroups[senderIndex] = newSenderState

    for (const [receiverIndex, receiverGroup] of updatedGroups.entries()) {
      if (receiverIndex === senderIndex) continue

      const result = await processPrivateMessage(receiverGroup, privateMessage, {}, impl)

      if (result.kind === "newState") {
        throw new Error(`Expected application message for member ${receiverIndex} from ${senderIndex}`)
      }

      expect(result.message).toStrictEqual(encodedMessage)

      updatedGroups[receiverIndex] = result.newState
    }
  }

  return { updatedGroups }
}
