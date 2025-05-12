import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { deriveSecret, expandWithLabel } from "./crypto/kdf"
import { extractEpochSecret, extractJoinerSecret, GroupContext } from "./groupContext"
import { extractWelcomeSecret } from "./groupInfo"

type KeySchedule = {
  epochSecret: Uint8Array
  senderDataSecret: Uint8Array
  encryptionSecret: Uint8Array
  exporterSecret: Uint8Array
  externalSecret: Uint8Array
  confirmationKey: Uint8Array
  membershipKey: Uint8Array
  resumptionPsk: Uint8Array
  epochAuthenticator: Uint8Array
  initSecret: Uint8Array
}

type EpochSecrets = {
  keySchedule: KeySchedule
  joinerSecret: Uint8Array
  welcomeSecret: Uint8Array
}

export async function mlsExporter(
  exporterSecret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
  cs: CiphersuiteImpl,
) {
  const secret = await deriveSecret(exporterSecret, label, cs.kdf)

  const hash = await cs.hash.digest(context)
  return expandWithLabel(secret, "exported", hash, length, cs.kdf)
}

export async function initializeEpoch(
  initSecret: Uint8Array,
  commitSecret: Uint8Array,
  groupContext: GroupContext,
  pskSecret: Uint8Array,
  impl: CiphersuiteImpl,
): Promise<EpochSecrets> {
  const joinerSecret = await extractJoinerSecret(groupContext, initSecret, commitSecret, impl.kdf)

  const welcomeSecret = await extractWelcomeSecret(joinerSecret, pskSecret, impl.kdf)
  const epochSecret = await extractEpochSecret(groupContext, joinerSecret, impl.kdf, pskSecret)

  const newInitSecret = await deriveSecret(epochSecret, "init", impl.kdf)
  const senderDataSecret = await deriveSecret(epochSecret, "sender data", impl.kdf)
  const encryptionSecret = await deriveSecret(epochSecret, "encryption", impl.kdf)
  const exporterSecret = await deriveSecret(epochSecret, "exporter", impl.kdf)
  const externalSecret = await deriveSecret(epochSecret, "external", impl.kdf)
  const confirmationKey = await deriveSecret(epochSecret, "confirm", impl.kdf)
  const membershipKey = await deriveSecret(epochSecret, "membership", impl.kdf)
  const resumptionPsk = await deriveSecret(epochSecret, "resumption", impl.kdf)
  const epochAuthenticator = await deriveSecret(epochSecret, "authentication", impl.kdf)

  const newKeySchedule: KeySchedule = {
    epochSecret: epochSecret,
    initSecret: newInitSecret,
    senderDataSecret,
    encryptionSecret,
    exporterSecret,
    externalSecret,
    confirmationKey,
    membershipKey,
    resumptionPsk,
    epochAuthenticator,
  }

  return { welcomeSecret, joinerSecret, keySchedule: newKeySchedule }
}
