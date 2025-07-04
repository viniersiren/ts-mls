import { Credential, CredentialCustom } from "./credential"
import { CredentialTypeName } from "./credentialType"

function createCustomCredentialType(credentialId: number): CredentialTypeName {
  return credentialId.toString() as CredentialTypeName
}

export function createCustomCredential(credentialId: number, data: Uint8Array): Credential {
  const result: CredentialCustom = {
    credentialType: createCustomCredentialType(credentialId),
    data,
  }
  return result as unknown as Credential
}
