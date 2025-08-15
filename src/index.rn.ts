// React Native compatible version of ts-mls
// This version only exports types and avoids importing problematic crypto modules

// Export only types and interfaces - no actual implementations
export type { Extension, ExtensionType } from "./extension"
export type { DefaultProposalTypeName } from "./defaultProposalType"
export type { DefaultExtensionTypeName } from "./defaultExtensionType"
export type { PrivateKeyPath } from "./privateKeyPath"
export type { RatchetTree } from "./ratchetTree"
export type { IncomingMessageCallback, IncomingMessageAction } from "./IncomingMessageAction"
export type { ExternalSender } from "./externalSender"
export type { RequiredCapabilities } from "./requiredCapabilities"
export type { AuthenticationService } from "./authenticationService"
export type { PaddingConfig } from "./paddingConfig"
export type { KeyPackageEqualityConfig } from "./keyPackageEqualityConfig"
export type { LifetimeConfig } from "./lifetimeConfig"
export type { PrivateKeyPackage, KeyPackage } from "./keyPackage"
export type { KeyRetentionConfig } from "./keyRetentionConfig"
export type { ClientState, GroupActiveState, EpochReceiverData } from "./clientState"
export type { CreateCommitResult } from "./createCommit"
export type { ProcessMessageResult } from "./processMessages"
export type { PskIndex } from "./pskIndex"
export type { Credential } from "./credential"
export type { Proposal } from "./proposal"
export type { ClientConfig } from "./clientConfig"
export type { Welcome } from "./welcome"
export type { Lifetime } from "./lifetime"
export type { Capabilities } from "./capabilities"
export type { CiphersuiteName, CiphersuiteImpl } from './crypto/ciphersuite'

// Export constants that don't require crypto imports
export { defaultProposalTypes } from "./defaultProposalType"
export { defaultExtensionTypes } from "./defaultExtensionType"
export { acceptAll } from "./IncomingMessageAction"
export { proposeAddExternal, proposeExternal } from "./externalProposal"
export { decodeExternalSender, encodeExternalSender } from "./externalSender"
export { decodeRequiredCapabilities, encodeRequiredCapabilities } from "./requiredCapabilities"
export { defaultAuthenticationService } from "./authenticationService"
export { defaultPaddingConfig } from "./paddingConfig"
export { defaultKeyPackageEqualityConfig } from "./keyPackageEqualityConfig"
export { defaultLifetimeConfig } from "./lifetimeConfig"
export { defaultKeyRetentionConfig } from "./keyRetentionConfig"
export { emptyPskIndex } from "./pskIndex"
export { defaultLifetime } from "./lifetime"
export { defaultCapabilities } from "./defaultCapabilities"

// Stub implementations for React Native
export const ciphersuites = {};
export const getCiphersuiteFromName = () => { throw new Error('Crypto not available in React Native') };
export const getCiphersuiteImpl = () => { throw new Error('Crypto not available in React Native') };

// Stub other functions that might be needed
export const createGroup = () => { throw new Error('Crypto not available in React Native') };
export const makePskIndex = () => { throw new Error('Crypto not available in React Native') };
export const joinGroup = () => { throw new Error('Crypto not available in React Native') };
export const createApplicationMessage = () => { throw new Error('Crypto not available in React Native') };
export const createProposal = () => { throw new Error('Crypto not available in React Native') };
export const joinGroupExternal = () => { throw new Error('Crypto not available in React Native') };
export const createCommit = () => { throw new Error('Crypto not available in React Native') };
export const createGroupInfoWithExternalPub = () => { throw new Error('Crypto not available in React Native') };
export const createGroupInfoWithExternalPubAndRatchetTree = () => { throw new Error('Crypto not available in React Native') };
export const processPrivateMessage = () => { throw new Error('Crypto not available in React Native') };
export const processMessage = () => { throw new Error('Crypto not available in React Native') };
export const processPublicMessage = () => { throw new Error('Crypto not available in React Native') };
export const joinGroupFromReinit = () => { throw new Error('Crypto not available in React Native') };
export const reinitCreateNewGroup = () => { throw new Error('Crypto not available in React Native') };
export const reinitGroup = () => { throw new Error('Crypto not available in React Native') };
export const joinGroupFromBranch = () => { throw new Error('Crypto not available in React Native') };
export const branchGroup = () => { throw new Error('Crypto not available in React Native') };
export const generateKeyPackage = () => { throw new Error('Crypto not available in React Native') };
export const decodeMlsMessage = () => { throw new Error('Crypto not available in React Native') };
export const encodeMlsMessage = () => { throw new Error('Crypto not available in React Native') };
export const bytesToBase64 = () => { throw new Error('Crypto not available in React Native') };