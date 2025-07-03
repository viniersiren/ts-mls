import { Capabilities } from "./capabilities"
import { ciphersuites, CiphersuiteName } from "./crypto/ciphersuite"
import { greaseCapabilities, defaultGreaseConfig } from "./grease"

export const defaultCapabilities: Capabilities = greaseCapabilities(defaultGreaseConfig, {
  versions: ["mls10"],
  ciphersuites: Object.keys(ciphersuites) as CiphersuiteName[],
  extensions: [],
  proposals: [],
  credentials: ["basic", "x509"],
})
