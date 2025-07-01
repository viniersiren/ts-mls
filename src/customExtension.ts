import { ExtensionTypeName, extensionTypes, ExtensionTypeValue } from "./extensionType"
import { UsageError } from "./mlsError"

export function createCustomExtension(extensionId: number): ExtensionTypeName {
  if (Object.values(extensionTypes).includes(extensionId as ExtensionTypeValue))
    throw new UsageError("Cannot create custom extension with default extension type")
  return extensionId.toString() as ExtensionTypeName
}
