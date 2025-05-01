import { encodeUint8 } from "./number"

export function encodeOptional<T>(value: T | undefined, encodeT: (t: T) => Uint8Array): Uint8Array {
  return value ? prependPresenceOctet(encodeT(value)) : new Uint8Array(0x0)
}

function prependPresenceOctet(v: Uint8Array): Uint8Array {
  return new Uint8Array([...encodeUint8(1), ...v])
}
