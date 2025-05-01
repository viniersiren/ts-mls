export function encodeUint16(n: number): Uint8Array {
  const buffer = new ArrayBuffer(2)
  const view = new DataView(buffer)
  view.setUint16(0, n)
  return new Uint8Array(buffer)
}

export function encodeUint8(n: number): Uint8Array {
  const buffer = new ArrayBuffer(1)
  const view = new DataView(buffer)
  view.setUint8(0, n)
  return new Uint8Array(buffer)
}

export function encodeUint32(n: number): Uint8Array {
  const buffer = new ArrayBuffer(4)
  const view = new DataView(buffer)
  view.setUint32(0, n)
  return new Uint8Array(buffer)
}

export function encodeUint64(n: bigint): Uint8Array {
  const buffer = new ArrayBuffer(8)
  const view = new DataView(buffer)
  view.setBigUint64(0, n)
  return new Uint8Array(buffer)
}
