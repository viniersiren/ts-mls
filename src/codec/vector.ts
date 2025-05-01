export function encodeVarLenData(data: Uint8Array): Uint8Array {
  const len = data.length
  let lenBytes: Uint8Array

  if (len < 64) {
    // 1-byte length: 00xxxxxx
    lenBytes = new Uint8Array([len & 0b00111111])
  } else if (len < 16384) {
    // 2-byte length: 01xxxxxx xxxxxxxx
    lenBytes = new Uint8Array(2)
    lenBytes[0] = ((len >> 8) & 0b00111111) | 0b01000000
    lenBytes[1] = len & 0xff
  } else if (len < 0x40000000) {
    // 4-byte length: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    lenBytes = new Uint8Array(4)
    lenBytes[0] = ((len >> 24) & 0b00111111) | 0b10000000
    lenBytes[1] = (len >> 16) & 0xff
    lenBytes[2] = (len >> 8) & 0xff
    lenBytes[3] = len & 0xff
  } else {
    throw new Error("Length too large to encode (max is 2^30 - 1)")
  }

  const result = new Uint8Array(lenBytes.length + data.length)
  result.set(lenBytes, 0)
  result.set(data, lenBytes.length)
  return result
}

export function decodeVarLenData(
  buf: Uint8Array,
  offset = 0,
): {
  data: Uint8Array
  length: number
  totalBytesRead: number
} {
  if (offset >= buf.length) {
    throw new Error("Offset beyond buffer")
  }

  const firstByte = buf[offset] as number
  const prefix = firstByte >> 6
  let length = 0
  let lengthFieldSize = 0

  if (prefix === 0) {
    length = firstByte & 0b00111111
    lengthFieldSize = 1
  } else if (prefix === 1) {
    if (offset + 2 > buf.length) throw new Error("Incomplete 2-byte length")
    length = ((firstByte & 0b00111111) << 8) | (buf[offset + 1] as number)
    lengthFieldSize = 2
  } else if (prefix === 2) {
    if (offset + 4 > buf.length) throw new Error("Incomplete 4-byte length")
    length =
      ((firstByte & 0b00111111) << 24) |
      ((buf[offset + 1] as number) << 16) |
      ((buf[offset + 2] as number) << 8) |
      (buf[offset + 3] as number)
    lengthFieldSize = 4
  } else {
    throw new Error("8-byte length not supported in this implementation")
  }

  const totalBytes = lengthFieldSize + length
  if (offset + totalBytes > buf.length) {
    throw new Error("Data length exceeds buffer")
  }

  const data = buf.subarray(offset + lengthFieldSize, offset + totalBytes)
  return { data, length, totalBytesRead: totalBytes }
}
