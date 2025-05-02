export type Encoder<T> = (t: T) => Uint8Array

export function contramapEncoders<T extends unknown[], R>(
  encoders: { [K in keyof T]: Encoder<T[K]> },
  toTuple: (input: R) => T,
): Encoder<R> {
  return (value: R) => {
    const values = toTuple(value)

    const encodedParts = encoders.map((encoder, i) => encoder(values[i]))
    const totalLength = encodedParts.reduce((sum, part) => sum + part.length, 0)

    const result = new Uint8Array(totalLength)
    encodedParts.reduce((offset, part) => {
      result.set(part, offset)
      return offset + part.length
    }, 0)

    return result
  }
}

export function composeEncoders<T extends unknown[]>(encoders: { [K in keyof T]: Encoder<T[K]> }): Encoder<T> {
  return (values: T) => contramapEncoders(encoders, (t) => t as T)(values)
}

export function contramapEncoder<T, U>(enc: Encoder<T>, f: (u: U) => Readonly<T>): Encoder<U> {
  return (u: U) => enc(f(u))
}
