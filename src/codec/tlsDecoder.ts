export type Decoder<T> = (b: Uint8Array, offset: number) => [T, number] | undefined

export function composeDecoders<T, U>(dt: Decoder<T>, du: Decoder<U>): Decoder<[T, U]> {
  return mapDecoders([dt, du], (t, u) => [t, u])
}

export function mapDecoder<T, U>(dec: Decoder<T>, f: (t: T) => U): Decoder<U> {
  return (b, offset) => {
    const x = dec(b, offset)
    if (x !== undefined) {
      const [t, l] = x
      return [f(t), l]
    }
  }
}

export function mapDecoderOption<T, U>(dec: Decoder<T>, f: (t: T) => U | undefined): Decoder<U> {
  return (b, offset) => {
    const x = dec(b, offset)
    if (x !== undefined) {
      const [t, l] = x
      const u = f(t)
      return u !== undefined ? [u, l] : undefined
    }
  }
}

export function mapDecoders<T extends unknown[], R>(
  decoders: { [K in keyof T]: Decoder<T[K]> },
  f: (...args: T) => R,
): Decoder<R> {
  return (b, offset) => {
    const result = decoders.reduce<
      | {
          values: unknown[]
          offset: number
          totalLength: number
        }
      | undefined
    >(
      (acc, decoder) => {
        if (!acc) return undefined

        const decoded = decoder(b, acc.offset)
        if (!decoded) return undefined

        const [value, length] = decoded
        return {
          values: [...acc.values, value],
          offset: acc.offset + length,
          totalLength: acc.totalLength + length,
        }
      },
      { values: [], offset, totalLength: 0 },
    )

    if (!result) return
    return [f(...(result.values as T)), result.totalLength]
  }
}
