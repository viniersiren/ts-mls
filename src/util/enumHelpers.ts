export function enumNumberToKey<T extends Record<string, number>, S extends string>(
  t: T,
): (n: number) => S | undefined {
  return (n) => (Object.values(t).includes(n) ? (reverseMap(t)[n] as S) : undefined)
}

export function reverseMap<T extends Record<string, number>>(obj: T): Record<number, string> {
  return Object.entries(obj).reduce(
    (acc, [key, value]) => ({
      ...acc,
      [value]: key,
    }),
    {},
  )
}
