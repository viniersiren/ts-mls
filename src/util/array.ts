export function updateArray<T>(tree: T[], index: number, t: T): T[] {
  return [...tree.slice(0, index), t, ...tree.slice(index + 1)]
}
