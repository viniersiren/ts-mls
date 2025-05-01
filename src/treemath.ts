function log2(x: number): number {
  if (x === 0) return 0
  let k = 0
  while (x >> k > 0) {
    k++
  }
  return k - 1
}

function level(x: number): number {
  if ((x & 0x01) === 0) return 0

  let k = 0
  while (((x >> k) & 0x01) === 1) {
    k++
  }
  return k
}

export function nodeWidth(n: number): number {
  return n === 0 ? 0 : 2 * (n - 1) + 1
}

export function root(n: number): number {
  const w = nodeWidth(n)
  return (1 << log2(w)) - 1
}

export function left(x: number): number {
  const k = level(x)
  if (k === 0) throw new Error("leaf node has no children")
  return x ^ (0x01 << (k - 1))
}

export function right(x: number): number {
  const k = level(x)
  if (k === 0) throw new Error("leaf node has no children")
  return x ^ (0x03 << (k - 1))
}

export function parent(x: number, n: number): number {
  if (x === root(n)) throw new Error("root node has no parent")
  const k = level(x)
  const b = (x >> (k + 1)) & 0x01
  return (x | (1 << k)) ^ (b << (k + 1))
}

export function sibling(x: number, n: number): number {
  const p = parent(x, n)
  return x < p ? right(p) : left(p)
}

function directPath(x: number, n: number): number[] {
  const r = root(n)
  if (x === r) return []

  const d: number[] = []
  while (x !== r) {
    x = parent(x, n)
    d.push(x)
  }
  return d
}

export function copath(x: number, n: number): number[] {
  if (x === root(n)) return []

  const d = directPath(x, n)
  d.unshift(x)
  d.pop()

  return d.map((y) => sibling(y, n))
}

export function commonAncestorSemantic(x: number, y: number, n: number): number {
  const dx = new Set<number>([x, ...directPath(x, n)])
  const dy = new Set<number>([y, ...directPath(y, n)])

  const intersection = Array.from(dx).filter((z) => dy.has(z))
  if (intersection.length === 0) {
    throw new Error("failed to find common ancestor")
  }

  return intersection.reduce((min, current) => {
    return level(current) < level(min) ? current : min
  })
}

export function commonAncestorDirect(x: number, y: number, _n: number): number {
  const lx = level(x) + 1
  const ly = level(y) + 1

  if (lx <= ly && x >> ly === y >> ly) return y
  if (ly <= lx && x >> lx === y >> lx) return x

  let xn = x
  let yn = y
  let k = 0
  while (xn !== yn) {
    xn >>= 1
    yn >>= 1
    k++
  }

  return (xn << k) + (1 << (k - 1)) - 1
}
