export interface Rng {
  randomBytes(n: number): Uint8Array
}

export const webCryptoRng: Rng = {
  randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n))
  },
}
