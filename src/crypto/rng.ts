export interface Rng {
  randomBytes(n: number): Uint8Array
}

import { randomBytes } from "@noble/hashes/utils"

export const webCryptoRng: Rng = {
  randomBytes(n) {
    return randomBytes(n)
  },
}
