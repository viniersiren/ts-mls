import { Ciphersuite, CiphersuiteImpl } from "./ciphersuite"
import { CryptoProvider } from "./provider"
import { makeNobleHashImpl } from "./nobleHash"
import { makeNobleSignatureImpl } from "./implementation/default/makeNobleSignatureImpl"
import { makeNobleHpke } from "./implementation/default/makeNobleHpke"
import { makeKdfImpl, makeKdf } from "./implementation/default/makeKdfImpl"
import { nobleRng } from "./nobleRng"

export const nobleCryptoProvider: CryptoProvider = {
  async getCiphersuiteImpl(cs: Ciphersuite): Promise<CiphersuiteImpl> {
    return {
      kdf: makeKdfImpl(makeKdf(cs.hpke.kdf)),
      hash: makeNobleHashImpl(cs.hash),
      signature: await makeNobleSignatureImpl(cs.signature),
      hpke: await makeNobleHpke(cs.hpke),
      rng: nobleRng,
      name: cs.name,
    }
  },
}