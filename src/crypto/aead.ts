import { Aes128Gcm, Aes256Gcm } from "@hpke/core"
import { AeadInterface } from "hpke-js"
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305"

export type AeadAlgorithm = "AES128GCM" | "CHACHA20POLY1305" | "AES256GCM"

export function makeAead(aeadAlg: AeadAlgorithm): AeadInterface {
  switch (aeadAlg) {
    case "AES128GCM":
      return new Aes128Gcm()
    case "AES256GCM":
      return new Aes256Gcm()
    case "CHACHA20POLY1305":
      return new Chacha20Poly1305()
  }
}
