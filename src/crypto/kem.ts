import {
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  DhkemX25519HkdfSha256,
  DhkemX448HkdfSha512,
  KemInterface,
} from "@hpke/core"
import { XWing } from "@hpke/hybridkem-x-wing"
import { MlKem1024, MlKem512, MlKem768 } from "@hpke/ml-kem"

export type KemAlgorithm =
  | "DHKEM-P256-HKDF-SHA256"
  | "DHKEM-X25519-HKDF-SHA256"
  | "DHKEM-X448-HKDF-SHA512"
  | "DHKEM-P521-HKDF-SHA512"
  | "DHKEM-P384-HKDF-SHA384"
  | "ML-KEM-512"
  | "ML-KEM-768"
  | "ML-KEM-1024"
  | "X-Wing"

export async function makeDhKem(kemAlg: KemAlgorithm): Promise<KemInterface> {
  switch (kemAlg) {
    case "DHKEM-P256-HKDF-SHA256":
      return new DhkemP256HkdfSha256()
    case "DHKEM-X25519-HKDF-SHA256":
      return new DhkemX25519HkdfSha256()
    case "DHKEM-X448-HKDF-SHA512":
      return new DhkemX448HkdfSha512()
    case "DHKEM-P521-HKDF-SHA512":
      return new DhkemP521HkdfSha512()
    case "DHKEM-P384-HKDF-SHA384":
      return new DhkemP384HkdfSha384()
    case "ML-KEM-512":
      return new MlKem512()

    case "ML-KEM-768":
      return new MlKem768()

    case "ML-KEM-1024":
      return new MlKem1024()

    case "X-Wing":
      return new XWing()
  }
}
