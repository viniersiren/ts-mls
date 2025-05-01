import {
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  DhkemX25519HkdfSha256,
  DhkemX448HkdfSha512,
  KemInterface,
} from "@hpke/core"

export type KemAlgorithm =
  | "DHKEM-P256-HKDF-SHA256"
  | "DHKEM-X25519-HKDF-SHA256"
  | "DHKEM-X448-HKDF-SHA512"
  | "DHKEM-P521-HKDF-SHA512"
  | "DHKEM-P384-HKDF-SHA384"

export function makeDhKem(kemAlg: KemAlgorithm): KemInterface {
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
  }
}
