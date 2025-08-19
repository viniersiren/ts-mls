import { KemId, KemInterface, CipherSuite, KdfId, AeadId } from "hpke-js"
// import { XWing } from "@hpke/hybridkem-x-wing"
// import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem';


export type KemAlgorithm =
  | "DHKEM-P256-HKDF-SHA256"
  | "DHKEM-X25519-HKDF-SHA256"
  | "DHKEM-X448-HKDF-SHA512"
  | "DHKEM-P521-HKDF-SHA512"
  | "DHKEM-P384-HKDF-SHA384"
  // | "ML-KEM-512"
  // | "ML-KEM-768"
  // | "ML-KEM-1024"
  // | "X-Wing"

export async function makeDhKem(kemAlg: KemAlgorithm): Promise<KemInterface> {
  switch (kemAlg) {
    case "DHKEM-P256-HKDF-SHA256":
      return new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      }).kem
    case "DHKEM-X25519-HKDF-SHA256":
      return new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      }).kem
    case "DHKEM-X448-HKDF-SHA512":
      return new CipherSuite({
        kem: KemId.DhkemX448HkdfSha512,
        kdf: KdfId.HkdfSha512,
        aead: AeadId.Aes128Gcm,
      }).kem
    case "DHKEM-P521-HKDF-SHA512":
      return new CipherSuite({
        kem: KemId.DhkemP521HkdfSha512,
        kdf: KdfId.HkdfSha512,
        aead: AeadId.Aes128Gcm,
      }).kem
    case "DHKEM-P384-HKDF-SHA384":
      return new CipherSuite({
        kem: KemId.DhkemP384HkdfSha384,
        kdf: KdfId.HkdfSha384,
        aead: AeadId.Aes128Gcm,
      }).kem
    // case "ML-KEM-512":
    //   return new ml_kem512()

    // case "ML-KEM-768":
    //   return new ml_kem768()

    // case "ML-KEM-1024":
    //   return  ml_kem1024;

    // case "X-Wing":
    //   return new XWing()
  }
}
