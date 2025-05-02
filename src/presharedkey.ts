import { decodeUint8, encodeUint16, encodeUint64, encodeUint8 } from "./codec/number"
import { Decoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder"
import { composeEncoders, contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { expandWithLabel } from "./crypto/kdf"

//8.4
const pskTypes = {
  external: 1,
  resumption: 2,
} as const

export type PSKType = keyof typeof pskTypes
export type PSKTypeId = (typeof pskTypes)[PSKType]

const resumptionPSKUsages = {
  application: 1,
  reinit: 2,
  branch: 3,
} as const

type ResumptionPSKUsage = keyof typeof resumptionPSKUsages
export type ResumptionPSKUsageId = (typeof resumptionPSKUsages)[ResumptionPSKUsage]

export const encodeResumptionPSKUsage: Encoder<ResumptionPSKUsage> = contramapEncoder(
  encodeUint8,
  (u) => resumptionPSKUsages[u],
)


type PSKInfo<P extends PSKType> = P extends "external"
  ? { pskId: Uint8Array }
  : P extends "resumption"
    ? { usage: ResumptionPSKUsage; pskGroupId: Uint8Array; pskEpoch: bigint }
    : {}

export const encodePskInfoExternal: Encoder<PSKInfo<"external">> = contramapEncoder(encodeVarLenData, (i) => i.pskId)

export const decodePskInfoExternal: Decoder<PSKInfo<"external">> = mapDecoder(decodeVarLenData, (data) => {
  return { pskId: data }
})

export const encodePskInfoResumption: Encoder<PSKInfo<"resumption">> = contramapEncoders(
  [encodeResumptionPSKUsage, encodeVarLenData, encodeUint64],
  (info) => [info.usage, info.pskGroupId, info.pskEpoch] as const,
)

export const encodePskType: Encoder<PSKType> = contramapEncoder(encodeUint8, (t) => pskTypes[t])

export type PreSharedKeyID<P extends PSKType> = P extends P
  ? Readonly<{
      psktype: P
      pskinfo: PSKInfo<P>
      pskNonce: Uint8Array
    }>
  : never

export const encodePskId: Encoder<PreSharedKeyID<PSKType>> = (id) => {
  const info = id.psktype == "external" ? encodePskInfoExternal(id.pskinfo) : encodePskInfoResumption(id.pskinfo)
  return new Uint8Array([...encodePskType(id.psktype), ...info, ...encodeVarLenData(id.pskNonce)])
}

export async function computePskSecret(psks: [PreSharedKeyID<"external">, Uint8Array][], impl: CiphersuiteImpl) {
  const zeroes = new Uint8Array(impl.kdf.keysize)

  return psks.reduce(async (acc, [curId, curPsk], index) => {
    const secret = await impl.kdf.extract(
      await expandWithLabel(
        await impl.kdf.extract(zeroes.buffer, curPsk.buffer as ArrayBuffer),
        "derived psk",
        encodePskLabel({ id: curId, index, count: psks.length }),
        impl.kdf.keysize,
        impl.kdf,
      ),
      (await acc).buffer,
    )
    return new Uint8Array(secret)
  }, Promise.resolve(zeroes))
}

type PSKLabel<P extends PSKType> = Readonly<{
  id: PreSharedKeyID<P>
  index: number
  count: number
}>

export const encodePskLabel: Encoder<PSKLabel<PSKType>> = contramapEncoders(
  [encodePskId, encodeUint16, encodeUint16],
  (label) => [label.id, label.index, label.count] as const,
)
