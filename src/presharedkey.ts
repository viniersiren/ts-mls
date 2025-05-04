import { decodeUint16, decodeUint64, decodeUint8, encodeUint16, encodeUint64, encodeUint8 } from "./codec/number"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { expandWithLabel } from "./crypto/kdf"
import { enumNumberToKey } from "./util/enumHelpers"

export const pskTypes = {
  external: 1,
  resumption: 2,
} as const

export type PSKTypeName = keyof typeof pskTypes
export type PSKType = (typeof pskTypes)[PSKTypeName]

export const encodePskType: Encoder<PSKTypeName> = contramapEncoder(encodeUint8, (t) => pskTypes[t])
export const decodePskType: Decoder<PSKTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(pskTypes))

const resumptionPSKUsages = {
  application: 1,
  reinit: 2,
  branch: 3,
} as const

export type ResumptionPSKUsageName = keyof typeof resumptionPSKUsages
export type ResumptionPSKUsage = (typeof resumptionPSKUsages)[ResumptionPSKUsageName]

export const encodeResumptionPSKUsage: Encoder<ResumptionPSKUsageName> = contramapEncoder(
  encodeUint8,
  (u) => resumptionPSKUsages[u],
)

export const decodeResumptionPSKUsage: Decoder<ResumptionPSKUsageName> = mapDecoderOption(
  decodeUint8,
  enumNumberToKey(resumptionPSKUsages),
)

type PSKInfoExternal = { psktype: "external"; pskId: Uint8Array }
type PSKInfoResumption = {
  psktype: "resumption"
  usage: ResumptionPSKUsageName
  pskGroupId: Uint8Array
  pskEpoch: bigint
}
type PSKInfo = PSKInfoExternal | PSKInfoResumption

const encodePskInfoExternal: Encoder<PSKInfoExternal> = contramapEncoders(
  [encodePskType, encodeVarLenData],
  (i) => [i.psktype, i.pskId] as const,
)

const encodePskInfoResumption: Encoder<PSKInfoResumption> = contramapEncoders(
  [encodePskType, encodeResumptionPSKUsage, encodeVarLenData, encodeUint64],
  (info) => [info.psktype, info.usage, info.pskGroupId, info.pskEpoch] as const,
)

const decodePskInfoResumption = mapDecoders(
  [decodeResumptionPSKUsage, decodeVarLenData, decodeUint64],
  (usage, pskGroupId, pskEpoch) => {
    return { usage, pskGroupId, pskEpoch }
  },
)

export const encodePskInfo: Encoder<PSKInfo> = (info) => {
  switch (info.psktype) {
    case "external":
      return encodePskInfoExternal(info)
    case "resumption":
      return encodePskInfoResumption(info)
  }
}

export const decodePskInfo: Decoder<PSKInfo> = flatMapDecoder(decodePskType, (psktype): Decoder<PSKInfo> => {
  switch (psktype) {
    case "external":
      return mapDecoder(decodeVarLenData, (pskId) => ({
        psktype,
        pskId,
      }))
    case "resumption":
      return mapDecoder(decodePskInfoResumption, (resumption) => ({
        psktype,
        ...resumption,
      }))
  }
})

type PSKNonce = Readonly<{ pskNonce: Uint8Array }>

export type PreSharedKeyID = PSKInfo & PSKNonce

export const encodePskId: Encoder<PreSharedKeyID> = contramapEncoders(
  [encodePskInfo, encodeVarLenData],
  (pskid) => [pskid, pskid.pskNonce] as const,
)

export const decodePskId: Decoder<PreSharedKeyID> = mapDecoders(
  [decodePskInfo, decodeVarLenData],
  (info, pskNonce) => ({ ...info, pskNonce }),
)

type PSKLabel = Readonly<{
  id: PreSharedKeyID
  index: number
  count: number
}>

export const encodePskLabel: Encoder<PSKLabel> = contramapEncoders(
  [encodePskId, encodeUint16, encodeUint16],
  (label) => [label.id, label.index, label.count] as const,
)

export const decodePskLabel: Decoder<PSKLabel> = mapDecoders(
  [decodePskId, decodeUint16, decodeUint16],
  (id, index, count) => ({ id, index, count }),
)

export type PreSharedKeyIdExternal = PSKInfoExternal & PSKNonce
export type PreSharedKeyIdResumption = PSKInfoResumption & PSKNonce

export async function computePskSecret(psks: [PreSharedKeyIdExternal, Uint8Array][], impl: CiphersuiteImpl) {
  const zeroes = new Uint8Array(impl.kdf.size)

  return psks.reduce(async (acc, [curId, curPsk], index) => {
    const secret = await impl.kdf.extract(
      await expandWithLabel(
        await impl.kdf.extract(zeroes.buffer, curPsk.buffer as ArrayBuffer),
        "derived psk",
        encodePskLabel({ id: curId, index, count: psks.length }),
        impl.kdf.size,
        impl.kdf,
      ),
      (await acc).buffer,
    )
    return new Uint8Array(secret)
  }, Promise.resolve(zeroes))
}
