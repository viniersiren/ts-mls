import { decodeUint16, decodeUint64, decodeUint8, encodeUint16, encodeUint64, encodeUint8 } from "./codec/number"
import { Decoder, mapDecoder, mapDecoderOption, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoder, contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeVarLenData, encodeVarLenData } from "./codec/variableLength"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { expandWithLabel } from "./crypto/kdf"
import { enumNumberToKey } from "./util/enumHelpers"

//8.4
export const pskTypes = {
  external: 1,
  resumption: 2,
} as const

export type PSKTypeName = keyof typeof pskTypes
export type PskTypeMapping<P extends PSKTypeName> = (typeof pskTypes)[P]
export type PSKType = PskTypeMapping<PSKTypeName>

export const encodePskType: Encoder<PSKTypeName> = contramapEncoder(encodeUint8, (t) => pskTypes[t])
export const decodePskType: Decoder<PSKTypeName> = mapDecoderOption(decodeUint8, enumNumberToKey(pskTypes))

const resumptionPSKUsages = {
  application: 1,
  reinit: 2,
  branch: 3,
} as const

export type ResumptionPSKUsageName = keyof typeof resumptionPSKUsages
export type ResumptionPSKUsageMapping<P extends ResumptionPSKUsageName> = (typeof resumptionPSKUsages)[P]
export type ResumptionPSKUsage = (typeof resumptionPSKUsages)[ResumptionPSKUsageName]

export const encodeResumptionPSKUsage: Encoder<ResumptionPSKUsageName> = contramapEncoder(
  encodeUint8,
  (u) => resumptionPSKUsages[u],
)

export const decodeResumptionPSKUsage: Decoder<ResumptionPSKUsageName> = mapDecoderOption(
  decodeUint8,
  enumNumberToKey(resumptionPSKUsages),
)

type PSKInfoExternal = { pskId: Uint8Array }
type PSKInfoResumption = { usage: ResumptionPSKUsageName; pskGroupId: Uint8Array; pskEpoch: bigint }
type PSKInfo = PSKInfoExternal | PSKInfoResumption

export const encodePskInfoExternal: Encoder<PSKInfoExternal> = contramapEncoder(encodeVarLenData, (i) => i.pskId)

export const decodePskInfoExternal: Decoder<PSKInfoExternal> = mapDecoder(decodeVarLenData, (data) => {
  return { pskId: data }
})

export const encodePskInfoResumption: Encoder<PSKInfoResumption> = contramapEncoders(
  [encodeResumptionPSKUsage, encodeVarLenData, encodeUint64],
  (info) => [info.usage, info.pskGroupId, info.pskEpoch] as const,
)

export const decodePskInfoResumption: Decoder<PSKInfoResumption> = mapDecoders(
  [decodeResumptionPSKUsage, decodeVarLenData, decodeUint64],
  (usage, pskGroupId, pskEpoch) => {
    return { usage, pskGroupId, pskEpoch }
  },
)

export function decodePskInfo(p: PSKTypeName): Decoder<PSKInfo> {
  if (p == "external") {
    return decodePskInfoExternal
  } else {
    return decodePskInfoResumption
  }
}

export type PreSharedKeyIdExternal = { psktype: "external"; pskinfo: PSKInfoExternal } & PSKNonce
export type PreSharedKeyIdResumption = { psktype: "resumption"; pskinfo: PSKInfoResumption } & PSKNonce
export type PreSharedKeyID = PreSharedKeyIdExternal | PreSharedKeyIdResumption

type PSKNonce = Readonly<{ pskNonce: Uint8Array }>

export const encodePskId: Encoder<PreSharedKeyID> = (id) => {
  const info = id.psktype == "external" ? encodePskInfoExternal(id.pskinfo) : encodePskInfoResumption(id.pskinfo)
  return new Uint8Array([...encodePskType(id.psktype), ...info, ...encodeVarLenData(id.pskNonce)])
}

export const decodePskId: Decoder<PreSharedKeyID> = (b, offset) => {
  const d = decodePskType(b, offset)

  if (d === undefined) return

  const [psktype, len] = d
  if (psktype === "external") {
    const dd = mapDecoders([decodePskInfoExternal, decodeVarLenData], (pskinfo, pskNonce) => ({
      psktype,
      pskinfo,
      pskNonce,
    }))(b, offset + len)
    if (dd == undefined) return
    else {
      const [id, len2] = dd
      return [id, len + len2]
    }
  } else {
    const dd = mapDecoders([decodePskInfoResumption, decodeVarLenData], (pskinfo, pskNonce) => ({
      psktype,
      pskinfo,
      pskNonce,
    }))(b, offset + len)
    if (dd == undefined) return
    else {
      const [id, len2] = dd
      return [id, len + len2]
    }
  }
}

export async function computePskSecret(psks: [PreSharedKeyIdExternal, Uint8Array][], impl: CiphersuiteImpl) {
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
