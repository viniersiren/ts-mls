import { encodeUint16, encodeUint64, encodeUint8 } from "./codec/number"
import { encodeVarLenData } from "./codec/vector"
import { CiphersuiteImpl } from "./crypto/ciphersuite"
import { expandWithLabel } from "./crypto/kdf"

//8.4
const pskTypes = {
  external: 1,
  resumption: 2,
} as const

type PSKType = keyof typeof pskTypes
export type PSKTypeId = (typeof pskTypes)[PSKType]

const resumptionPSKUsages = {
  application: 1,
  reinit: 2,
  branch: 3,
} as const

type ResumptionPSKUsage = keyof typeof resumptionPSKUsages
export type ResumptionPSKUsageId = (typeof resumptionPSKUsages)[ResumptionPSKUsage]

export function encodeResumptionPSKUsage(u: ResumptionPSKUsage): Uint8Array {
  return encodeUint8(resumptionPSKUsages[u])
}

type PSKInfo<P extends PSKType> = P extends "external"
  ? { pskId: Uint8Array }
  : P extends "resumption"
    ? { usage: ResumptionPSKUsage; pskGroupId: Uint8Array; pskEpoch: bigint }
    : {}

export function encodePskInfoExternal(info: PSKInfo<"external">): Uint8Array {
  return encodeVarLenData(info.pskId)
}

export function encodePskInfoResumption(info: PSKInfo<"resumption">): Uint8Array {
  return new Uint8Array([
    ...encodeResumptionPSKUsage(info.usage),
    ...encodeVarLenData(info.pskGroupId),
    ...encodeUint64(info.pskEpoch),
  ])
}

export function encodePskType(t: PSKType): Uint8Array {
  return encodeUint8(pskTypes[t])
}

export type PreSharedKeyID<P extends PSKType> = P extends P
  ? Readonly<{
      psktype: P
      pskinfo: PSKInfo<P>
      pskNonce: Uint8Array
    }>
  : never

export function encodePskId<P extends PSKType>(id: PreSharedKeyID<P>): Uint8Array {
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

export function encodePskLabel<P extends PSKType>(label: PSKLabel<P>): Uint8Array {
  return new Uint8Array([...encodePskId(label.id), ...encodeUint16(label.index), ...encodeUint16(label.count)])
}
