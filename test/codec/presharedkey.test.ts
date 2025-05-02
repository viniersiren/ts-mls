import {
  decodePskId,
  decodePskInfoExternal,
  decodePskInfoResumption,
  decodePskLabel,
  decodePskType,
  decodeResumptionPSKUsage,
  encodePskId,
  encodePskInfoExternal,
  encodePskInfoResumption,
  encodePskLabel,
  encodePskType,
  encodeResumptionPSKUsage,
  PSKType,
  PSKTypeName,
  ResumptionPSKUsageName,
} from "../../src/presharedkey"
import { createRoundtripTest } from "./roundtrip"

test("PSKType roundtrip", () => {
  const roundtrip = createRoundtripTest(encodePskType, decodePskType)
  roundtrip("external")
  roundtrip("resumption")
})

test("ResumptionPSKUsageName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeResumptionPSKUsage, decodeResumptionPSKUsage)
  roundtrip("application")
  roundtrip("branch")
  roundtrip("reinit")
})

test("PSKInfoExternal roundtrip", () => {
  dummyPskInfoExternal.forEach(createRoundtripTest(encodePskInfoExternal, decodePskInfoExternal))
})

test("PSKInfoResumption roundtrip", () => {
  dummyPskInfoResumption.forEach(createRoundtripTest(encodePskInfoResumption, decodePskInfoResumption))
})

test("PreSharedKeyID roundtrip", () => {
  dummyPskId.forEach(createRoundtripTest(encodePskId, decodePskId))
})

test("PSKLabel roundtrip", () => {
  dummyPskLabel.forEach(createRoundtripTest(encodePskLabel, decodePskLabel))
})

const dummyByteArray = [new Uint8Array([0, 1, 2]), new Uint8Array()] as const
const dummyPskInfoResumption = [
  { usage: "application", pskGroupId: dummyByteArray[0], pskEpoch: 1000n },
  { usage: "branch", pskGroupId: dummyByteArray[1], pskEpoch: 0n },
] as const
const dummyPskInfoExternal = [{ pskId: dummyByteArray[0] }, { pskId: dummyByteArray[1] }] as const
const dummyPskId = [
  { psktype: "external", pskinfo: dummyPskInfoExternal[0], pskNonce: dummyByteArray[0] },
  { psktype: "resumption", pskinfo: dummyPskInfoResumption[0], pskNonce: dummyByteArray[1] },
] as const
const dummyPskLabel = [
  { id: dummyPskId[0], index: 99, count: 200 },
  { id: dummyPskId[1], index: 1, count: 65535 },
]
