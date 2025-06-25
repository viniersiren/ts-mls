import { encodeProposalType, decodeProposalType, ProposalTypeName } from "../../src/proposalType"
import { createRoundtripTest } from "./roundtrip"

describe("ProposalTypeName roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeProposalType, decodeProposalType)

  test("roundtrips add", () => {
    roundtrip("add" as ProposalTypeName)
  })

  test("roundtrips group_context_extensions", () => {
    roundtrip("group_context_extensions" as ProposalTypeName)
  })
})
