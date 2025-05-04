import json from "../../test_vectors/messages.json"

import { hexToBytes } from "@noble/ciphers/utils"

test("messages test vectors", () => {
  for (const x of json) {
    codecRoundtrip(x)
  }
})

type Messages = {
  mls_welcome: string
  mls_group_info: string
  mls_key_package: string
  ratchet_tree: string
  group_secrets: string
  add_proposal: string
  update_proposal: string
  remove_proposal: string
  pre_shared_key_proposal: string
  re_init_proposal: string
  external_init_proposal: string
  group_context_extensions_proposal: string
  commit: string
  public_message_application: string
  public_message_proposal: string
  public_message_commit: string
  private_message: string
}

function codecRoundtrip(msgs: Messages) {
  // const mlsWelcome = decode(hexToBytes(msgs.mls_welcome))
  expect(msgs).toBe(msgs)
}
