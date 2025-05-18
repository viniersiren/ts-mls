# ts-mls

[![CI](https://github.com/LukaJCB/ts-mls/actions/workflows/ci.yml/badge.svg)](https://github.com/LukaJCB/ts-mls/actions/workflows/ci.yml)

Typescript implementation of Messaging Layer Security (RFC 9420, MLS).

This project is work in progress, but it will focus on immutability, type safety, minimal dependencies and extensibility.

## Current Status

The following test vectors are fully passing:

- [x] crypto-basics
- [x] deserialization
- [x] key-schedule
- [x] message-protection
- [x] messages
- [ ] passive-client-handling-commit
- [ ] passive-client-random
- [ ] passive-client-welcome
- [x] psk_secret
- [x] secret-tree
- [x] transcript-hashes
- [x] tree-math
- [x] tree-operations
- [x] tree-validation
- [x] treekem
- [x] welcome
