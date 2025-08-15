# WebCrypto to Pure JavaScript Migration Plan

## Overview

This document outlines the plan to migrate the `ts-mls` repository from WebCrypto dependencies to pure JavaScript implementations. The goal is to achieve universal compatibility across all JavaScript runtimes, including React Native, while maintaining security and performance.

## Migration Strategy: Gradual Replacement

We will replace WebCrypto components one at a time, maintaining compatibility during the transition and testing each component individually. This approach minimizes risk and allows for incremental validation.

## Current WebCrypto Dependencies to Replace

1. **Random Number Generation**: `crypto.getRandomValues()`
2. **AES-GCM**: `crypto.subtle.importKey()`, `crypto.subtle.encrypt()`, `crypto.subtle.decrypt()`
3. **Hash Functions**: `crypto.subtle.digest()`, `crypto.subtle.importKey()` for HMAC
4. **HPKE Core**: `@hpke/core` (likely uses WebCrypto internally)

## Pure JavaScript Libraries to Integrate

- `@noble/hashes` - For SHA-256/384/512 and HMAC
- `@noble/ciphers` - For AES-GCM (already partially used)
- `hpke-js` - Pure JavaScript HPKE implementation
- `asn1js` - For ASN.1 parsing (if needed for key formats)

## Phase 1: Dependency Analysis & Planning

### Tasks
- Audit all WebCrypto usage across the codebase
- Identify pure JavaScript alternatives for each component
- Plan the order of replacement based on dependency chains
- Set up testing infrastructure for validation

### Deliverables
- Complete inventory of WebCrypto dependencies
- Mapping of WebCrypto functions to pure JS alternatives
- Replacement order plan

## Phase 2: Core Infrastructure Replacement

### 2.1 Random Number Generation (`src/crypto/rng.ts`)
```typescript
// Replace webCryptoRng with pure JS implementation
import { randomBytes } from '@noble/hashes/utils'

export const pureJsRng: Rng = {
  randomBytes(n: number): Uint8Array {
    return randomBytes(n)
  }
}
```

### 2.2 Hash Functions (`src/crypto/hash.ts`)
```typescript
// Replace crypto.subtle.digest with @noble/hashes
import { sha256, sha384, sha512, hmac } from '@noble/hashes'

// Replace crypto.subtle.importKey + HMAC with direct hmac function
```

### 2.3 AES-GCM (`src/crypto/aead.ts`)
```typescript
// Replace crypto.subtle with @noble/ciphers/aes
import { aes } from '@noble/ciphers/aes'
```

## Phase 3: HPKE Implementation Replacement

### 3.1 Replace @hpke/core with hpke-js
- **Challenge**: `hpke-js` might have different API than `@hpke/core`
- **Solution**: Create adapter layer or modify existing HPKE wrapper
- **Files affected**: `src/crypto/hpke.ts`, `src/crypto/kem.ts`, `src/crypto/kdf.ts`

### 3.2 Update Ciphersuite Implementation
- Ensure all HPKE algorithms work with pure JS implementation
- Test compatibility with existing MLS ciphersuites

## Phase 4: Signature & Key Management

### 4.1 Ed25519 Implementation
- Already using `@noble/curves` for Ed25519, P256, P384, P521
- Ensure ML-DSA uses pure JS random number generation
- Verify all signature algorithms work without WebCrypto

### 4.2 Key Format Handling
- If ASN.1 parsing is needed, integrate `asn1js`
- Ensure key import/export works with pure JS implementations

## Phase 5: Testing & Validation

### 5.1 Unit Tests
- Run existing test suite: `npm test`
- Fix any failures related to crypto implementation changes
- Ensure all ciphersuites pass validation

### 5.2 Integration Tests
- Test MLS protocol operations end-to-end
- Verify message encryption/decryption works
- Test group operations (join, leave, update)

### 5.3 Performance Testing
- Compare performance between WebCrypto and pure JS
- Ensure acceptable performance on mobile devices

## Phase 6: Documentation & Cleanup

### 6.1 Update Dependencies
- Remove WebCrypto-dependent packages
- Update package.json with new pure JS dependencies
- Update CONTRIBUTING.md to remove Node.js 19+ requirement

### 6.2 Update README
- Document new platform compatibility
- Update installation instructions
- Add React Native compatibility notes

## Implementation Guidelines

### For Each Component Replacement
1. **Create pure JS implementation** alongside existing WebCrypto version
2. **Add feature flag** to switch between implementations
3. **Test thoroughly** with existing test suite
4. **Remove WebCrypto version** only after validation
5. **Update all dependent code** to use new implementation

### Testing Strategy
- Run `npm test` after each component replacement
- Validate specific crypto operations in isolation
- Ensure backward compatibility during transition
- Test on multiple platforms (Node.js, browser, React Native)

## Risk Assessment

### Low Risk
- Random number generation replacement
- Hash function replacement
- Ed25519 (already pure JS)

### Medium Risk
- AES-GCM replacement
- HPKE implementation switch

### High Risk
- Breaking changes in HPKE API
- Performance degradation on mobile

## Success Criteria

1. **All tests pass**: `npm test` completes successfully
2. **No WebCrypto imports**: Complete removal of `crypto.` references
3. **React Native compatibility**: Works in React Native environment
4. **Performance maintained**: Acceptable performance compared to WebCrypto
5. **Security preserved**: All cryptographic operations remain secure

## Expected Benefits

- **Universal compatibility** (React Native, browsers, Node.js)
- **Smaller bundle size** (no polyfills needed)
- **Better mobile performance** (pure JS often faster than polyfilled WebCrypto)
- **Elimination of platform dependencies**
- **Improved developer experience** (no need for Node.js 19+)

## Notes

- The existing `@noble/*` libraries are already well-integrated and provide excellent pure JavaScript implementations
- This migration will maintain the same security guarantees while improving platform compatibility
- Each phase should be completed and validated before moving to the next
- Performance testing on mobile devices is crucial for React Native compatibility

## Test Folder Relevance by Phase

### Phase 1: Dependency Analysis & Planning
- **All test folders**: Audit for WebCrypto usage
- **Focus areas**: `test/crypto/`, `test/codec/`, `test/scenario/`

### Phase 2: Core Infrastructure Replacement
- **`test/crypto/`**: Test random number generation, hash functions, AES-GCM
- **`test/codec/`**: Test encoding/decoding with new crypto implementations
- **`test/test-vectors/`**: Validate against official MLS test vectors

### Phase 3: HPKE Implementation Replacement
- **`test/crypto/`**: Test HPKE operations, KEM, KDF
- **`test/scenario/`**: Test end-to-end MLS scenarios with new HPKE
- **`test/test-vectors/`**: Validate HPKE-specific test vectors

### Phase 4: Signature & Key Management
- **`test/crypto/`**: Test signature generation/verification
- **`test/validation/`**: Test key validation and format handling
- **`test/scenario/`**: Test group operations requiring signatures

### Phase 5: Testing & Validation
- **All test folders**: Comprehensive testing of all components
- **`test/scenario/`**: Full MLS protocol validation
- **`test/test-vectors/`**: Complete test vector validation

### Phase 6: Documentation & Cleanup
- **All test folders**: Final validation before release
- **Performance testing**: Compare results across platforms