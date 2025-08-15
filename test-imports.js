// Test file to isolate React Native import issues
// Comment out imports one by one to find the problematic one

// Test 1: Basic noble imports
console.log('Testing @noble/hashes...');
try {
  const { randomBytes } = require('@noble/hashes/utils');
  console.log('✅ @noble/hashes/utils imported successfully');
} catch (e) {
  console.log('❌ @noble/hashes/utils failed:', e.message);
}

// Test 2: HPKE core
console.log('Testing @hpke/core...');
try {
  const { CipherSuite } = require('@hpke/core');
  console.log('✅ @hpke/core imported successfully');
} catch (e) {
  console.log('❌ @hpke/core failed:', e.message);
}

// Test 3: Noble curves
console.log('Testing @noble/curves...');
try {
  const { ed25519 } = require('@noble/curves/ed25519');
  console.log('✅ @noble/curves/ed25519 imported successfully');
} catch (e) {
  console.log('❌ @noble/curves/ed25519 failed:', e.message);
}

// Test 4: Noble ciphers
console.log('Testing @noble/ciphers...');
try {
  const { utf8ToBytes } = require('@noble/ciphers/utils');
  console.log('✅ @noble/ciphers/utils imported successfully');
} catch (e) {
  console.log('❌ @noble/ciphers/utils failed:', e.message);
}

console.log('Import tests completed');