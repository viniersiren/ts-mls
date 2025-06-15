/** @type {import('ts-jest').JestConfigWithTsJest} **/
export default {
  testEnvironment: "node",
  testPathIgnorePatterns: ["/dist/"],
  transform: {
    "^.+.tsx?$": ["ts-jest", {}],
  },
}
