/** @type {import('jest').Config} */
module.exports = {
  roots: ["<rootDir>/src", "<rootDir>/tests"],
  testMatch: ["**/*.test.ts"],
  projects: [
    {
      displayName: "default",
      testEnvironment: "node",
      testMatch: ["<rootDir>/tests/**/*.test.ts"],
      testPathIgnorePatterns: ["parity.node.test.ts"],
      transform: {
        "^.+\\.tsx?$": ["ts-jest", { diagnostics: { ignoreCodes: [151002] } }],
      },
    },
    {
      displayName: "ort-parity",
      // Custom environment pins TypedArray constructors so onnxruntime-node's
      // native addon instanceof checks pass inside Jest's vm context.
      testEnvironment: "<rootDir>/jest-ort-environment.js",
      testMatch: ["<rootDir>/tests/parity.node.test.ts"],
      transform: {
        "^.+\\.tsx?$": ["ts-jest", { diagnostics: { ignoreCodes: [151002] } }],
      },
    },
  ],
};
