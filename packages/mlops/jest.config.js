/** @type {import('jest').Config} */
module.exports = {
  roots: ["<rootDir>/src", "<rootDir>/tests"],
  testEnvironment: "node",
  testMatch: ["<rootDir>/tests/**/*.test.ts"],
  transform: {
    "^.+\\.tsx?$": ["ts-jest", { tsconfig: "tsconfig.test.json", diagnostics: { ignoreCodes: [151002] } }],
  },
};
