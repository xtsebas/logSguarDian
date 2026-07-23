/** @type {import('jest').Config} */
module.exports = {
  rootDir: "..",
  testEnvironment: "node",
  testMatch: ["<rootDir>/e2e/**/*.test.ts"],
  transform: {
    "^.+\\.tsx?$": ["ts-jest", { tsconfig: "<rootDir>/e2e/tsconfig.json" }],
  },
  testTimeout: 120000,
  maxWorkers: 1,
  verbose: true,
};
