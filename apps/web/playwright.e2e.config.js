const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests/e2e",
  reporter: [["list"], ["junit", { outputFile: "./test-results/e2e/results.xml" }]],
  outputDir: "./test-results/e2e",
  timeout: 30_000,
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://127.0.0.1:3100",
    browserName: "chromium",
    headless: true,
  },
});
