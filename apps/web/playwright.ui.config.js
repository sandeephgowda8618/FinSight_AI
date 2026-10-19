const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests/ui",
  reporter: [["list"], ["junit", { outputFile: "./test-results/ui/results.xml" }]],
  outputDir: "./test-results/ui",
  use: {
    baseURL: "http://127.0.0.1:3100",
    browserName: "chromium",
    headless: true,
  },
  webServer: {
    command: "npm run dev -- --hostname 127.0.0.1 --port 3100",
    url: "http://127.0.0.1:3100",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    env: { NEXT_TELEMETRY_DISABLED: "1", API_BASE_URL: "http://127.0.0.1:8100" },
  },
});
