/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  generateBuildId: async () => process.env.GITHUB_SHA || "local",
};

module.exports = nextConfig;
