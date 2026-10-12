import { defineConfig } from '@playwright/test';
export default defineConfig({
    testDir: './tests',
    use: { baseURL: 'http://127.0.0.1:4197', launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } },
    webServer: { command: 'bun scripts/test-server.js', url: 'http://127.0.0.1:4197', reuseExistingServer: false },
});
