import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueDevTools from 'vite-plugin-vue-devtools'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    vueDevTools(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    },
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:1234',
        changeOrigin: true
      },
      '/drm': {
        target: 'http://127.0.0.1:1234',
        changeOrigin: true
      },
      '/subscribe-url': {
        target: 'http://127.0.0.1:1234',
        changeOrigin: true
      }
    }
  }
})
