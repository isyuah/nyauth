import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
      '/auth': 'http://localhost:8080',
      '/authorize': 'http://localhost:8080',
      '/token': 'http://localhost:8080',
      '/.well-known': 'http://localhost:8080',
      '/userinfo': 'http://localhost:8080',
      '/health': 'http://localhost:8080'
    }
  }
});
