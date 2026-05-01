import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],

  // Built assets are referenced as /frontend/assets/... in the HTML.
  // The Python server already handles GET /frontend/* → FRONTEND_DIR/*.
  base: '/frontend/',

  build: {
    // Overwrite the old hand-written source files with compiled output.
    outDir:     '../frontend',
    emptyOutDir: true,
  },

  // ── Dev-server proxy (optional, for hot-reload development) ──────────────
  // Run `npm run dev` here while `python3 server.py` runs on 8765.
  // Visit http://localhost:5173/ — API calls are forwarded automatically.
  // Note: the session cookie is scoped to 8765, so log in there once first.
  server: {
    proxy: {
      '/alerts':  'http://localhost:8765',
      '/events':  'http://localhost:8765',
      '/flows':   'http://localhost:8765',
      '/dns':     'http://localhost:8765',
      '/http':    'http://localhost:8765',
      '/charts':  'http://localhost:8765',
      '/webhooks':'http://localhost:8765',
      '/users':   'http://localhost:8765',
      '/me':      'http://localhost:8765',
      '/health':  'http://localhost:8765',
      '/login':   'http://localhost:8765',
      '/logout':  'http://localhost:8765',
    },
  },
});
