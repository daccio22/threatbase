import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Set base to repo name for GitHub Pages — override with VITE_BASE env var
const base = process.env.VITE_BASE || '/threatbase/'

export default defineConfig({
  plugins: [react()],
  base,
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
