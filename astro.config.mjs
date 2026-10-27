import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://firmarpdfcertificado.com',
  trailingSlash: 'always',
  vite: {
    plugins: [tailwindcss()],
    server: {
      host: true,
      allowedHosts: true,
    },
    worker: {
      format: 'es',
    },
  },
  integrations: [
    sitemap({
      filter: (page) =>
        !page.includes('/r/holded/') &&
        !page.includes('/r/qonto/') &&
        !page.endsWith('/404/') &&
        !page.endsWith('/500/'),
    }),
  ],
});
