// publish-post.mjs
import fs from 'fs';
import path from 'path';

const projectRoot = path.dirname(new URL(import.meta.url).pathname);
const draftsDir = path.join(projectRoot, 'blog-drafts');
const liveDir = path.join(projectRoot, 'src', 'pages', 'blog');

const slug = process.argv[2];
if (!slug) {
  console.log('Uso: node publish-post.mjs <slug-del-articulo>');
  console.log('Borradores disponibles en ./blog-drafts:');
  if (fs.existsSync(draftsDir)) {
    fs.readdirSync(draftsDir)
      .filter((f) => f.endsWith('.astro'))
      .forEach((f) => console.log('  •', f.replace('.astro', '')));
  }
  process.exit(1);
}

const cleanSlug = slug.replace(/\.astro$/, '');
const draftPath = path.join(draftsDir, `${cleanSlug}.astro`);
const livePath = path.join(liveDir, `${cleanSlug}.astro`);

if (!fs.existsSync(draftPath)) {
  console.error(`❌ No se encontró el borrador: ${draftPath}`);
  process.exit(1);
}

fs.mkdirSync(liveDir, { recursive: true });
fs.renameSync(draftPath, livePath);
console.log(`✅ Movido a producción: ${livePath}`);
console.log(`👉 Recuerda descomentar "${cleanSlug}" en src/data/blogPosts.ts y ejecutar: npm run build`);
