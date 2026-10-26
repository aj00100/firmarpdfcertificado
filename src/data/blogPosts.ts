// src/data/blogPosts.ts
export interface BlogPostMeta {
  slug: string;
  title: string;
  description: string;
  category: string;
  readTime: string;
  updatedDate: string;
  badgeColor: 'amber' | 'blue' | 'emerald' | 'indigo';
}

export const publishedBlogPosts: BlogPostMeta[] = [
  // DAY 1 LIVE POST (High-Ticket VeriFactu B2B Affiliate Magnet)
  {
    slug: 'normativa-verifactu-multas-facturas-pdf',
    title: 'Normativa VeriFactu 2026: Sanciones de 50.000 € y Cómo Firmar Facturas PDF Legalmente',
    description:
      'Guía completa sobre el Reglamento VeriFactu (RD 1007/2023) y la Ley Antifraude. Cuándo es válido firmar facturas PDF con certificado digital y cómo evitar multas de Hacienda.',
    category: 'Facturación y VeriFactu',
    readTime: '7 min de lectura',
    updatedDate: '27 de octubre de 2026',
    badgeColor: 'amber',
  },

  // UNCOMMENT DAY 2 WHEN MOVED FROM blog-drafts/ TO src/pages/blog/
  /*
  {
    slug: 'como-hacer-factura-rectificativa-requisitos-hacienda',
    title: 'Cómo Hacer una Factura Rectificativa en España: Requisitos AEAT, Ejemplo y Firma Digital',
    description:
      'Aprende cómo emitir y firmar una factura rectificativa por sustitución o por diferencias (Art. 15 RD 1619/2012) para recuperar el IVA de facturas impagadas o corregir errores.',
    category: 'Autónomos y Pymes',
    readTime: '6 min de lectura',
    updatedDate: '28 de octubre de 2026',
    badgeColor: 'blue',
  },
  */

  // UNCOMMENT DAY 3: Cl@ve PIN Myth Funnel (>10,000/mo Easy KD)
  /*
  {
    slug: 'se-puede-firmar-pdf-con-clave-pin',
    title: '¿Se Puede Firmar un PDF con Cl@ve PIN o Cl@ve Permanente? Diferencias y Solución',
    description:
      'Descubre por qué el sistema Cl@ve PIN solo sirve para trámites internos de la AEAT y cómo firmar cualquier documento PDF externo gratis con tu certificado digital FNMT o DNIe.',
    category: 'Identidad Digital y Cl@ve',
    readTime: '6 min de lectura',
    updatedDate: '29 de octubre de 2026',
    badgeColor: 'emerald',
  },
  */

  // UNCOMMENT DAY 4: Certificado Estar al Corriente (>1,000/mo x8 terms, 100% Easy KD)
  /*
  {
    slug: 'como-obtener-certificado-estar-al-corriente-seguridad-social-hacienda',
    title: 'Cómo Obtener el Certificado de Estar al Corriente con Hacienda y la Seguridad Social Online',
    description:
      'Guía paso a paso para descargar al instante el certificado de estar al corriente de pago (Art. 43.1.f LGT y TGSS) con certificado digital para contratistas, subvenciones y licitaciones.',
    category: 'Autónomos y Empresas',
    readTime: '7 min de lectura',
    updatedDate: '30 de octubre de 2026',
    badgeColor: 'amber',
  },
  */

  // UNCOMMENT DAY 5: LexNET Justicia & Abogacía (>10,000/mo x2 terms, Easy KD)
  /*
  {
    slug: 'como-firmar-pdf-para-lexnet-abogados-procuradores',
    title: 'Cómo Firmar Documentos PDF y Escritos para LexNET Justicia sin Errores (PAdES)',
    description:
      'Requisitos técnicos del Ministerio de Justicia para firmar demandas, escritos de trámite y poderes en PDF para LexNET Abogacía y Procuradores sin bloqueos de AutoFirma ni Java.',
    category: 'Justicia y LegalTech',
    readTime: '7 min de lectura',
    updatedDate: '31 de octubre de 2026',
    badgeColor: 'indigo',
  },
  */
];
