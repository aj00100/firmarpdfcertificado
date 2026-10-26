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

  // UNCOMMENT DAY 6: Regional AutoFirma Bypass (Junta de Andalucía >1,000/mo, GVA, Madrid — Easy KD)
  /*
  {
    slug: 'solucion-autofirma-junta-de-andalucia-gva-madrid',
    title: 'Solución a Errores de AutoFirma en Junta de Andalucía, GVA y Comunidad de Madrid (2026)',
    description:
      '¿AutoFirma no te deja firmar en la Ventanilla Electrónica de la Junta de Andalucía (VEA), Generalitat Valenciana o Madrid? Aprende cómo solucionarlo o presentar tu PDF ya firmado.',
    category: 'Sedes Autonómicas y AutoFirma',
    readTime: '6 min de lectura',
    updatedDate: '1 de noviembre de 2026',
    badgeColor: 'blue',
  },
  */

  // UNCOMMENT DAY 7: Plataforma Mercurio Extranjería (>1,000/mo x2) & Becas MEC (>10,000/mo — Easy KD)
  /*
  {
    slug: 'como-firmar-subir-documentos-plataforma-mercurio-y-becas-mec',
    title: 'Cómo Firmar y Subir Documentos PDF en Plataforma Mercurio (Extranjería) y Becas MEC',
    description:
      'Guía práctica para renovar el NIE o presentar expedientes en la Plataforma Mercurio de Extranjería y firmar solicitudes de Becas MEC e inscripción en Oposiciones sin fallos de Java.',
    category: 'Extranjería, Educación y Oposiciones',
    readTime: '7 min de lectura',
    updatedDate: '2 de noviembre de 2026',
    badgeColor: 'emerald',
  },
  */

  // UNCOMMENT DAY 8: Certificado Delitos Sexuales (>10,000/mo Easy KD) & Antecedentes Penales (>1,000/mo)
  /*
  {
    slug: 'como-descargar-certificado-delitos-sexuales-y-antecedentes-penales',
    title: 'Cómo Descargar el Certificado de Delitos Sexuales y Antecedentes Penales Online al Instante',
    description:
      'Pasos exactos para obtener gratis el Certificado de Delitos de Naturaleza Sexual y el Certificado de Antecedentes Penales (Tasa 006) en la Sede del Ministerio de Justicia con certificado digital.',
    category: 'Ministerio de Justicia',
    readTime: '6 min de lectura',
    updatedDate: '3 de noviembre de 2026',
    badgeColor: 'indigo',
  },
  */

  // UNCOMMENT DAY 9: Certificado de Empadronamiento (>10,000/mo Easy KD)
  /*
  {
    slug: 'descargar-certificado-empadronamiento-con-certificado-digital',
    title: 'Cómo Descargar el Certificado o Volante de Empadronamiento Online con Certificado Digital',
    description:
      'Guía para obtener al instante el certificado de empadronamiento individual o colectivo en Madrid, Barcelona, Valencia, Sevilla y cualquier ayuntamiento sin pedir cita previa.',
    category: 'Trámites Municipales y Padrón',
    readTime: '7 min de lectura',
    updatedDate: '4 de noviembre de 2026',
    badgeColor: 'emerald',
  },
  */

  // UNCOMMENT DAY 10: Registro Civil: Nacimiento (>10,000/mo), Matrimonio (>1,000/mo), Defunción (>1,000/mo), Últimas Voluntades (>1,000/mo — All Easy KD)
  /*
  {
    slug: 'solicitar-certificado-nacimiento-matrimonio-defuncion-ultimas-voluntades',
    title: 'Certificado de Nacimiento, Matrimonio, Defunción y Últimas Voluntades Online (Gratis)',
    description:
      'Cómo descargar gratis y en el acto los certificados oficiales del Registro Civil y del Ministerio de Justicia con tu certificado digital sin pagar a gestorías intermediarias.',
    category: 'Registro Civil y Herencias',
    readTime: '8 min de lectura',
    updatedDate: '5 de noviembre de 2026',
    badgeColor: 'blue',
  },
  */

  // UNCOMMENT DAY 11: Vida Laboral (>100K/mo), Renta 2026 (>10,000/mo) & Certificado Retenciones (>1,000/mo — All Easy KD)
  /*
  {
    slug: 'descargar-firmar-vida-laboral-borrador-renta-certificado-retenciones',
    title: 'Descargar Vida Laboral, Borrador de la Renta 2026 y Certificado de Retenciones IRPF con Certificado Digital',
    description:
      'Cómo obtener tu informe de Vida Laboral al segundo en Import@ss, consultar el borrador de la Declaración de la Renta 2026 y firmar tu certificado de retenciones en PDF.',
    category: 'Seguridad Social y Hacienda',
    readTime: '7 min de lectura',
    updatedDate: '6 de noviembre de 2026',
    badgeColor: 'amber',
  },
  */
];
