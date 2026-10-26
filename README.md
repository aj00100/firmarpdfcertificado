# FirmarPDFCertificado.com 🇪🇸

> **El firmador de PDF con certificado digital en el navegador más rápido, privado y gratuito de España.**  
> Firma tus documentos con certificado FNMT o DNIe sin instalar AutoFirma, sin Java y 100% en local.

## 🚀 Características
- **100% en el Navegador (RAM):** Ni el PDF ni tu certificado digital salen de tu equipo. Cumplimiento estricto con RGPD y eIDAS (Reglamento UE 910/2014).
- **Validez Legal Plena:** Genera firmas criptográficas avanzadas PAdES-B-B (ETSI EN 319 142-1) válidas ante la Agencia Tributaria (AEAT), Seguridad Social, DGT y juzgados.
- **Sin AutoFirma:** Di adiós a los errores de Java, bloqueos de puertos y fallos `Broken pipe` en macOS y Windows.
- **Compatible con Móviles:** Firma desde Safari en iPhone/iPad y Chrome en Android.

## 🛠️ Stack Tecnológico
- **Framework:** [Astro.js](https://astro.build/) (Static MPA)
- **Estilos:** Tailwind CSS v4
- **Criptografía:** Web Crypto API + `pkijs` + `node-forge` (Dual Engine PKCS#12)
- **Manipulación PDF:** `pdf-lib` (Inyección de firma detached PKCS#7 en `/Contents`)
- **Despliegue:** Cloudflare Pages (Coste de servidor: 0 €)

## 📦 Desarrollo Local
```bash
npm install
npm run dev
npm run build
```
