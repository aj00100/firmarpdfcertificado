# FirmarPDFCertificado.com 🇪🇸

> **El firmador de PDF con certificado digital en el navegador más rápido, privado y gratuito de España.**  
> Firma tus documentos con certificado FNMT, DNIe o cualquier archivo `.p12` / `.pfx` sin instalar AutoFirma, sin Java y 100% en local.

---

## 🚀 Características

- **100% en el Navegador (RAM & Web Workers):** Ni el archivo PDF ni la clave privada de tu certificado digital salen jamás de tu dispositivo. Cumplimiento estricto con el **RGPD** y el **Reglamento eIDAS (UE 910/2014)**.
- **Validez Legal Plena:** Genera firmas criptográficas avanzadas **PAdES-B-B (ETSI EN 319 142-1)** válidas ante la Agencia Tributaria (AEAT), Seguridad Social, DGT y juzgados.
- **Sin AutoFirma ni Java:** Olvídate de dependencias pesadas, bloqueos de puertos locales y errores típicos de configuración en macOS y Windows.
- **Validador Criptográfico Integrado:** Inspecciona y verifica firmas existentes en cualquier PDF con lectura de metadatos X.509 (NIF/NIE del emisor, fecha, integridad de bytes y autoridad de certificación).
- **Multiplataforma:** Compatible con navegadores modernos de escritorio y móviles (Chrome, Safari, Firefox, Edge en Windows, macOS, Linux, iOS y Android).
- **21 Páginas y Guías Especializadas:** Arquitectura optimizada para SEO con guías sobre exportación FNMT, DNIe, co-firmas, normativa Veri*factu y resolución de errores.

---

## 🛠️ Stack Tecnológico

| Componente | Tecnología | Uso |
| :--- | :--- | :--- |
| **Framework** | [Astro.js 5](https://astro.build/) | Static MPA ultrarrápido con renderizado estático |
| **Estilos** | Tailwind CSS v4 | Diseño responsive y componentes accesibles |
| **Criptografía** | Web Crypto API + `pkijs` + `node-forge` | Motor dual PKCS#12, digests SHA-256 y firma detached PKCS#7 |
| **Manipulación PDF** | `pdf-lib` | Inyección de diccionario `/ByteRange`, stamping visual y ensamblado |
| **Hosting & CDN** | Cloudflare Workers Static Assets | Despliegue global en el edge de alta velocidad y coste cero |

---

## 📦 Instalación y Desarrollo Local

### Requisitos Previos
- **Node.js** `>= 22.12.0`
- **npm** `>= 10.0.0`

### Comandos Básicos

```bash
# 1. Clonar el repositorio
git clone https://github.com/aj00100/firmarpdfcertificado.git
cd firmarpdfcertificado

# 2. Instalar dependencias
npm install

# 3. Iniciar servidor de desarrollo local
npm run dev

# 4. Construir para producción (genera la carpeta dist/)
npm run build
```

---

## 🧪 Pruebas y Validación (Generador de Test)

El repositorio incluye un script para generar un documento PDF y un certificado digital PKCS#12 (`.p12` / `.pfx`) de prueba técnica:

```bash
# Generar archivos de prueba en la raíz del proyecto
npm run test:generate
# O directamente:
python3 scripts/generate-test-files.py
```

### Archivos generados:
1. **`test_document.pdf`:** Documento PDF con estructura PAdES y área para estampado visual.
2. **`test_certificate.p12` / `test_certificate.pfx`:** Certificado RSA 2048-bit X.509 de prueba con NIF simulado.
3. **Contraseña por defecto:** `1234`

### Flujo de prueba:
1. Accede a tu entorno local (`http://localhost:4321`) o al sitio en producción (`https://firmarpdfcertificado.com`).
2. Sube **`test_document.pdf`**.
3. Sube **`test_certificate.p12`**.
4. Introduce la contraseña: `1234`.
5. Haz clic en **"Firmar PDF Ahora"** y descarga el archivo resultante.
6. Abre el archivo en **Adobe Acrobat Reader** o en la herramienta **/validar-firma-digital-pdf** para comprobar la validez de la firma.

---

## 🌐 Despliegue en Cloudflare

El proyecto se despliega como un Worker de activos estáticos (**Cloudflare Workers Static Assets**) utilizando `wrangler.json`:

```json
{
  "name": "firmarpdfcertificado",
  "compatibility_date": "2026-10-23",
  "assets": {
    "directory": "./dist"
  }
}
```

### Desplegar a Producción

```bash
# Compilar y desplegar con Wrangler
npm run deploy

# O con credenciales de API directamente:
export CLOUDFLARE_API_KEY="<TU_API_KEY>"
export CLOUDFLARE_EMAIL="<TU_EMAIL>"
export CLOUDFLARE_ACCOUNT_ID="<TU_ACCOUNT_ID>"
npx wrangler deploy
```

---

## 🔒 Privacidad y Seguridad

- **Zero-Knowledge Architecture:** El procesamiento criptográfico y la manipulación del árbol binario del PDF ocurren exclusivamente dentro del hilo de un Web Worker en la memoria RAM del navegador.
- **Sin Almacenamiento Remoto:** Ningún byte de tus documentos ni de tus certificados se transfiere a ningún servidor externo.
- **Cabeceras de Seguridad:** Políticas estrictas de Content Security Policy (`CSP`), HSTS, `X-Content-Type-Options: nosniff` y `X-Frame-Options: SAMEORIGIN`.

---

## 📄 Licencia

Este proyecto es privado y confidencial. Todos los derechos reservados.
