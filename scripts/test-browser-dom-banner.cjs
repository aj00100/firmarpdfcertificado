#!/usr/bin/env node
/**
 * End-to-End Browser DOM Banner & UI Assertion Test Suite
 *
 * Uses JSDOM to load the exact HTML and client-side JavaScript from ValidatorStudio.astro.
 * Simulates user file drops across positive and tampered PDF files.
 * Verifies that the DOM layer renders the correct banners, alert titles,
 * and that no tampered file EVER sneaks past with a positive or neutral banner.
 */

const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');
const { JSDOM } = require('jsdom');
const esbuild = require('esbuild');

// 1. Read component HTML template and client script
const studioPath = path.join(__dirname, '../src/components/ValidatorStudio.astro');
const studioCode = fs.readFileSync(studioPath, 'utf8');

const templateHtml = studioCode.slice(0, studioCode.indexOf('<script>')).replace(/^---[\s\S]*?---/, '').trim();
const scriptContent = studioCode.slice(studioCode.indexOf('<script>') + 8, studioCode.indexOf('</script>'));

// 2. Transpile client script from TypeScript to CommonJS
const transpiledJs = esbuild.transformSync(
  scriptContent.replace(/import\s+[^;]+;/g, 'const trackEvent = () => {};'),
  { loader: 'ts', format: 'cjs' }
).code;

let totalDomAssertions = 0;
let passedDomAssertions = 0;

function assert(condition, message) {
  totalDomAssertions++;
  if (!condition) {
    console.error(`  ❌ DOM ASSERTION FAILED: ${message}`);
    throw new Error(`DOM Assertion failed: ${message}`);
  }
  passedDomAssertions++;
  console.log(`  ✅ ${message}`);
}

// 3. Test Runner using JSDOM environment
async function testDomForFile(filePath, expectedType, testLabel) {
  console.log(`\n---------------------------------------------------------------`);
  console.log(`[DOM TEST] ${testLabel} (${path.basename(filePath)})`);
  console.log(`---------------------------------------------------------------`);

  const fileBytes = fs.readFileSync(filePath);

  // Setup fresh JSDOM for each test
  const dom = new JSDOM(`<!DOCTYPE html><html><body>${templateHtml}</body></html>`, {
    runScripts: 'outside-only',
    url: 'https://firmarpdfcertificado.es/validar-firma-digital-pdf/'
  });

  const { window } = dom;
  window.crypto = webcrypto;

  // Provide mock File class
  class MockFile {
    constructor(buffer, name) {
      this._buf = buffer;
      this.name = name;
      this.size = buffer.length;
    }
    async arrayBuffer() {
      return this._buf.buffer.slice(this._buf.byteOffset, this._buf.byteOffset + this._buf.byteLength);
    }
  }

  // Execute client script inside window context
  const runScript = new Function('window', 'document', 'File', 'crypto', 'globalThis', transpiledJs);
  runScript(window, window.document, MockFile, webcrypto, window);

  // Trigger file input handler
  const fileInput = window.document.getElementById('pdf-audit-input');
  const mockFile = new MockFile(fileBytes, path.basename(filePath));
  Object.defineProperty(fileInput, 'files', { value: [mockFile], writable: true });

  fileInput.dispatchEvent(new window.Event('change'));

  // Wait for async execution of handleFile
  let attempts = 0;
  const statusBanner = window.document.getElementById('audit-status-banner');
  const statusTitle = window.document.getElementById('audit-status-title');
  const statusDesc = window.document.getElementById('audit-status-desc');
  const signaturesList = window.document.getElementById('signatures-list');

  while ((!statusTitle.textContent || statusTitle.textContent.trim() === '') && attempts < 50) {
    await new Promise((r) => setTimeout(r, 100));
    attempts++;
  }

  const title = statusTitle.textContent.trim();
  const desc = statusDesc.textContent.trim();
  const bannerClass = statusBanner.className;
  const listHtml = signaturesList.innerHTML;

  console.log(`  Rendered Banner Class: "${bannerClass}"`);
  console.log(`  Rendered Title:        "${title}"`);
  console.log(`  Rendered Desc:         "${desc.slice(0, 100)}..."`);

  if (expectedType === 'NEUTRAL_VALID') {
    assert(bannerClass.includes('bg-slate-100'), 'Positive file renders neutral slate banner (bg-slate-100)');
    assert(!bannerClass.includes('bg-red-50'), 'Positive file DOES NOT render red alert banner');
    assert(title.includes('Firma Analizada Localmente: Integridad Criptográfica Verificada'), 'Title confirms local cryptographic integrity');
    assert(desc.includes('Estructura interna PDF (árbol de objetos y tabla xref) no analizada'), 'Description explicitly disclaims unanalyzed PDF object graph');
    assert(listHtml.includes('Integridad Matemática Comprobada') || listHtml.includes('Algoritmo SHA-1'), 'Signature card confirms mathematical integrity');
  } else if (expectedType === 'ALERT_TAMPERED') {
    assert(bannerClass.includes('bg-red-50'), 'Tampered file MUST render red alert banner (bg-red-50)');
    assert(!bannerClass.includes('bg-slate-100'), 'Tampered file NEVER renders neutral slate banner');
    assert(title.startsWith('Alerta:'), 'Title MUST start with "Alerta:"');
    assert(!title.includes('Verificada'), 'Tampered title MUST NOT claim "Verificada"');
    assert(
      title.includes('Integridad Criptográfica Comprometida') ||
      title.includes('Modificación Posterior') ||
      title.includes('Manipulación Detectada'),
      'Title specifically states compromised integrity or posterior modification'
    );
  } else if (expectedType === 'ALERT_TRAILING_DATA') {
    assert(bannerClass.includes('bg-red-50'), 'Trailing data file renders red alert banner');
    assert(title.includes('Modificación Posterior') || title.includes('Integridad Criptográfica Comprometida'), 'Title indicates posterior modification');
  }
}

async function main() {
  console.log('=====================================================================');
  console.log('=== STARTING BROWSER DOM BANNER & TAMPER UI INTEGRATION SUITE ===');
  console.log('=====================================================================');

  // 1. Positive Tests (Should render neutral slate banner)
  await testDomForFile('/tmp/pades_e2e_test/signed_pbmac1.pdf', 'NEUTRAL_VALID', 'Positive Synthetic PBMAC1');
  await testDomForFile('/tmp/pades_e2e_test/signed_legacy.pdf', 'NEUTRAL_VALID', 'Positive Synthetic Legacy 3DES');
  await testDomForFile('/tmp/pades_e2e_test/signed_ecdsa_valid.pdf', 'NEUTRAL_VALID', 'Positive Synthetic ECDSA P-256');

  // 2. Cryptographic Negative Tests (MUST render red alert banner)
  await testDomForFile('/tmp/tamper_tests/tamper_sig_pbmac1.pdf', 'ALERT_TAMPERED', 'T1: Flipped RSA Signature Byte');
  await testDomForFile('/tmp/tamper_tests/tamper_time_pbmac1.pdf', 'ALERT_TAMPERED', 'T2: Mutated signingTime in signedAttrs');
  await testDomForFile('/tmp/tamper_tests/tamper_content_pbmac1.pdf', 'ALERT_TAMPERED', 'T3: Mutated PDF Document Body');
  await testDomForFile('/tmp/tamper_matrix_full/tamper_sha1_convenio.pdf', 'ALERT_TAMPERED', 'Real AutoFirma SHA-1 Mutated Body');
  await testDomForFile('/tmp/tamper_matrix_full/tamper_sha512_dss.pdf', 'ALERT_TAMPERED', 'Real EU DSS SHA-512 Mutated Body');
  await testDomForFile('/tmp/tamper_matrix_full/tamper_ecdsa_sig.pdf', 'ALERT_TAMPERED', 'Detached ECDSA Flipped Sig Byte');
  await testDomForFile('/tmp/tamper_matrix_full/tamper_cert_substitution.pdf', 'ALERT_TAMPERED', 'T4: Certificate Substitution Attack');

  // 3. Structural Negative Tests (MUST render red alert banner)
  await testDomForFile('/tmp/negative_test_pdfs/dss_modified_after_sig.pdf', 'ALERT_TRAILING_DATA', 'EU DSS Modified After Signature');
  await testDomForFile('/tmp/negative_test_pdfs/dss_pdf_corrupted.pdf', 'ALERT_TAMPERED', 'EU DSS Corrupted Document Stream');
  await testDomForFile('/tmp/negative_test_pdfs/dss_out_of_byterange.pdf', 'ALERT_TAMPERED', 'EU DSS Out-of-ByteRange Modification');
  await testDomForFile('/tmp/negative_test_pdfs/afirma_shadow_attack.pdf', 'ALERT_TRAILING_DATA', 'Spanish Gov Shadow Attack Revision');

  console.log('\n=====================================================================');
  console.log(`=== ALL DOM ASSERTIONS PASSED: ${passedDomAssertions}/${totalDomAssertions} SUCCEEDED (100%) ===`);
  console.log('=====================================================================');
}

main().catch((err) => {
  console.error('\n[FATAL DOM TEST FAILURE]:', err);
  process.exit(1);
});
