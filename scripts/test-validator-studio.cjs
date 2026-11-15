#!/usr/bin/env node
/**
 * ValidatorStudio Comprehensive Verification & Negative Test Suite
 * 
 * Verifies that the client-side auditPdfBuffer() logic from ValidatorStudio.astro:
 *  1. Correctly verifies positive signed PDFs (PBMAC1, Legacy 3DES, AutoFirma, EU DSS)
 *     with mathematical RSA verification (WebCrypto), sid cert binding, and PAdES detection.
 *  2. Correctly flags SHA-1 as legacy/deprecated.
 *  3. Strictly detects and fails negative fixtures:
 *     - Shadow attacks & post-signature modifications (coversEntireFile === false)
 *     - Corrupted document contents (hashMatches === false)
 *     - Bit-flipped RSA signatures (mathSignatureValid === false)
 */
const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');
globalThis.crypto = webcrypto;

// Load ValidatorStudio functions directly from component source
const studioPath = path.join(__dirname, '../src/components/ValidatorStudio.astro');
const studioCode = fs.readFileSync(studioPath, 'utf8');

const scriptStart = studioCode.indexOf('<script>');
const scriptEnd = studioCode.indexOf('</script>');
const scriptContent = studioCode.slice(scriptStart + 8, scriptEnd);

const esbuild = require('../node_modules/esbuild');

// Extract pure cryptographic analysis functions (before DOM manipulation)
const cutoffIdx = scriptContent.indexOf('// Referencias del DOM');
const pureFunctionsCode = scriptContent.slice(0, cutoffIdx).replace(/import\s+[^;]+;/g, '');

const jsTranspiled = esbuild.transformSync(pureFunctionsCode, { loader: 'ts', format: 'cjs' }).code;

const scriptToRun = `
  const trackEvent = () => {};
  ${jsTranspiled}
  
  module.exports = {
    auditPdfBuffer,
    inspectPkcs7Cms,
    inspectCmsFull,
    parseAsn1,
    hexToBytes
  };
`;

const m = { exports: {} };
const fn = new Function('module', 'exports', 'require', 'globalThis', scriptToRun);
fn(m, m.exports, require, globalThis);

const { auditPdfBuffer } = m.exports;

let totalAssertions = 0;
let passedAssertions = 0;

function assert(condition, message) {
  totalAssertions++;
  if (!condition) {
    console.error(`  ❌ ASSERTION FAILED: ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  passedAssertions++;
  console.log(`  ✅ ${message}`);
}

async function auditBuffer(buf, label) {
  const mockFile = {
    name: label,
    size: buf.length,
    arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
  };
  return await auditPdfBuffer(mockFile);
}

async function runPositiveTest(filePath, label, expected = {}) {
  console.log(`\n===============================================================`);
  console.log(`[POSITIVE TEST] ${label}`);
  console.log(`===============================================================`);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Fixture file not found: ${filePath}`);
  }

  const buf = fs.readFileSync(filePath);
  const result = await auditBuffer(buf, label);

  console.log(`  Signatures detected: ${result.signatures.length}`);
  assert(result.signatures.length > 0, `At least 1 signature detected in ${label}`);

  for (const sig of result.signatures) {
    console.log(`  - Signature #${sig.index}:`);
    console.log(`    ByteRange: [${sig.byteRange.join(', ')}]`);
    console.log(`    Covers Entire File: ${sig.coversEntireFile}`);
    console.log(`    Digest Algorithm: ${sig.signerInfo?.digestAlgorithm}`);
    console.log(`    Hash Matches: ${sig.hashMatches}`);
    console.log(`    Math RSA Valid: ${sig.mathSignatureValid}`);
    console.log(`    SID Cert Matched: ${sig.sidMatched}`);
    console.log(`    PAdES ESSCertIDv2: ${sig.signerInfo?.hasPadesEssCertIdV2}`);
    console.log(`    Signer CN: "${sig.cmsInfo?.subject?.CN || 'N/A'}"`);

    assert(sig.rangeValidBounds === true, `Signature #${sig.index} ByteRange is within file bounds`);
    assert(sig.coversEntireFile === true, `Signature #${sig.index} covers entire file`);
    assert(sig.hashMatches === true, `Signature #${sig.index} hash matches messageDigest`);
    assert(sig.mathSignatureValid === true, `Signature #${sig.index} RSA mathematical verification succeeds`);
    assert(sig.sidMatched === true, `Signature #${sig.index} certificate matched via SignerIdentifier (sid)`);

    if (expected.digestAlgorithm) {
      assert(sig.signerInfo?.digestAlgorithm === expected.digestAlgorithm, `Signature #${sig.index} uses ${expected.digestAlgorithm}`);
    }
    if (expected.isSha1 !== undefined) {
      assert(sig.isSha1 === expected.isSha1, `Signature #${sig.index} isSha1 matches expected (${expected.isSha1})`);
    }
    if (expected.requirePadesEssCertIdV2) {
      assert(sig.signerInfo?.hasPadesEssCertIdV2 === true, `Signature #${sig.index} contains PAdES ESSCertIDv2 attribute`);
    }
  }
}

async function runNegativeFixture(filePath, label, expectedFailures = {}) {
  console.log(`\n===============================================================`);
  console.log(`[NEGATIVE TEST] ${label}`);
  console.log(`===============================================================`);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Fixture file not found: ${filePath}`);
  }

  const buf = fs.readFileSync(filePath);
  const result = await auditBuffer(buf, label);

  console.log(`  Signatures detected: ${result.signatures.length}`);
  assert(result.signatures.length > 0, `Signature structure detected for negative audit`);

  for (const sig of result.signatures) {
    console.log(`  - Signature #${sig.index}:`);
    console.log(`    Covers Entire File: ${sig.coversEntireFile}`);
    console.log(`    Hash Matches: ${sig.hashMatches}`);
    console.log(`    Math RSA Valid: ${sig.mathSignatureValid}`);

    if (expectedFailures.coversEntireFile === false) {
      assert(sig.coversEntireFile === false, `Correctly detected unauthenticated trailing bytes / shadow revision (coversEntireFile === false)`);
    }
    if (expectedFailures.hashMatches === false) {
      assert(sig.hashMatches === false, `Correctly detected document content tampering (hashMatches === false)`);
    }
  }
}

async function runSyntheticTamperTests() {
  console.log(`\n===============================================================`);
  console.log(`[SYNTHETIC NEGATIVE TESTS] Mathematical Tamper Vectors`);
  console.log(`===============================================================`);

  const originalPath = '/tmp/pades_e2e_test/signed_pbmac1.pdf';
  const originalBuf = fs.readFileSync(originalPath);

  // 1. Bit-flip the RSA signature inside the CMS DER container
  console.log(`\n--- Test: Tampering with RSA Signature Bytes ---`);
  const latin1 = originalBuf.toString('latin1');
  const match = latin1.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  const [_, b0, l0, b1, l1] = match.map(Number);
  const hexSlice = latin1.slice(b0 + l0, b1).match(/<([0-9A-Fa-f\s]+)>/)[1];

  const cmsBytes = m.exports.hexToBytes(hexSlice);
  const tamperedDer = new Uint8Array(cmsBytes);
  // Invert one byte in the 256-byte RSA signature (near the end of the DER structure)
  tamperedDer[tamperedDer.length - 100] ^= 0x01;
  const tamperedHex = Array.from(tamperedDer).map(b => b.toString(16).padStart(2, '0')).join('') + '0'.repeat(hexSlice.length - tamperedDer.length * 2);

  const sigTamperedBuf = Buffer.concat([
    originalBuf.slice(0, b0 + l0),
    Buffer.from('<' + tamperedHex + '>'),
    originalBuf.slice(b1)
  ]);

  const sigTamperResult = await auditBuffer(sigTamperedBuf, 'RSA Signature Tampered PDF');
  assert(sigTamperResult.signatures.length === 1, 'Detected 1 signature in tampered PDF');
  const tamperedSig = sigTamperResult.signatures[0];
  assert(tamperedSig.mathSignatureValid === false, 'WebCrypto crypto.subtle.verify correctly REJECTS tampered RSA signature (mathSignatureValid === false)');

  // 2. Modify document content in signed ByteRange
  console.log(`\n--- Test: Tampering with Document Content Inside ByteRange ---`);
  const contentTamperedBuf = Buffer.from(originalBuf);
  // Modify a byte in the first byte range (b0 + 10)
  contentTamperedBuf[10] ^= 0x01;

  const contentTamperResult = await auditBuffer(contentTamperedBuf, 'Document Content Tampered PDF');
  assert(contentTamperResult.signatures.length === 1, 'Detected 1 signature in content-tampered PDF');
  const tamperedContentSig = contentTamperResult.signatures[0];
  assert(tamperedContentSig.hashMatches === false, 'Correctly REJECTS tampered document content (hashMatches === false)');

  // 3. Append trailing bytes to simulate shadow revision
  console.log(`\n--- Test: Appending Shadow Data After Signed ByteRange ---`);
  const trailingBuf = Buffer.concat([
    originalBuf,
    Buffer.from('\n%% SHADOW ATTACK / POST SIGNATURE MODIFICATION %%\n')
  ]);
  const trailingResult = await auditBuffer(trailingBuf, 'Trailing Data PDF');
  assert(trailingResult.signatures.length === 1, 'Detected 1 signature in trailing-data PDF');
  const trailingSig = trailingResult.signatures[0];
  assert(trailingSig.coversEntireFile === false, 'Correctly flags document as incomplete due to trailing data (coversEntireFile === false)');
}

async function main() {
  console.log(`=====================================================================`);
  console.log(`=== STARTING VALIDATOR STUDIO REALITY AUDIT (POSITIVE & NEGATIVE) ===`);
  console.log(`=====================================================================`);

  // Positive Test Suite (5 files)
  await runPositiveTest(
    '/tmp/pades_e2e_test/signed_pbmac1.pdf',
    'OUR ENGINE: Modern PBMAC1 (RFC 9879) Signed PDF',
    { digestAlgorithm: 'SHA-256', isSha1: false, requirePadesEssCertIdV2: true }
  );

  await runPositiveTest(
    '/tmp/pades_e2e_test/signed_legacy.pdf',
    'OUR ENGINE: Legacy 3DES Signed PDF',
    { digestAlgorithm: 'SHA-256', isSha1: false, requirePadesEssCertIdV2: true }
  );

  await runPositiveTest(
    '/tmp/real_signed_pdfs/afirma_convenio_firmado.pdf',
    'REAL-WORLD: Spanish Government AutoFirma Convenio (SHA-1)',
    { digestAlgorithm: 'SHA-1', isSha1: true }
  );

  await runPositiveTest(
    '/tmp/real_signed_pdfs/afirma_abogacia_estado.pdf',
    'REAL-WORLD: Spanish Government AutoFirma Abogacía del Estado (BER Indefinite Length)',
    { digestAlgorithm: 'SHA-1', isSha1: true }
  );

  await runPositiveTest(
    '/tmp/real_signed_pdfs/pades_bes_dss.pdf',
    'REAL-WORLD: European Commission DSS PAdES-BES (SHA-512)',
    { digestAlgorithm: 'SHA-512', isSha1: false, requirePadesEssCertIdV2: true }
  );

  // Negative Fixture Suite (3 official external files)
  await runNegativeFixture(
    '/tmp/negative_test_pdfs/dss_modified_after_sig.pdf',
    'EU DSS NEGATIVE: Modified After Signature',
    { coversEntireFile: false }
  );

  await runNegativeFixture(
    '/tmp/negative_test_pdfs/dss_pdf_corrupted.pdf',
    'EU DSS NEGATIVE: Corrupted Document Content',
    { hashMatches: false, coversEntireFile: false }
  );

  await runNegativeFixture(
    '/tmp/negative_test_pdfs/afirma_shadow_attack.pdf',
    'AFIRMA NEGATIVE: Shadow Attack Multi-Signature PDF',
    { coversEntireFile: false }
  );

  // Synthetic Negative Tampering Suite
  await runSyntheticTamperTests();

  console.log(`\n=====================================================================`);
  console.log(`=== ALL AUDITS PASSED: ${passedAssertions}/${totalAssertions} ASSERTIONS SUCCEEDED (100%) ===`);
  console.log(`=====================================================================`);
}

main().catch((err) => {
  console.error('\n[FATAL AUDIT FAILURE]:', err);
  process.exit(1);
});
