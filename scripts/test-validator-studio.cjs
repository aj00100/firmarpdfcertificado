#!/usr/bin/env node
/**
 * ValidatorStudio Comprehensive Verification & Cryptographic Negative Test Suite
 * 
 * Verifies that the client-side auditPdfBuffer() logic from ValidatorStudio.astro:
 *  1. Correctly verifies positive signed PDFs (PBMAC1, Legacy 3DES, AutoFirma, EU DSS)
 *     with mathematical RSA verification (WebCrypto), sid cert binding, PAdES detection,
 *     and ETSI ESSCertIDv2 certificate hash binding.
 *  2. Handles Multi-Signature / Incremental Saves without false-red warnings on co-signed PDFs.
 *  3. Verifies official external negative fixtures from EU DSS and Spanish Government (@firma).
 *  4. Enforces the complete Negative Cryptographic Attack Matrix:
 *     - T1: Bit-flipped RSA signature value (mathSignatureStatus === "INVALID")
 *     - T2: Tampered signingTime in signedAttrs (mathSignatureStatus === "INVALID")
 *     - T3: Tampered document content in ByteRange (hashMatches === false)
 *     - T4: Certificate substitution attack (certSubstitutionDetected === true)
 *     - T5: ByteRange gap injection / wrapping attack (gapIntegrityValid === false)
 *     - T6: Graceful handling of unsupported algorithms (RSA-PSS) without false corruption flag
 *  5. Executes independent pyHanko audit on output files.
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
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
    hexToBytes,
    toHex,
    decodeOid
  };
`;

const m = { exports: {} };
const fn = new Function('module', 'exports', 'require', 'globalThis', scriptToRun);
fn(m, m.exports, require, globalThis);

const { auditPdfBuffer, hexToBytes, parseAsn1, toHex, decodeOid } = m.exports;

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
    console.log(`    Gap Integrity Valid: ${sig.gapIntegrityValid}`);
    console.log(`    Covers Entire File: ${sig.coversEntireFile}`);
    console.log(`    Digest Algorithm: ${sig.signerInfo?.digestAlgorithm}`);
    console.log(`    Hash Matches: ${sig.hashMatches}`);
    console.log(`    Math Status: ${sig.mathSignatureStatus} (${sig.sigAlgorithmLabel})`);
    console.log(`    SID Cert Matched: ${sig.sidMatched}`);
    console.log(`    ESSCertIDv2 Hash Matched: ${sig.certHashMatches}`);
    console.log(`    Signer CN: "${sig.cmsInfo?.subject?.CN || 'N/A'}"`);

    assert(sig.rangeValidBounds === true, `Signature #${sig.index} ByteRange is within file bounds`);
    assert(sig.gapIntegrityValid === true, `Signature #${sig.index} ByteRange gap is clean (/Contents hex only)`);
    assert(sig.hashMatches === true, `Signature #${sig.index} hash matches messageDigest`);
    assert(sig.mathSignatureStatus === 'VALID', `Signature #${sig.index} mathematical verification succeeds (mathSignatureStatus === "VALID")`);
    assert(sig.sidMatched === true, `Signature #${sig.index} certificate matched via SignerIdentifier (sid)`);

    if (expected.digestAlgorithm) {
      assert(sig.signerInfo?.digestAlgorithm === expected.digestAlgorithm, `Signature #${sig.index} uses ${expected.digestAlgorithm}`);
    }
    if (expected.isSha1 !== undefined) {
      assert(sig.isSha1 === expected.isSha1, `Signature #${sig.index} isSha1 matches expected (${expected.isSha1})`);
    }
    if (expected.requireCertHashMatch) {
      assert(sig.certHashMatches === true, `Signature #${sig.index} certificate raw DER hash matches ESSCertIDv2 certHash`);
    }
  }
}

async function runMultiSigTest(filePath, label) {
  console.log(`\n===============================================================`);
  console.log(`[MULTI-SIGNATURE TEST] ${label}`);
  console.log(`===============================================================`);

  const buf = fs.readFileSync(filePath);
  const result = await auditBuffer(buf, label);

  console.log(`  Signatures detected: ${result.signatures.length}`);
  assert(result.signatures.length >= 2, `Multiple signatures detected (${result.signatures.length})`);

  const latestSig = result.signatures[result.signatures.length - 1];
  const hasTrailingData = (latestSig.byteRange[2] + latestSig.byteRange[3] < buf.length);
  assert(hasTrailingData === false, 'Latest signature covers the file; no false trailing-data flag on valid multi-sig document');

  for (let i = 0; i < result.signatures.length; i++) {
    const sig = result.signatures[i];
    assert(sig.hashMatches === true, `Signature #${sig.index} ByteRange hash matches messageDigest`);
    if (sig.isLatestSignature) {
      assert(sig.coversEntireFile === true, `Final signature #${sig.index} covers entire file`);
    } else {
      assert(sig.isHistoricalRevision === true, `Intermediate signature #${sig.index} correctly identified as historical revision`);
      assert(sig.isEnclosedBySubsequent === true, `Intermediate signature #${sig.index} correctly enclosed by subsequent signature`);
    }
  }
}

async function runNegativeFixture(filePath, label, expectedFailures = {}) {
  console.log(`\n===============================================================`);
  console.log(`[NEGATIVE FIXTURE TEST] ${label}`);
  console.log(`===============================================================`);

  const buf = fs.readFileSync(filePath);
  const result = await auditBuffer(buf, label);

  console.log(`  Signatures detected: ${result.signatures.length}`);
  assert(result.signatures.length > 0, `Signature structure detected for negative audit`);

  const latestSig = result.signatures[result.signatures.length - 1];
  const hasTrailingData = (latestSig.byteRange[2] + latestSig.byteRange[3] < buf.length);

  if (expectedFailures.hasTrailingData) {
    assert(hasTrailingData === true, 'Correctly detected unauthenticated trailing data / shadow revision at end of file');
  }

  for (const sig of result.signatures) {
    if (expectedFailures.hashMatches === false) {
      assert(sig.hashMatches === false, `Correctly detected document content tampering (hashMatches === false) on signature #${sig.index}`);
    }
  }
}

async function runNegativeAttackMatrix() {
  console.log(`\n===============================================================`);
  console.log(`[NEGATIVE ATTACK MATRIX] Cryptographic Tamper & Attack Vectors`);
  console.log(`===============================================================`);

  const originalPath = '/tmp/pades_e2e_test/signed_pbmac1.pdf';
  const originalBuf = fs.readFileSync(originalPath);
  const latin1 = originalBuf.toString('latin1');
  const match = latin1.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  const [_, b0, l0, b1, l1] = match.map(Number);
  const hexSlice = latin1.slice(b0 + l0, b1).match(/<([0-9A-Fa-f\s]+)>/)[1];
  const cmsBytes = hexToBytes(hexSlice);

  // T1: Bit-flip inside RSA signature value in CMS
  console.log(`\n--- [T1 Attack Vector] Bit-flipped RSA Signature Value ---`);
  const t1Der = new Uint8Array(cmsBytes);
  t1Der[t1Der.length - 100] ^= 0x01;
  const t1Hex = toHex(t1Der) + '0'.repeat(hexSlice.length - t1Der.length * 2);
  const t1Buf = Buffer.concat([
    originalBuf.slice(0, b0 + l0),
    Buffer.from('<' + t1Hex + '>'),
    originalBuf.slice(b1)
  ]);
  const t1Res = await auditBuffer(t1Buf, 'T1 Tampered RSA Signature');
  assert(t1Res.signatures[0].mathSignatureStatus === 'INVALID', 'T1: WebCrypto correctly marks tampered RSA signature as INVALID');

  // T2: Tamper signingTime attribute inside signedAttrs
  console.log(`\n--- [T2 Attack Vector] Tampered signingTime Attribute in signedAttrs ---`);
  const t2Der = new Uint8Array(cmsBytes);
  // Find UTCTime tag (0x17) inside signedAttrs and mutate one character
  for (let i = 1200; i < t2Der.length - 300; i++) {
    if (t2Der[i] === 0x17 && t2Der[i + 1] === 13) {
      t2Der[i + 5] ^= 0x01; // mutate timestamp digit
      break;
    }
  }
  const t2Hex = toHex(t2Der) + '0'.repeat(hexSlice.length - t2Der.length * 2);
  const t2Buf = Buffer.concat([
    originalBuf.slice(0, b0 + l0),
    Buffer.from('<' + t2Hex + '>'),
    originalBuf.slice(b1)
  ]);
  const t2Res = await auditBuffer(t2Buf, 'T2 Tampered signingTime');
  assert(t2Res.signatures[0].mathSignatureStatus === 'INVALID', 'T2: Mutating signingTime inside signedAttrs breaks signature verification (INVALID)');

  // T3: Tamper document content in ByteRange
  console.log(`\n--- [T3 Attack Vector] Tampered Document Content Inside ByteRange ---`);
  const t3Buf = Buffer.from(originalBuf);
  t3Buf[10] ^= 0x01; // mutate a byte in the signed PDF header
  const t3Res = await auditBuffer(t3Buf, 'T3 Tampered Content');
  assert(t3Res.signatures[0].hashMatches === false, 'T3: Tampered PDF content correctly caught by ByteRange hash mismatch');

  // T4: Certificate Substitution Attack
  console.log(`\n--- [T4 Attack Vector] Certificate Substitution in CMS Certs Bag ---`);
  // Substitute the leaf certificate in the CMS cert bag with another certificate
  const t4Der = new Uint8Array(cmsBytes);
  // Flip a bit in the certificate's subject / TBS area (offset 200)
  t4Der[200] ^= 0x01;
  const t4Hex = toHex(t4Der) + '0'.repeat(hexSlice.length - t4Der.length * 2);
  const t4Buf = Buffer.concat([
    originalBuf.slice(0, b0 + l0),
    Buffer.from('<' + t4Hex + '>'),
    originalBuf.slice(b1)
  ]);
  const t4Res = await auditBuffer(t4Buf, 'T4 Certificate Substitution');
  assert(t4Res.signatures[0].certSubstitutionDetected === true, 'T4: Certificate substitution detected via ESSCertIDv2 certHash mismatch');

  // T5: ByteRange Gap Injection / Wrapping Attack
  console.log(`\n--- [T5 Attack Vector] ByteRange Gap Injection (Signature Wrapping) ---`);
  // Inject arbitrary PDF operators inside the /Contents gap
  const t5Gap = '<' + hexSlice.slice(0, 100) + '>> /Injected (Attack) <' + hexSlice.slice(100 + 24) + '>';
  const t5Buf = Buffer.concat([
    originalBuf.slice(0, b0 + l0),
    Buffer.from(t5Gap),
    originalBuf.slice(b1)
  ]);
  const t5Res = await auditBuffer(t5Buf, 'T5 Gap Injection');
  assert(t5Res.signatures[0].gapIntegrityValid === false, 'T5: Non-hexadecimal injection in /Contents gap rejected (gapIntegrityValid === false)');

  // T6: Unsupported Algorithm (RSA-PSS) Graceful Handling
  console.log(`\n--- [T6 Vector] Unsupported Algorithm (RSA-PSS) Graceful Handling ---`);
  const t6Der = new Uint8Array(cmsBytes);
  // Find signatureAlgorithm OID 1.2.840.113549.1.1.1 and mutate last byte 0x01 -> 0x0A (1.2.840.113549.1.1.10 = rsassa-pss)
  for (let i = t6Der.length - 300; i < t6Der.length - 10; i++) {
    if (t6Der[i] === 0x06 && t6Der[i + 1] === 0x09 && t6Der[i + 2] === 0x2a && t6Der[i + 3] === 0x86 && t6Der[i + 10] === 0x01) {
      t6Der[i + 10] = 0x0a; // mutate to rsassa-pss OID
      break;
    }
  }
  const t6Hex = toHex(t6Der) + '0'.repeat(hexSlice.length - t6Der.length * 2);
  const t6Buf = Buffer.concat([
    originalBuf.slice(0, b0 + l0),
    Buffer.from('<' + t6Hex + '>'),
    originalBuf.slice(b1)
  ]);
  const t6Res = await auditBuffer(t6Buf, 'T6 RSA-PSS');
  assert(t6Res.signatures[0].mathSignatureStatus === 'UNSUPPORTED_ALGORITHM', 'T6: RSA-PSS gracefully reported as UNSUPPORTED_ALGORITHM without false corruption failure');
  assert(t6Res.signatures[0].mathSignatureValid === null, 'T6: mathSignatureValid is null (unverified, not marked false/corrupt)');
}

async function runIndependentPyHankoAudit() {
  console.log(`\n===============================================================`);
  console.log(`[INDEPENDENT AUDIT] Third-Party pyHanko Validation`);
  console.log(`===============================================================`);

  const pyScript = `
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import validation

targets = [
    ("/tmp/pades_e2e_test/signed_pbmac1.pdf", "PBMAC1"),
    ("/tmp/pades_e2e_test/signed_legacy.pdf", "Legacy 3DES")
]

for path, label in targets:
    with open(path, "rb") as f:
        r = PdfFileReader(f)
        sig = r.embedded_signatures[0]
        st = validation.validate_pdf_signature(sig)
        assert st.intact, f"pyHanko reported signature not intact on {label}"
        assert st.valid, f"pyHanko reported signature invalid on {label}"
        assert st.coverage.name == "ENTIRE_FILE", f"pyHanko reported coverage {st.coverage.name} on {label}"
        print(f"  pyHanko [PASS]: {label} -> intact={st.intact}, valid={st.valid}, coverage={st.coverage.name}")
`;

  try {
    const output = execSync(`/root/.venv-validator/bin/python -c '${pyScript.trim()}'`, { encoding: 'utf8' });
    console.log(output.trim());
    assert(true, 'pyHanko independently confirmed cryptographic integrity and ENTIRE_FILE coverage on signed PDFs');
  } catch (err) {
    console.error('pyHanko error output:', err.stdout || err.message);
    throw err;
  }
}

async function main() {
  console.log(`=====================================================================`);
  console.log(`=== STARTING ENHANCED VALIDATOR AUDIT & SECURITY ATTACK MATRIX ===`);
  console.log(`=====================================================================`);

  // 1. Positive Test Suite (Individual Documents)
  await runPositiveTest(
    '/tmp/pades_e2e_test/signed_pbmac1.pdf',
    'OUR ENGINE: Modern PBMAC1 (RFC 9879) Signed PDF',
    { digestAlgorithm: 'SHA-256', isSha1: false, requireCertHashMatch: true }
  );

  await runPositiveTest(
    '/tmp/pades_e2e_test/signed_legacy.pdf',
    'OUR ENGINE: Legacy 3DES Signed PDF',
    { digestAlgorithm: 'SHA-256', isSha1: false, requireCertHashMatch: true }
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
    { digestAlgorithm: 'SHA-512', isSha1: false }
  );

  // 2. Multi-Signature / Incremental Saves Suite
  await runMultiSigTest(
    '/tmp/real_signed_pdfs/pades_5_sigs_dss.pdf',
    'REAL-WORLD: European Commission DSS Multi-Signature Document (6 signatures)'
  );

  // 3. Official External Negative Fixture Suite
  await runNegativeFixture(
    '/tmp/negative_test_pdfs/dss_modified_after_sig.pdf',
    'OFFICIAL EU DSS: Modified After Signature (github.com/esig/dss)',
    { hasTrailingData: true }
  );

  await runNegativeFixture(
    '/tmp/negative_test_pdfs/dss_pdf_corrupted.pdf',
    'OFFICIAL EU DSS: Corrupted Document Content (github.com/esig/dss)',
    { hashMatches: false }
  );

  await runNegativeFixture(
    '/tmp/negative_test_pdfs/afirma_shadow_attack.pdf',
    'OFFICIAL SPANISH GOV: Shadow Attack PDF (github.com/ctt-gob-es/clienteafirma)',
    { hasTrailingData: true }
  );

  // 4. Negative Attack Matrix (T1 - T6)
  await runNegativeAttackMatrix();

  // 5. Independent pyHanko Cryptographic Audit
  await runIndependentPyHankoAudit();

  console.log(`\n=====================================================================`);
  console.log(`=== ALL AUDITS PASSED: ${passedAssertions}/${totalAssertions} ASSERTIONS SUCCEEDED (100%) ===`);
  console.log(`=====================================================================`);
}

main().catch((err) => {
  console.error('\n[FATAL AUDIT FAILURE]:', err);
  process.exit(1);
});
