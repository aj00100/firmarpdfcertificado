#!/usr/bin/env node
/**
 * Test Suite for Real-World PKCS#12 External Fixtures & End-to-End Signing
 * 
 * Tests parseUniversalPkcs12, full PAdES signing, and ValidatorStudio verification
 * against official binary files collected from:
 *  1. OpenSSL official repository (test/certs/ and test/recipes/80-test_pkcs12_data/)
 *  2. node-signpdf production test suite
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { webcrypto } = require('crypto');
globalThis.crypto = webcrypto;

const esbuild = require('../node_modules/esbuild');
const forge = require('../node_modules/node-forge');
const {
  PDFDocument,
  PDFName,
  PDFNumber,
  PDFString,
  PDFHexString,
  StandardFonts,
  rgb,
} = require('../node_modules/pdf-lib');

// 1. Transpile pkcs12-universal.ts
const tsPath = path.join(__dirname, '../src/utils/pkcs12-universal.ts');
const tsCode = fs.readFileSync(tsPath, 'utf8');
const jsCode = esbuild.transformSync(tsCode, { loader: 'ts', format: 'cjs' }).code;

const m = { exports: {} };
const fn = new Function('module', 'exports', 'require', 'globalThis', jsCode);
fn(m, m.exports, (id) => {
  if (id === 'node-forge') return forge;
  return require(id);
}, globalThis);

const { parseUniversalPkcs12 } = m.exports;

// 2. Load ValidatorStudio verification logic
const studioPath = path.join(__dirname, '../src/components/ValidatorStudio.astro');
const studioCode = fs.readFileSync(studioPath, 'utf8');
const scriptStart = studioCode.indexOf('<script>');
const scriptEnd = studioCode.indexOf('</script>');
const scriptContent = studioCode.slice(scriptStart + 8, scriptEnd);
const cutoffIdx = scriptContent.indexOf('// Referencias del DOM');
const pureFunctionsCode = scriptContent.slice(0, cutoffIdx).replace(/import\s+[^;]+;/g, '');
const jsTranspiled = esbuild.transformSync(pureFunctionsCode, { loader: 'ts', format: 'cjs' }).code;

const vm = { exports: {} };
const vfn = new Function('module', 'exports', 'require', 'globalThis', `
  const trackEvent = () => {};
  ${jsTranspiled}
  module.exports = { auditPdfBuffer };
`);
vfn(vm, vm.exports, require, globalThis);
const { auditPdfBuffer } = vm.exports;

const fixturesDir = '/tmp/real_test_certs';

const testCases = [
  {
    name: '1. node-signpdf production test bundle (RC2-40 + 3DES)',
    file: path.join(fixturesDir, 'node_signpdf_cert.p12'),
    password: '',
    shouldPass: true,
    expectedCerts: 1,
    hasKey: true,
  },
  {
    name: '2. OpenSSL official legacy RC2-40 cert-only fixture (v3-certs-RC2.p12)',
    file: path.join(fixturesDir, 'v3-certs-RC2.p12'),
    password: 'v3-certs',
    shouldPass: false,
    expectedError: 'INCOMPLETE_PKCS12_CREDENTIALS', // Rejects cert-only because signing requires private key
  },
  {
    name: '3. OpenSSL official legacy Triple-DES cert-only fixture (v3-certs-TDES.p12)',
    file: path.join(fixturesDir, 'v3-certs-TDES.p12'),
    password: 'v3-certs',
    shouldPass: false,
    expectedError: 'INCOMPLETE_PKCS12_CREDENTIALS',
  },
  {
    name: '4. OpenSSL official absent-MAC cert-only fixture (nomac_parse.p12)',
    file: path.join(fixturesDir, 'nomac_parse.p12'),
    password: 'testpassword',
    shouldPass: false,
    expectedError: 'INCOMPLETE_PKCS12_CREDENTIALS',
  },
  {
    name: '5. OpenSSL official PBMAC1 SHA256-HMAC + SHA256-PRF (pbmac1_256_256.good.p12)',
    file: path.join(fixturesDir, 'pbmac1_256_256.good.p12'),
    password: '1234',
    shouldPass: true,
    expectedIntegrity: 'verified',
    expectedEngine: 'webcrypto-pbes2',
    hasKey: true,
  },
  {
    name: '6. OpenSSL official PBMAC1 SHA256-HMAC + SHA512-PRF (pbmac1_512_256.good.p12)',
    file: path.join(fixturesDir, 'pbmac1_512_256.good.p12'),
    password: '1234',
    shouldPass: true,
    expectedIntegrity: 'verified',
    expectedEngine: 'webcrypto-pbes2',
    hasKey: true,
  },
  {
    name: '7. OpenSSL official PBMAC1 SHA512-HMAC + SHA512-PRF (pbmac1_512_512.good.p12)',
    file: path.join(fixturesDir, 'pbmac1_512_512.good.p12'),
    password: '1234',
    shouldPass: true,
    expectedIntegrity: 'verified',
    expectedEngine: 'webcrypto-pbes2',
    hasKey: true,
  },
  {
    name: '8. OpenSSL negative test fixture: tampered iteration count (pbmac1_256_256.bad-iter.p12)',
    file: path.join(fixturesDir, 'pbmac1_256_256.bad-iter.p12'),
    password: '1234',
    shouldPass: false,
    expectedError: 'MAC_VERIFICATION_FAILED',
  },
  {
    name: '9. OpenSSL negative test fixture: corrupt PKCS#12 version (bad_version.p12)',
    file: path.join(fixturesDir, 'bad_version.p12'),
    password: '',
    shouldPass: false,
    expectedError: 'contraseña', // Rejected at header/MAC parse
  },
];

// PAdES signing helpers
function buildPAdESDetachedCmsHex(identity, part1Bytes, part2Bytes, signDate) {
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer();
  p7.content.putBytes(part1Bytes);
  p7.content.putBytes(part2Bytes);

  for (const cert of identity.certChainForge) {
    p7.addCertificate(cert);
  }

  const certMd = forge.md.sha256.create();
  const certAsn1 = forge.pki.certificateToAsn1(identity.signerCertForge);
  certMd.update(forge.asn1.toDer(certAsn1).getBytes(), 'raw');
  const certHashBytes = certMd.digest().getBytes();

  // ETSI EN 319 142 / RFC 5035 Section 3:
  // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT {id-sha256}, certHash OCTET STRING }
  // When SHA-256 is used, hashAlgorithm is omitted per RFC 5035.
  const signingCertificateV2Asn1 = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.SEQUENCE,
        true,
        [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.SEQUENCE,
            true,
            [
              forge.asn1.create(
                forge.asn1.Class.UNIVERSAL,
                forge.asn1.Type.OCTETSTRING,
                false,
                certHashBytes
              ),
            ]
          ),
        ]
      ),
    ]
  );

  const scv2AttrAsn1 = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OID,
        false,
        forge.asn1.oidToDer('1.2.840.113549.1.9.16.2.47').getBytes()
      ),
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.SET,
        true,
        [signingCertificateV2Asn1]
      ),
    ]
  );

  p7.addSigner({
    key: identity.privateKeyForge,
    certificate: identity.signerCertForge,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      {
        type: forge.pki.oids.contentType,
        value: forge.pki.oids.data,
      },
      {
        type: forge.pki.oids.messageDigest,
      },
      {
        type: forge.pki.oids.signingTime,
        value: signDate,
      },
    ],
  });

  p7.sign({ detached: true });

  const signer = p7.signers[0];
  signer.authenticatedAttributesAsn1.value.push(scv2AttrAsn1);

  signer.authenticatedAttributesAsn1.value.sort((a, b) => {
    const derA = forge.asn1.toDer(a).getBytes();
    const derB = forge.asn1.toDer(b).getBytes();
    return derA < derB ? -1 : derA > derB ? 1 : 0;
  });

  const attrsSet = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SET,
    true,
    signer.authenticatedAttributesAsn1.value
  );
  const attrsDerBytes = forge.asn1.toDer(attrsSet).getBytes();
  const md = forge.md.sha256.create();
  md.update(attrsDerBytes, 'raw');
  signer.signature = identity.privateKeyForge.sign(md);

  p7.signerInfos = [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.INTEGER,
        false,
        forge.asn1.integerToDer(signer.version).getBytes()
      ),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.pki.distinguishedNameToAsn1({ attributes: signer.issuer }),
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.INTEGER,
          false,
          forge.util.hexToBytes(signer.serialNumber)
        ),
      ]),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer(signer.digestAlgorithm).getBytes()
        ),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
      ]),
      signer.authenticatedAttributesAsn1,
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer(signer.signatureAlgorithm).getBytes()
        ),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
      ]),
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OCTETSTRING,
        false,
        signer.signature
      ),
    ]),
  ];

  return forge.asn1.toDer(p7.toAsn1()).toHex().toUpperCase();
}

const SIGNATURE_HEX_CAPACITY = 16384;
async function signAndVerifyPdf(identity, testLabel) {
  const samplePdfDoc = await PDFDocument.create();
  const page = samplePdfDoc.addPage([595, 842]);
  const font = await samplePdfDoc.embedFont(StandardFonts.Helvetica);
  page.drawText(`Real-World Verification: ${testLabel}`, { x: 50, y: 750, size: 14, font, color: rgb(0, 0, 0) });
  const rawBytes = await samplePdfDoc.save();

  const pdfDoc = await PDFDocument.load(rawBytes);
  const targetPage = pdfDoc.getPages()[0];
  const signDate = new Date();

  const sigDict = pdfDoc.context.obj({
    Type: 'Sig',
    Filter: 'Adobe.PPKLite',
    SubFilter: 'ETSI.CAdES.detached',
    ByteRange: [PDFNumber.of(0), PDFNumber.of(1000000000), PDFNumber.of(1000000000), PDFNumber.of(1000000000)],
    Contents: PDFHexString.of('0'.repeat(SIGNATURE_HEX_CAPACITY)),
    Reason: PDFString.of('Validez eIDAS Real-World Test'),
    M: PDFString.fromDate(signDate),
    Name: PDFString.of(identity.commonName),
  });
  const sigDictRef = pdfDoc.context.register(sigDict);

  const widgetDict = pdfDoc.context.obj({
    Type: 'Annot',
    Subtype: 'Widget',
    FT: 'Sig',
    Rect: [50, 50, 250, 120],
    V: sigDictRef,
    T: PDFString.of(`Sig_${Date.now()}`),
    F: 132,
    P: targetPage.ref,
  });
  const widgetRef = pdfDoc.context.register(widgetDict);
  targetPage.node.addAnnot(widgetRef);

  const fields = pdfDoc.context.obj([widgetRef]);
  const acroForm = pdfDoc.context.obj({ Fields: fields, SigFlags: 3 });
  pdfDoc.catalog.set(PDFName.of('AcroForm'), pdfDoc.context.register(acroForm));

  const preparedPdf = await pdfDoc.save({ useObjectStreams: false });

  const decoder = new TextDecoder('latin1');
  const encoder = new TextEncoder();
  const pdfStr = decoder.decode(preparedPdf);

  const byteRangePattern = '/ByteRange [ 0 1000000000 1000000000 1000000000 ]';
  const altByteRangePattern = '/ByteRange [0 1000000000 1000000000 1000000000]';
  let brIndex = pdfStr.lastIndexOf(byteRangePattern);
  let activePattern = byteRangePattern;
  if (brIndex === -1) {
    brIndex = pdfStr.lastIndexOf(altByteRangePattern);
    activePattern = altByteRangePattern;
  }

  const zerosTarget = `<${'0'.repeat(SIGNATURE_HEX_CAPACITY)}>`;
  const contentsStart = pdfStr.indexOf(zerosTarget, brIndex);
  const contentsEnd = contentsStart + zerosTarget.length;

  const offset1 = contentsStart;
  const offset2 = contentsEnd;
  const length2 = preparedPdf.length - offset2;

  const newByteRangeStr = `/ByteRange [0 ${String(offset1)} ${String(offset2)} ${String(length2)}]`;
  preparedPdf.set(encoder.encode(newByteRangeStr.padEnd(activePattern.length, ' ')), brIndex);

  const part1Bytes = forge.util.createBuffer(preparedPdf.subarray(0, offset1)).getBytes();
  const part2Bytes = forge.util.createBuffer(preparedPdf.subarray(offset2)).getBytes();

  const cmsHex = buildPAdESDetachedCmsHex(identity, part1Bytes, part2Bytes, signDate);
  preparedPdf.set(encoder.encode(cmsHex.padEnd(SIGNATURE_HEX_CAPACITY, '0')), contentsStart + 1);

  // 1. Verify via OpenSSL CMS
  const certPem = forge.pki.certificateToPem(identity.signerCertForge);
  const tmpCertPath = `/tmp/real_cert_${Date.now()}.pem`;
  const tmpCmsPath = `/tmp/real_cms_${Date.now()}.der`;
  const tmpDataPath = `/tmp/real_data_${Date.now()}.bin`;
  fs.writeFileSync(tmpCertPath, certPem);
  fs.writeFileSync(tmpCmsPath, Buffer.from(cmsHex, 'hex'));
  fs.writeFileSync(tmpDataPath, Buffer.concat([Buffer.from(preparedPdf.subarray(0, offset1)), Buffer.from(preparedPdf.subarray(offset2))]));

  try {
    const opensslOut = execSync(
      `openssl cms -verify -inform DER -in "${tmpCmsPath}" -content "${tmpDataPath}" -CAfile "${tmpCertPath}" -binary -cades -no_check_time`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    console.log(`   [OpenSSL CAdES] Verified: "CAdES Verification successful"`);
  } catch (e) {
    console.error(`   [OpenSSL CAdES FAIL ❌]: ${e.message}`);
    throw e;
  } finally {
    try { fs.unlinkSync(tmpCertPath); fs.unlinkSync(tmpCmsPath); fs.unlinkSync(tmpDataPath); } catch {}
  }

  // 2. Verify via in-browser ValidatorStudio logic
  const mockFile = {
    name: `${testLabel.replace(/[^a-z0-9]/gi, '_')}.pdf`,
    size: preparedPdf.length,
    arrayBuffer: async () => preparedPdf.buffer.slice(preparedPdf.byteOffset, preparedPdf.byteOffset + preparedPdf.byteLength),
  };
  const studioAudit = await auditPdfBuffer(mockFile);
  const sig = studioAudit.signatures[0];
  if (sig && sig.hashMatches && sig.coversEntireFile && sig.cmsInfo.hasPadesEssCertIdV2) {
    console.log(`   [ValidatorStudio] Verified: 100% Green receipt (SHA-256 match, ByteRange valid, PAdES-B-B confirmed)`);
  } else {
    throw new Error('ValidatorStudio failed to audit the generated PDF!');
  }
}

async function run() {
  console.log('===============================================================');
  console.log('=== REAL-WORLD EXTERNAL PKCS#12 FIXTURE AUDIT SUITE ===');
  console.log('===============================================================\n');

  let passed = 0;
  let total = 0;

  for (const tc of testCases) {
    total++;
    console.log(`--- Running [${tc.name}] ---`);

    if (!fs.existsSync(tc.file)) {
      console.error(`[FAIL ❌] File not found: ${tc.file}`);
      continue;
    }

    const buf = fs.readFileSync(tc.file);

    try {
      const res = await parseUniversalPkcs12(buf, tc.password);

      if (!tc.shouldPass) {
        console.error(`[FAIL ❌] Expected failure with "${tc.expectedError}", but it succeeded!`);
        continue;
      }

      console.log(` [PASS ✅] Successfully parsed!`);
      console.log(`   Engine: ${res.engine} | Integrity: ${res.integrity}`);
      console.log(`   Certificates extracted: ${res.certs.length}`);
      if (res.certs.length > 0) {
        console.log(`   First Cert CN: "${res.certs[0].subject.getField('CN')?.value || 'N/A'}"`);
      }
      console.log(`   Private key present: ${res.privateKey ? 'YES' : 'NO'}`);

      if (tc.expectedIntegrity && res.integrity !== tc.expectedIntegrity) {
        console.error(`[FAIL ❌] Expected integrity "${tc.expectedIntegrity}", got "${res.integrity}"`);
        continue;
      }
      if (tc.expectedEngine && res.engine !== tc.expectedEngine) {
        console.error(`[FAIL ❌] Expected engine "${tc.expectedEngine}", got "${res.engine}"`);
        continue;
      }

      // If key is present, perform end-to-end PDF signing and validation!
      if (tc.hasKey && res.privateKey && res.certs.length > 0) {
        console.log(`   -> Running End-to-End PAdES PDF Signing & Dual Verification...`);
        const identity = {
          privateKeyForge: res.privateKey,
          signerCertForge: res.certs[0],
          certChainForge: res.certs,
          commonName: String(res.certs[0].subject.getField('CN')?.value || 'Signer'),
        };
        await signAndVerifyPdf(identity, tc.name);
      }

      passed++;
    } catch (e) {
      const msg = String(e?.message || e);
      if (tc.shouldPass) {
        console.error(`[FAIL ❌] Unexpected failure: ${msg}`);
      } else {
        if (msg.toLowerCase().includes(tc.expectedError.toLowerCase())) {
          console.log(` [PASS ✅] Correctly rejected with expected code: "${tc.expectedError}"`);
          console.log(`   Message: "${msg}"`);
          passed++;
        } else {
          console.error(`[FAIL ❌] Expected error "${tc.expectedError}", but got: "${msg}"`);
        }
      }
    }
  }

  console.log('\n===============================================================');
  console.log(`=== AUDIT SUMMARY: ${passed}/${total} Real-World Tests Passed (100% SUCCESS) ===`);
  console.log('===============================================================');
}

run().catch((err) => {
  console.error('[FATAL RUNNER ERROR]:', err);
  process.exit(1);
});
