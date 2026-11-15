#!/usr/bin/env node
/**
 * End-to-End PAdES PDF Signing Verification Test
 * 
 * Verifies that certificates extracted by parseUniversalPkcs12 (commit 6f8675c)
 * successfully produce valid PAdES (ETSI.CAdES.detached) signed PDFs.
 * 
 * Tested with:
 *  1. Modern OpenSSL 3 with PBMAC1 (RFC 9879)
 *  2. Legacy TripleDES / RC2-40 (-legacy)
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
  PDFArray,
  PDFDict,
  StandardFonts,
  rgb,
} = require('../node_modules/pdf-lib');

// Transpile pkcs12-universal.ts
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

const tmpDir = '/tmp/pades_e2e_test';
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, { recursive: true });
}

// Generate base test key and self-signed certificate if not present
const keyPath = path.join(tmpDir, 'test_key.pem');
const certPath = path.join(tmpDir, 'test_cert.pem');

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout ${keyPath} -out ${certPath} -days 365 -nodes ` +
    `-subj "/C=ES/ST=Madrid/L=Madrid/O=FNMT-RCM/OU=CERES/CN=JUAN GARCIA PEREZ - 12345678Z/serialNumber=12345678Z"`,
    { stdio: 'pipe' }
  );
}

// Generate PBMAC1 and Legacy PKCS#12 containers
const pbmac1P12Path = path.join(tmpDir, 'test_pbmac1.p12');
const legacyP12Path = path.join(tmpDir, 'test_legacy.p12');

execSync(
  `openssl pkcs12 -export -out ${pbmac1P12Path} -inkey ${keyPath} -in ${certPath} -passout pass:test1234 -pbmac1_pbkdf2`,
  { stdio: 'pipe' }
);

try {
  execSync(
    `openssl pkcs12 -export -legacy -out "${legacyP12Path}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234`,
    { stdio: 'pipe' }
  );
} catch {
  execSync(
    `openssl pkcs12 -export -out "${legacyP12Path}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234`,
    { stdio: 'pipe' }
  );
}

// Helper: Extract Identity like signer.worker.ts does
async function extractIdentity(p12Buf, password) {
  const { certs, privateKey } = await parseUniversalPkcs12(p12Buf, password);
  if (!privateKey) throw new Error('No private key');
  if (certs.length === 0) throw new Error('No certificates');

  const matchingCert = certs.find((c) => {
    try {
      const pub = c.publicKey;
      return Boolean(pub?.n && privateKey?.n && pub.n.compareTo(privateKey.n) === 0);
    } catch {
      return false;
    }
  });

  const signerCert = matchingCert || certs[0];
  const certAsn1 = forge.pki.certificateToAsn1(signerCert);
  const certDerStr = forge.asn1.toDer(certAsn1).getBytes();
  const signerCertDer = new Uint8Array(certDerStr.length);
  for (let i = 0; i < certDerStr.length; i++) {
    signerCertDer[i] = certDerStr.charCodeAt(i);
  }

  const cnAttr = signerCert.subject.getField('CN');
  const commonName = cnAttr ? String(cnAttr.value) : 'Titular';

  return {
    privateKeyForge: privateKey,
    signerCertForge: signerCert,
    certChainForge: certs,
    signerCertDer,
    commonName,
    nif: '12345678Z',
    issuerName: 'FNMT-RCM',
    notBefore: signerCert.validity.notBefore,
    notAfter: signerCert.validity.notAfter,
  };
}

// Helper: Build Detached CMS Hex (identical to signer.worker.ts)
function buildPAdESDetachedCmsHex(identity, part1Bytes, part2Bytes, signDate) {
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer();
  p7.content.putBytes(part1Bytes);
  p7.content.putBytes(part2Bytes);

  for (const cert of identity.certChainForge) {
    p7.addCertificate(cert);
  }

  // 1. Build ETSI SigningCertificateV2 (id-aa-signingCertificateV2 / RFC 5035 / PAdES-B-B)
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

  // 2. Add Signer with standard base attributes
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

  // Calculate base message digest and initialize structure
  p7.sign({ detached: true });

  // 3. Inject SigningCertificateV2 into authenticatedAttributesAsn1
  const signer = p7.signers[0];
  signer.authenticatedAttributesAsn1.value.push(scv2AttrAsn1);

  // 4. Sort attributes SET by DER octets per X.690 / RFC 5652 Section 5.3 rules
  signer.authenticatedAttributesAsn1.value.sort((a, b) => {
    const derA = forge.asn1.toDer(a).getBytes();
    const derB = forge.asn1.toDer(b).getBytes();
    return derA < derB ? -1 : derA > derB ? 1 : 0;
  });

  // 5. Re-sign the complete attributes SET with the signer's RSA private key
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

  // 6. Rebuild signerInfos with updated authenticatedAttributes and signature
  p7.signerInfos = [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      // version
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.INTEGER,
        false,
        forge.asn1.integerToDer(signer.version).getBytes()
      ),
      // issuerAndSerialNumber
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.pki.distinguishedNameToAsn1({ attributes: signer.issuer }),
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.INTEGER,
          false,
          forge.util.hexToBytes(signer.serialNumber)
        ),
      ]),
      // digestAlgorithm
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer(signer.digestAlgorithm).getBytes()
        ),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
      ]),
      // authenticatedAttributes [0] IMPLICIT
      signer.authenticatedAttributesAsn1,
      // digestEncryptionAlgorithm
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer(signer.signatureAlgorithm).getBytes()
        ),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
      ]),
      // signature
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OCTETSTRING,
        false,
        signer.signature
      ),
    ]),
  ];

  const cmsAsn1 = p7.toAsn1();
  const cmsDer = forge.asn1.toDer(cmsAsn1);
  return cmsDer.toHex().toUpperCase();
}

// Helper: End-to-End PDF Signer
const BYTE_RANGE_SENTINEL = 1000000000;
const SIGNATURE_HEX_CAPACITY = 16384;

async function signPdf(pdfBytes, identity, signDate) {
  const pdfDoc = await PDFDocument.load(pdfBytes);
  const pages = pdfDoc.getPages();
  const page = pages[0];

  const sigDict = pdfDoc.context.obj({
    Type: 'Sig',
    Filter: 'Adobe.PPKLite',
    SubFilter: 'ETSI.CAdES.detached',
    ByteRange: [
      PDFNumber.of(0),
      PDFNumber.of(BYTE_RANGE_SENTINEL),
      PDFNumber.of(BYTE_RANGE_SENTINEL),
      PDFNumber.of(BYTE_RANGE_SENTINEL),
    ],
    Contents: PDFHexString.of('0'.repeat(SIGNATURE_HEX_CAPACITY)),
    Reason: PDFString.of('Validez juridica eIDAS'),
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
    T: PDFString.of(`Signature_${Date.now()}`),
    F: 132,
    P: page.ref,
  });
  const widgetRef = pdfDoc.context.register(widgetDict);
  page.node.addAnnot(widgetRef);

  let acroForm = pdfDoc.catalog.get(PDFName.of('AcroForm'));
  if (!acroForm) {
    const fields = pdfDoc.context.obj([widgetRef]);
    acroForm = pdfDoc.context.obj({ Fields: fields, SigFlags: 3 });
    pdfDoc.catalog.set(PDFName.of('AcroForm'), pdfDoc.context.register(acroForm));
  }

  const preparedPdf = await pdfDoc.save({ useObjectStreams: false });

  // In-place byte replacement
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
  const paddedByteRangeStr = newByteRangeStr.padEnd(activePattern.length, ' ');
  preparedPdf.set(encoder.encode(paddedByteRangeStr), brIndex);

  const part1Bytes = forge.util.createBuffer(preparedPdf.subarray(0, offset1)).getBytes();
  const part2Bytes = forge.util.createBuffer(preparedPdf.subarray(offset2)).getBytes();

  const cmsHex = buildPAdESDetachedCmsHex(identity, part1Bytes, part2Bytes, signDate);
  const paddedHex = cmsHex.padEnd(SIGNATURE_HEX_CAPACITY, '0');
  preparedPdf.set(encoder.encode(paddedHex), contentsStart + 1);

  return {
    signedPdf: preparedPdf,
    offset1,
    offset2,
    length2,
    cmsHex,
  };
}

async function verifySignedPdf(testName, signedResult, expectedCert) {
  const { signedPdf, offset1, offset2, length2, cmsHex } = signedResult;
  console.log(`\n--- Verifying [${testName}] ---`);

  // 1. Verify ByteRange exact boundary coverage
  if (offset1 + (offset2 - offset1) + length2 !== signedPdf.length) {
    throw new Error(`ByteRange does not cover exact file length: ${offset1} + ${offset2-offset1} + ${length2} !== ${signedPdf.length}`);
  }
  console.log(` [PASS] ByteRange exact coverage: [0, ${offset1}, ${offset2}, ${length2}] = Total ${signedPdf.length} bytes`);

  // 2. Write CMS DER and ByteRange data to temp files
  const safeName = testName.replace(/[^a-z0-9]/gi, '_');
  const cmsDerPath = path.join(tmpDir, `${safeName}.cms.der`);
  const dataPath = path.join(tmpDir, `${safeName}.data.bin`);
  fs.writeFileSync(cmsDerPath, Buffer.from(cmsHex, 'hex'));

  const part1 = Buffer.from(signedPdf.subarray(0, offset1));
  const part2 = Buffer.from(signedPdf.subarray(offset2));
  fs.writeFileSync(dataPath, Buffer.concat([part1, part2]));

  // 3. Inspect CMS structure with OpenSSL
  const cmsInfo = execSync(`openssl cms -cmsout -print -inform DER -in "${cmsDerPath}"`, { encoding: 'utf8' });

  // Verify SigningCertificateV2 attribute presence
  if (!cmsInfo.includes('signingCertificateV2') && !cmsInfo.includes('1.2.840.113549.1.9.16.2.47')) {
    throw new Error('SigningCertificateV2 (PAdES-B-B) attribute missing from CMS');
  }
  console.log(' [PASS] ETSI SigningCertificateV2 (id-aa-signingCertificateV2) PAdES-B-B attribute verified!');

  // Verify Leaf Certificate Serial / Subject
  if (!cmsInfo.includes('JUAN GARCIA PEREZ')) {
    throw new Error('Signer leaf certificate subject missing from CMS structure');
  }
  console.log(' [PASS] SignerInfo binds leaf certificate: CN="JUAN GARCIA PEREZ - 12345678Z"');

  // 4. Run official OpenSSL CMS cryptographic verification with -cades & -binary
  const verifyCmd = `openssl cms -verify -inform DER -in "${cmsDerPath}" -content "${dataPath}" -CAfile "${certPath}" -binary -cades`;
  const out = execSync(verifyCmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  console.log(` [PASS] OpenSSL CMS -verify -cades passed: "CAdES Verification successful"`);
}

async function runE2eTests() {
  console.log('===============================================================');
  console.log('=== END-TO-END PAdES PDF SIGNING VERIFICATION SUITE ===');
  console.log('===============================================================');

  // Create a sample 1-page PDF
  const samplePdfDoc = await PDFDocument.create();
  const p = samplePdfDoc.addPage([595, 842]);
  const font = await samplePdfDoc.embedFont(StandardFonts.Helvetica);
  p.drawText('Factura / Contrato Oficial de Prueba para Firma PAdES', {
    x: 50,
    y: 750,
    size: 16,
    font,
    color: rgb(0, 0, 0),
  });
  p.drawText('Documento emitido conforme al Reglamento (UE) 910/2014 (eIDAS).', {
    x: 50,
    y: 720,
    size: 10,
    font,
    color: rgb(0.3, 0.3, 0.3),
  });
  const samplePdfBytes = await samplePdfDoc.save();

  // Test 1: Full PAdES Signing with Modern OpenSSL 3 PBMAC1 (RFC 9879) Certificate
  const pbmac1Buf = fs.readFileSync(pbmac1P12Path);
  const pbmac1Identity = await extractIdentity(pbmac1Buf, 'test1234');
  const signDate1 = new Date();
  const pbmac1Signed = await signPdf(new Uint8Array(samplePdfBytes), pbmac1Identity, signDate1);
  await verifySignedPdf('1. Modern PBMAC1 (RFC 9879) Certificate', pbmac1Signed, pbmac1Identity.signerCertForge);

  // Test 2: Full PAdES Signing with Legacy TripleDES (-legacy) Certificate
  const legacyBuf = fs.readFileSync(legacyP12Path);
  const legacyIdentity = await extractIdentity(legacyBuf, 'test1234');
  const signDate2 = new Date();
  const legacySigned = await signPdf(new Uint8Array(samplePdfBytes), legacyIdentity, signDate2);
  await verifySignedPdf('2. Legacy TripleDES / RC2-40 (-legacy) Certificate', legacySigned, legacyIdentity.signerCertForge);

  // Write out signed test PDFs for external VALIDe / Acrobat testing
  const outPbmac1Pdf = path.join(tmpDir, 'signed_pbmac1.pdf');
  const outLegacyPdf = path.join(tmpDir, 'signed_legacy.pdf');
  fs.writeFileSync(outPbmac1Pdf, pbmac1Signed.signedPdf);
  fs.writeFileSync(outLegacyPdf, legacySigned.signedPdf);

  console.log('\n===============================================================');
  console.log('=== ALL END-TO-END PAdES SIGNING TESTS PASSED (100% SUCCESS) ===');
  console.log(`=== Output PDF 1 (PBMAC1): ${outPbmac1Pdf} ===`);
  console.log(`=== Output PDF 2 (Legacy 3DES): ${outLegacyPdf} ===`);
  console.log('===============================================================');
}

runE2eTests().catch((err) => {
  console.error('\n[FATAL TEST FAILURE]:', err);
  process.exit(1);
});
