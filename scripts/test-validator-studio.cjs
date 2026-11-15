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
const forge = require('../node_modules/node-forge');

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
    assert(sig.certSubstitutionDetected === false, `Signature #${sig.index} does not falsely trigger cert substitution`);
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
  if (!fs.existsSync('/tmp/tamper_tests')) fs.mkdirSync('/tmp/tamper_tests', { recursive: true });
  fs.writeFileSync('/tmp/tamper_tests/tamper_sig_pbmac1.pdf', t1Buf);

  const t1Res = await auditBuffer(t1Buf, 'T1 Tampered RSA Signature');
  assert(t1Res.signatures[0].mathSignatureStatus === 'INVALID', 'T1: WebCrypto correctly marks tampered RSA signature as INVALID');

  // T2: Tamper signedAttrs (Authenticated Attributes) Attack Vector
  console.log(`\n--- [T2 Attack Vector] Tampered Attribute in signedAttrs ---`);
  const t2Der = new Uint8Array(cmsBytes);
  // Find taggedAttrs [0xa0] inside SignerInfo and mutate an attribute byte inside it
  const cmsAsn1 = parseAsn1(t2Der);
  let mutated = false;
  function mutateSignedAttrs(node) {
    if (node.tag === 0xa0 && node.children && node.children.length >= 2) {
      t2Der[node.valueStart + 5] ^= 0x01;
      mutated = true;
      return;
    }
    if (node.children) {
      for (const ch of node.children) {
        if (!mutated) mutateSignedAttrs(ch);
      }
    }
  }
  mutateSignedAttrs(cmsAsn1);
  const t2Hex = toHex(t2Der) + '0'.repeat(hexSlice.length - t2Der.length * 2);
  const t2Buf = Buffer.concat([
    originalBuf.slice(0, b0 + l0),
    Buffer.from('<' + t2Hex + '>'),
    originalBuf.slice(b1)
  ]);
  if (!fs.existsSync('/tmp/tamper_tests')) fs.mkdirSync('/tmp/tamper_tests', { recursive: true });
  fs.writeFileSync('/tmp/tamper_tests/tamper_time_pbmac1.pdf', t2Buf);

  const t2Res = await auditBuffer(t2Buf, 'T2 Tampered signedAttrs');
  assert(t2Res.signatures[0].mathSignatureStatus === 'INVALID', 'T2: Mutating attribute inside signedAttrs breaks signature verification (INVALID)');

  // T3: Tamper document content in ByteRange
  console.log(`\n--- [T3 Attack Vector] Tampered Document Content Inside ByteRange ---`);
  const t3Buf = Buffer.from(originalBuf);
  t3Buf[10] ^= 0x01; // mutate a byte in the signed PDF header
  fs.writeFileSync('/tmp/tamper_tests/tamper_content_pbmac1.pdf', t3Buf);
  const t3Res = await auditBuffer(t3Buf, 'T3 Tampered Content');
  assert(t3Res.signatures[0].hashMatches === false, 'T3: Tampered PDF content correctly caught by ByteRange hash mismatch');

  // T4: Clean Single-Variable Certificate-Substitution Attack (Item 5)
  console.log(`\n--- [T4 Attack Vector] Clean Certificate Substitution (Attacker Cert B + Victim Cert A ESSCertIDv2) ---`);
  const pki = forge.pki;

  // 1. Victim Cert A
  const keysA = pki.rsa.generateKeyPair(2048);
  const certA = pki.createCertificate();
  certA.publicKey = keysA.publicKey;
  certA.serialNumber = '01';
  certA.validity.notBefore = new Date(Date.now() - 86400000);
  certA.validity.notAfter = new Date(Date.now() + 365 * 86400000);
  certA.setSubject([{ name: 'commonName', value: 'Victim Citizen A' }]);
  certA.setIssuer([{ name: 'commonName', value: 'FNMT-RCM' }]);
  certA.sign(keysA.privateKey, forge.md.sha256.create());
  const certADer = forge.asn1.toDer(pki.certificateToAsn1(certA)).getBytes();
  const mdA = forge.md.sha256.create();
  mdA.update(certADer);
  const certAHashBytes = mdA.digest().getBytes();

  // 2. Attacker Cert B (uncompromised ASN.1, valid dates, valid RSA-2048 keypair)
  const keysB = pki.rsa.generateKeyPair(2048);
  const certB = pki.createCertificate();
  certB.publicKey = keysB.publicKey;
  certB.serialNumber = '02';
  certB.validity.notBefore = new Date(Date.now() - 86400000);
  certB.validity.notAfter = new Date(Date.now() + 365 * 86400000);
  certB.setSubject([{ name: 'commonName', value: 'Attacker B' }]);
  certB.setIssuer([{ name: 'commonName', value: 'FNMT-RCM' }]);
  certB.sign(keysB.privateKey, forge.md.sha256.create());

  // 3. Document bytes in original ByteRange: originalBuf[0..l0] + originalBuf[b1..b1+l1]
  const signedDocBytes = Buffer.concat([originalBuf.slice(0, l0), originalBuf.slice(b1, b1 + l1)]);

  // 4. Create CMS container signed by Attacker B over signedDocBytes
  const p7Sub = forge.pkcs7.createSignedData();
  p7Sub.content = forge.util.createBuffer(signedDocBytes.toString('binary'));
  p7Sub.addCertificate(certB);
  p7Sub.addSigner({
    key: keysB.privateKey,
    certificate: certB,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest }
    ]
  });
  p7Sub.sign({ detached: true });

  // 5. Inject ESSCertIDv2 containing Victim Cert A's hash into Attacker's signedAttrs
  const scv2SubAsn1 = forge.asn1.create(
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
                    forge.asn1.Type.SEQUENCE,
                    true,
                    [
                      forge.asn1.create(
                        forge.asn1.Class.UNIVERSAL,
                        forge.asn1.Type.OCTETSTRING,
                        false,
                        certAHashBytes
                      )
                    ]
                  )
                ]
              )
            ]
          )
        ]
      )
    ]
  );
  const signerSub = p7Sub.signers[0];
  signerSub.authenticatedAttributesAsn1.value.push(scv2SubAsn1);
  signerSub.authenticatedAttributesAsn1.value.sort((a, b) => {
    const derA = forge.asn1.toDer(a).getBytes();
    const derB = forge.asn1.toDer(b).getBytes();
    return derA < derB ? -1 : derA > derB ? 1 : 0;
  });

  // 6. Attacker B signs the complete signedAttrs SET with Attacker Key B
  const attrsSetSub = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SET,
    true,
    signerSub.authenticatedAttributesAsn1.value
  );
  const attrsDerSub = forge.asn1.toDer(attrsSetSub).getBytes();
  const mdSub = forge.md.sha256.create();
  mdSub.update(attrsDerSub, 'raw');
  signerSub.signature = keysB.privateKey.sign(mdSub);

  // Rebuild signerInfos with updated authenticatedAttributes and signature
  p7Sub.signerInfos = [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.INTEGER,
        false,
        forge.asn1.integerToDer(signerSub.version).getBytes()
      ),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.pki.distinguishedNameToAsn1({ attributes: signerSub.issuer }),
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.INTEGER,
          false,
          forge.util.hexToBytes(signerSub.serialNumber)
        ),
      ]),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer(signerSub.digestAlgorithm).getBytes()
        ),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
      ]),
      signerSub.authenticatedAttributesAsn1,
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(
          forge.asn1.Class.UNIVERSAL,
          forge.asn1.Type.OID,
          false,
          forge.asn1.oidToDer(signerSub.signatureAlgorithm).getBytes()
        ),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
      ]),
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OCTETSTRING,
        false,
        signerSub.signature
      ),
    ]),
  ];

  const t4CmsDer = forge.asn1.toDer(p7Sub.toAsn1()).getBytes();
  const t4Hex = forge.util.bytesToHex(t4CmsDer).padEnd(hexSlice.length, '0');
  const t4Buf = Buffer.concat([
    originalBuf.slice(0, b0 + l0),
    Buffer.from('<' + t4Hex + '>'),
    originalBuf.slice(b1)
  ]);

  if (!fs.existsSync('/tmp/tamper_matrix_full')) fs.mkdirSync('/tmp/tamper_matrix_full', { recursive: true });
  fs.writeFileSync('/tmp/tamper_matrix_full/tamper_cert_substitution.pdf', t4Buf);

  const t4Res = await auditBuffer(t4Buf, 'T4 Clean Certificate Substitution');
  assert(t4Res.signatures[0].hashMatches === true, 'T4: Document content digest is 100% valid (hashMatches === true)');
  assert(t4Res.signatures[0].mathSignatureStatus === 'VALID', 'T4: Attacker RSA signature is 100% mathematically valid');
  assert(t4Res.signatures[0].certHashMatches === false, 'T4: ESSCertIDv2 hash mismatch detected against embedded cert');
  assert(t4Res.signatures[0].certSubstitutionDetected === true, 'T4: Certificate substitution detected exclusively via ESSCertIDv2 certHash mismatch');
  assert(t4Res.signatures[0].hasMalformedEssCert === false, 'T4: Valid ASN.1 structure has hasMalformedEssCert === false');
  assert(t4Res.signatures[0].rsaKeyBits === 2048, 'T4: Attacker B key is verified as RSA-2048');
  assert(t4Res.signatures[0].isWeakRsaKey === false, 'T4: RSA-2048 is not marked as weak key');

  // T4b: Malformed SigningCertificateV2 Attribute (Case a - Defense against corruption bypass)
  console.log(`\n--- [T4b Vector] Malformed SigningCertificateV2 (Attacker Corrupts ASN.1 Attribute) ---`);
  const t4bDer = new Uint8Array(Buffer.from(t4CmsDer, 'binary'));
  const certAHashBuf = Buffer.from(certAHashBytes, 'binary');
  for (let i = 0; i < t4bDer.length - 34; i++) {
    if (t4bDer[i] === 0x04 && t4bDer[i + 1] === 32 && t4bDer[i + 2] === certAHashBuf[0] && t4bDer[i + 3] === certAHashBuf[1]) {
      t4bDer[i] = 0x05; // corrupt OCTET STRING tag to NULL
      break;
    }
  }
  const t4bHex = toHex(t4bDer) + '0'.repeat(hexSlice.length - t4bDer.length * 2);
  const t4bBuf = Buffer.concat([
    originalBuf.slice(0, b0 + l0),
    Buffer.from('<' + t4bHex + '>'),
    originalBuf.slice(b1)
  ]);
  const t4bRes = await auditBuffer(t4bBuf, 'T4b Malformed SigningCertificateV2');
  assert(t4bRes.signatures[0].hasMalformedEssCert === true, 'T4b: Malformed SigningCertificateV2 correctly flagged as hasMalformedEssCert === true');
  assert(t4bRes.signatures[0].certSubstitutionDetected === false, 'T4b: Malformed attribute does not falsely claim certSubstitutionDetected');

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
from pyhanko_certvalidator import ValidationContext

targets = [
    ("/tmp/pades_e2e_test/signed_pbmac1.pdf", "PBMAC1"),
    ("/tmp/pades_e2e_test/signed_legacy.pdf", "Legacy 3DES"),
    ("/tmp/pades_e2e_test/signed_ecdsa_valid.pdf", "Detached ECDSA P-256")
]

for path, label in targets:
    with open(path, "rb") as f:
        r = PdfFileReader(f)
        sig = r.embedded_signatures[0]
        vc = ValidationContext(trust_roots=[sig.signer_cert]) if sig.signer_cert else None
        st = validation.validate_pdf_signature(sig, signer_validation_context=vc)
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

  await runPositiveTest(
    '/tmp/pades_e2e_test/signed_ecdsa_valid.pdf',
    'OUR ENGINE / INDEPENDENT: Detached ECDSA P-256 Signed PDF',
    { digestAlgorithm: 'SHA-256', isSha1: false }
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

  // Mirror freshly generated base & tamper test files to /sdcard/Download/pades_test/
  const sdcardDir = '/sdcard/Download/pades_test';
  if (fs.existsSync('/sdcard/Download')) {
    if (!fs.existsSync(sdcardDir)) fs.mkdirSync(sdcardDir, { recursive: true });
    fs.copyFileSync('/tmp/pades_e2e_test/signed_pbmac1.pdf', path.join(sdcardDir, 'signed_pbmac1.pdf'));
    fs.copyFileSync('/tmp/tamper_tests/tamper_sig_pbmac1.pdf', path.join(sdcardDir, 'tamper_sig_pbmac1.pdf'));
    fs.copyFileSync('/tmp/tamper_tests/tamper_time_pbmac1.pdf', path.join(sdcardDir, 'tamper_time_pbmac1.pdf'));
    fs.copyFileSync('/tmp/tamper_tests/tamper_content_pbmac1.pdf', path.join(sdcardDir, 'tamper_content_pbmac1.pdf'));
    fs.copyFileSync('/tmp/tamper_matrix_full/tamper_cert_substitution.pdf', path.join(sdcardDir, 'tamper_cert_substitution.pdf'));
    console.log(`[EXPORT] Copied fresh base and 4 tamper fixtures to ${sdcardDir}`);
  }

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
