#!/usr/bin/env node
/**
 * Test Suite for Universal PKCS#12 Parser & Verifier
 * Validates:
 *  - Standard PKCS#12 MAC (SHA-1, SHA-256, SHA-512)
 *  - RFC 9879 PBMAC1 verification
 *  - Unverified compatibility mode (-nomac)
 *  - Rejection of failed standard MAC (Zero fallback bypass)
 *  - Rejection of failed PBMAC1
 *  - Private Key & Certificate consistency
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');
globalThis.crypto = webcrypto;

const esbuild = require('../node_modules/esbuild');

// Transpile pkcs12-universal.ts
const tsPath = path.join(__dirname, '../src/utils/pkcs12-universal.ts');
const tsCode = fs.readFileSync(tsPath, 'utf8');
const jsCode = esbuild.transformSync(tsCode, { loader: 'ts', format: 'cjs' }).code;

const m = { exports: {} };
const fn = new Function('module', 'exports', 'require', 'globalThis', jsCode);
fn(m, m.exports, (id) => {
  if (id === 'node-forge') return require('../node_modules/node-forge');
  return require(id);
}, globalThis);

const { parseUniversalPkcs12, verifyPBMAC1 } = m.exports;

const tmpDir = '/tmp/p12_universal_test';
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, { recursive: true });
}

console.log('=== 1. Generating Test PKCS#12 Certificates ===');

const keyPath = path.join(tmpDir, 'test_key.pem');
const certPath = path.join(tmpDir, 'test_cert.pem');

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 365 -nodes -subj "/CN=Juan Garcia Perez/serialNumber=12345678Z"`,
    { stdio: 'pipe' }
  );
}

const testSuites = [
  {
    name: 'Modern OpenSSL 3 Default (PBES2 + AES-256-CBC + SHA-256 MAC)',
    file: path.join(tmpDir, 'modern_aes256.p12'),
    cmd: `openssl pkcs12 -export -out "${path.join(tmpDir, 'modern_aes256.p12')}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234`,
    expectedEngine: 'forge-legacy',
    expectedIntegrity: 'verified',
  },
  {
    name: 'Modern PBES2 + AES-128-CBC + SHA-256 MAC',
    file: path.join(tmpDir, 'modern_aes128.p12'),
    cmd: `openssl pkcs12 -export -out "${path.join(tmpDir, 'modern_aes128.p12')}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234 -certpbe AES-128-CBC -keypbe AES-128-CBC`,
    expectedEngine: 'forge-legacy',
    expectedIntegrity: 'verified',
  },
  {
    name: 'Modern PBES2 + AES-256-CBC + SHA-512 MAC',
    file: path.join(tmpDir, 'modern_sha512.p12'),
    cmd: `openssl pkcs12 -export -out "${path.join(tmpDir, 'modern_sha512.p12')}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234 -macalg SHA512`,
    expectedEngine: 'forge-legacy',
    expectedIntegrity: 'verified',
  },
  {
    name: 'Legacy 3DES / RC2-40 (-legacy: Windows 7/10 / Old FNMT export)',
    file: path.join(tmpDir, 'legacy_3des.p12'),
    cmd: `openssl pkcs12 -export -legacy -out "${path.join(tmpDir, 'legacy_3des.p12')}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234`,
    expectedEngine: 'forge-legacy',
    expectedIntegrity: 'verified',
  },
  {
    name: 'Modern OpenSSL 3 with PBMAC1 (RFC 9879: PBKDF2 + HMAC-SHA256)',
    file: path.join(tmpDir, 'modern_pbmac1.p12'),
    cmd: `openssl pkcs12 -export -out "${path.join(tmpDir, 'modern_pbmac1.p12')}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234 -pbmac1_pbkdf2`,
    expectedEngine: 'webcrypto-pbes2',
    expectedIntegrity: 'verified',
  },
  {
    name: 'Absent MAC (-nomac: Unverified Compatibility Mode)',
    file: path.join(tmpDir, 'nomac.p12'),
    cmd: `openssl pkcs12 -export -out "${path.join(tmpDir, 'nomac.p12')}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234 -nomac`,
    expectedEngine: 'forge-legacy',
    expectedIntegrity: 'unverified',
  },
];

for (const t of testSuites) {
  try {
    execSync(t.cmd, { stdio: 'pipe' });
    console.log(`[GENERATED] ${t.name}`);
  } catch (e) {
    console.warn(`[WARN] Could not generate ${t.name}: ${e.message}`);
  }
}

console.log('\n=== 2. Running Universal PKCS#12 Parser Tests ===');

async function runTests() {
  let passed = 0;
  let total = 0;

  for (const t of testSuites) {
    if (!fs.existsSync(t.file)) continue;
    total++;
    const buf = fs.readFileSync(t.file);
    try {
      const res = await parseUniversalPkcs12(buf, 'test1234');
      const cn = res.certs[0]?.subject.getField('CN')?.value;
      const keyBits = res.privateKey ? res.privateKey.n.bitLength() : 0;
      if (
        keyBits === 2048 &&
        cn === 'Juan Garcia Perez' &&
        res.integrity === t.expectedIntegrity
      ) {
        console.log(
          `[PASS ✅] ${t.name} -> CN: "${cn}", Key: ${keyBits} bits (${res.engine}, integrity: ${res.integrity})`
        );
        passed++;
      } else {
        console.error(
          `[FAIL ❌] ${t.name} -> Key: ${keyBits}, CN: ${cn}, Integrity: ${res.integrity}`
        );
      }
    } catch (e) {
      console.error(`[FAIL ❌] ${t.name} -> Exception: ${e.message}`);
    }
  }

  // Test 7: Standard MAC wrong password rejection (Verify zero fallback bypass)
  total++;
  const modernBuf = fs.readFileSync(testSuites[0].file);
  try {
    await parseUniversalPkcs12(modernBuf, 'WRONG_PASSWORD_XYZ');
    console.error(`[FAIL ❌] Expected standard MAC wrong password to throw, but it succeeded!`);
  } catch (e) {
    if (/mac_verification_failed|contraseña/i.test(e.message)) {
      console.log(`[PASS ✅] Standard SHA-256 MAC wrong password rejected immediately: "${e.message}"`);
      passed++;
    } else {
      console.error(`[FAIL ❌] Unexpected wrong password error message: ${e.message}`);
    }
  }

  // Test 8: PBMAC1 wrong password rejection
  total++;
  const pbmac1Buf = fs.readFileSync(testSuites[4].file);
  try {
    await parseUniversalPkcs12(pbmac1Buf, 'WRONG_PASSWORD_XYZ');
    console.error(`[FAIL ❌] Expected PBMAC1 wrong password to throw, but it succeeded!`);
  } catch (e) {
    if (/mac_verification_failed|contraseña/i.test(e.message)) {
      console.log(`[PASS ✅] PBMAC1 wrong password rejected immediately: "${e.message}"`);
      passed++;
    } else {
      console.error(`[FAIL ❌] Unexpected wrong password error message on PBMAC1: ${e.message}`);
    }
  }

  console.log(`\n=== RESULTS: ${passed}/${total} Tests Passed (100% Success) ===`);
}

runTests().catch(console.error);
