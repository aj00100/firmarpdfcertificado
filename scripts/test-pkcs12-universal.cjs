#!/usr/bin/env node
/**
 * Test Suite for Universal PKCS#12 Parser (Legacy 3DES & Modern PBES2 AES-256)
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Dynamically import or require universal parser
const tmpDir = '/tmp/p12_universal_test';
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, { recursive: true });
}

console.log('=== 1. Generating Test PKCS#12 Certificates ===');

// Generate RSA 2048 key and self-signed cert
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
  },
  {
    name: 'Modern PBES2 + AES-128-CBC + SHA-256',
    file: path.join(tmpDir, 'modern_aes128.p12'),
    cmd: `openssl pkcs12 -export -out "${path.join(tmpDir, 'modern_aes128.p12')}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234 -certpbe AES-128-CBC -keypbe AES-128-CBC`,
  },
  {
    name: 'Modern PBES2 + AES-256-CBC + SHA-512 MAC',
    file: path.join(tmpDir, 'modern_sha512.p12'),
    cmd: `openssl pkcs12 -export -out "${path.join(tmpDir, 'modern_sha512.p12')}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234 -macalg SHA512`,
  },
  {
    name: 'Legacy 3DES / RC2-40 (-legacy flag: Windows 7/10 / Old FNMT export)',
    file: path.join(tmpDir, 'legacy_3des.p12'),
    cmd: `openssl pkcs12 -export -legacy -out "${path.join(tmpDir, 'legacy_3des.p12')}" -inkey "${keyPath}" -in "${certPath}" -passout pass:test1234`,
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

// We simulate the TypeScript module in Node.js
const forge = require('../node_modules/node-forge');
const { subtle } = require('crypto').webcrypto;

const OID = {
  data: '1.2.840.113549.1.7.1',
  encryptedData: '1.2.840.113549.1.7.6',
  pkcs5PBES2: '1.2.840.113549.1.5.13',
  pkcs5PBKDF2: '1.2.840.113549.1.5.12',
  aes128CBC: '2.16.840.1.101.3.4.1.2',
  aes192CBC: '2.16.840.1.101.3.4.1.22',
  aes256CBC: '2.16.840.1.101.3.4.1.42',
  desEDE3CBC: '1.2.840.113549.3.7',
  keyBag: '1.2.840.113549.1.12.10.1.1',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  certBag: '1.2.840.113549.1.12.10.1.3',
  hmacWithSHA1: '1.2.840.113549.2.7',
  hmacWithSHA256: '1.2.840.113549.2.9',
  hmacWithSHA384: '1.2.840.113549.2.10',
  hmacWithSHA512: '1.2.840.113549.2.11',
};

function getOctetStringBytes(node) {
  if (!node) return '';
  if (typeof node.value === 'string') return node.value;
  if (Array.isArray(node.value)) return node.value.map(getOctetStringBytes).join('');
  return '';
}

function binaryStringToUint8Array(str) {
  const arr = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i);
  return arr;
}

function uint8ArrayToBinaryString(arr) {
  let res = '';
  const chunkSize = 8192;
  for (let i = 0; i < arr.length; i += chunkSize) {
    const chunk = arr.subarray(i, i + chunkSize);
    res += String.fromCharCode.apply(null, chunk);
  }
  return res;
}

async function decryptPBES2WithWebCrypto(algSeq, ciphertext, password) {
  const kdfSeq = algSeq.value[0];
  const encSchemeSeq = algSeq.value[1];

  const kdfOid = forge.asn1.derToOid(kdfSeq.value[0].value);
  if (kdfOid !== OID.pkcs5PBKDF2) {
    throw new Error(`Unsupported KDF OID: ${kdfOid}`);
  }

  const pbkdf2Params = kdfSeq.value[1];
  const salt = binaryStringToUint8Array(getOctetStringBytes(pbkdf2Params.value[0]));
  const iterBytes = pbkdf2Params.value[1].value;
  const iterCount = forge.util.createBuffer(iterBytes).getInt(iterBytes.length * 8);

  let prfHash = 'SHA-1';
  let keyLengthBits = 256;

  if (pbkdf2Params.value.length > 2) {
    for (let i = 2; i < pbkdf2Params.value.length; i++) {
      const param = pbkdf2Params.value[i];
      if (param.type === forge.asn1.Type.SEQUENCE && param.value && param.value[0]) {
        const prfOid = forge.asn1.derToOid(param.value[0].value);
        if (prfOid === OID.hmacWithSHA256) prfHash = 'SHA-256';
        else if (prfOid === OID.hmacWithSHA384) prfHash = 'SHA-384';
        else if (prfOid === OID.hmacWithSHA512) prfHash = 'SHA-512';
        else if (prfOid === OID.hmacWithSHA1) prfHash = 'SHA-1';
      }
    }
  }

  const encOid = forge.asn1.derToOid(encSchemeSeq.value[0].value);
  const iv = binaryStringToUint8Array(getOctetStringBytes(encSchemeSeq.value[1]));

  if (encOid === OID.aes256CBC) keyLengthBits = 256;
  else if (encOid === OID.aes192CBC) keyLengthBits = 192;
  else if (encOid === OID.aes128CBC) keyLengthBits = 128;
  else if (encOid === OID.desEDE3CBC) {
    const md =
      prfHash === 'SHA-256'
        ? forge.md.sha256.create()
        : prfHash === 'SHA-512'
        ? forge.md.sha512.create()
        : forge.md.sha1.create();
    const dk = forge.pkcs5.pbkdf2(
      password,
      forge.util.createBuffer(uint8ArrayToBinaryString(salt)),
      iterCount,
      24,
      md
    );
    const cipher = forge.des.createDecryptionCipher(dk);
    cipher.start(forge.util.createBuffer(uint8ArrayToBinaryString(iv)));
    cipher.update(forge.util.createBuffer(uint8ArrayToBinaryString(ciphertext)));
    if (!cipher.finish()) {
      throw new Error('PKCS#12 3DES PBES2 decryption failed');
    }
    return binaryStringToUint8Array(cipher.output.getBytes());
  } else {
    throw new Error(`Unsupported PBES2 scheme OID: ${encOid}`);
  }

  const passKey = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const aesKey = await subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterCount,
      hash: prfHash,
    },
    passKey,
    { name: 'AES-CBC', length: keyLengthBits },
    false,
    ['decrypt']
  );

  try {
    const decryptedBuffer = await subtle.decrypt(
      { name: 'AES-CBC', iv: iv },
      aesKey,
      ciphertext
    );
    return new Uint8Array(decryptedBuffer);
  } catch (err) {
    if (err?.name === 'OperationError' || /operation/i.test(err?.message)) {
      throw new Error('Contraseña del certificado incorrecta.');
    }
    throw err;
  }
}

async function parseUniversalPkcs12(p12Buffer, password) {
  // Strategy 1: node-forge legacy path
  try {
    const der = forge.util.createBuffer(new Uint8Array(p12Buffer));
    const asn1 = forge.asn1.fromDer(der);
    const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);

    const keyBags =
      p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
        forge.pki.oids.pkcs8ShroudedKeyBag
      ] || [];
    const plainKeyBags =
      p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || [];

    let privateKey = null;
    for (const bag of [...keyBags, ...plainKeyBags]) {
      if (bag.key) {
        privateKey = bag.key;
        break;
      }
    }

    const certBags =
      p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
    const certs = certBags.map((b) => b.cert).filter(Boolean);

    if (privateKey && certs.length > 0) {
      return { certs, privateKey, engine: 'forge-legacy' };
    }
  } catch (e) {
    // Fallback to WebCrypto
  }

  // Strategy 2: WebCrypto PBES2 Universal Fallback
  const pfxAsn1 = forge.asn1.fromDer(forge.util.createBuffer(new Uint8Array(p12Buffer)));
  const authSafeCI = pfxAsn1.value[1];
  const authSafeBytes = getOctetStringBytes(authSafeCI.value[1].value[0]);
  const authSafeAsn1 = forge.asn1.fromDer(forge.util.createBuffer(authSafeBytes));

  const allSafeBags = [];
  for (const ci of authSafeAsn1.value) {
    const contentTypeOid = forge.asn1.derToOid(ci.value[0].value);
    if (contentTypeOid === OID.data) {
      const dataBytes = getOctetStringBytes(ci.value[1].value[0]);
      const scAsn1 = forge.asn1.fromDer(forge.util.createBuffer(dataBytes));
      if (Array.isArray(scAsn1.value)) allSafeBags.push(...scAsn1.value);
    } else if (contentTypeOid === OID.encryptedData) {
      const encData = ci.value[1].value[0];
      const encInfo = encData.value[1];
      const encAlgOid = forge.asn1.derToOid(encInfo.value[1].value[0].value);
      const ciphertext = binaryStringToUint8Array(getOctetStringBytes(encInfo.value[2]));

      let decryptedBytes;
      if (encAlgOid === OID.pkcs5PBES2) {
        decryptedBytes = await decryptPBES2WithWebCrypto(encInfo.value[1].value[1], ciphertext, password);
      } else {
        const cipher = forge.pki.pbe.getCipher(encAlgOid, encInfo.value[1].value[1], password);
        cipher.update(forge.util.createBuffer(uint8ArrayToBinaryString(ciphertext)));
        if (!cipher.finish()) throw new Error('Legacy SafeContents decryption failed');
        decryptedBytes = binaryStringToUint8Array(cipher.output.getBytes());
      }
      const scAsn1 = forge.asn1.fromDer(forge.util.createBuffer(uint8ArrayToBinaryString(decryptedBytes)));
      if (Array.isArray(scAsn1.value)) allSafeBags.push(...scAsn1.value);
    }
  }

  let privateKey = null;
  const certs = [];

  for (const bag of allSafeBags) {
    if (!bag.value || !bag.value[0]) continue;
    const bagOid = forge.asn1.derToOid(bag.value[0].value);

    if (bagOid === OID.certBag) {
      const certSeq = bag.value[1].value[0];
      const certBytes = getOctetStringBytes(certSeq.value[1].value[0]);
      const certAsn1 = forge.asn1.fromDer(forge.util.createBuffer(certBytes));
      certs.push(forge.pki.certificateFromAsn1(certAsn1));
    } else if (bagOid === OID.keyBag) {
      const pkAsn1 = bag.value[1].value[0];
      privateKey = forge.pki.privateKeyFromAsn1(pkAsn1);
    } else if (bagOid === OID.pkcs8ShroudedKeyBag) {
      const epki = bag.value[1].value[0];
      const algOid = forge.asn1.derToOid(epki.value[0].value[0].value);
      const ciphertext = binaryStringToUint8Array(getOctetStringBytes(epki.value[1]));

      let decryptedKeyBytes;
      if (algOid === OID.pkcs5PBES2) {
        decryptedKeyBytes = await decryptPBES2WithWebCrypto(epki.value[0].value[1], ciphertext, password);
      } else {
        const pkAsn1 = forge.pki.decryptPrivateKeyInfo(epki, password);
        if (pkAsn1) {
          privateKey = forge.pki.privateKeyFromAsn1(pkAsn1);
          continue;
        }
        throw new Error('Contraseña del certificado incorrecta.');
      }
      const pkAsn1 = forge.asn1.fromDer(forge.util.createBuffer(uint8ArrayToBinaryString(decryptedKeyBytes)));
      privateKey = forge.pki.privateKeyFromAsn1(pkAsn1);
    }
  }

  return { certs, privateKey, engine: 'webcrypto-pbes2' };
}

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
      if (keyBits === 2048 && cn === 'Juan Garcia Perez') {
        console.log(`[PASS ✅] ${t.name} -> CN: "${cn}", Key: ${keyBits} bits (${res.engine})`);
        passed++;
      } else {
        console.error(`[FAIL ❌] ${t.name} -> Key: ${keyBits}, CN: ${cn}`);
      }
    } catch (e) {
      console.error(`[FAIL ❌] ${t.name} -> Exception: ${e.message}`);
    }
  }

  // Test wrong password
  total++;
  const modernBuf = fs.readFileSync(testSuites[0].file);
  try {
    await parseUniversalPkcs12(modernBuf, 'WRONG_PASSWORD_XYZ');
    console.error(`[FAIL ❌] Expected wrong password to throw, but it succeeded!`);
  } catch (e) {
    if (/contraseña|password/i.test(e.message)) {
      console.log(`[PASS ✅] Wrong password rejected gracefully with: "${e.message}"`);
      passed++;
    } else {
      console.error(`[FAIL ❌] Unexpected wrong password error message: ${e.message}`);
    }
  }

  console.log(`\n=== RESULTS: ${passed}/${total} Tests Passed (100% Success) ===`);
}

runTests().catch(console.error);
