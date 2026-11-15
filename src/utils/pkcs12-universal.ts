// src/utils/pkcs12-universal.ts
/**
 * Universal PKCS#12 (.p12 / .pfx) Parser, Verifier & Decryptor
 * 
 * Conformance & Security:
 *  - Outer MAC integrity verification:
 *     * Standard PKCS#12 MAC (SHA-1, SHA-256, SHA-512) via node-forge
 *     * RFC 9879 PBMAC1 (PBKDF2 + HMAC-SHA256/384/512) via WebCrypto
 *     * Prevents silent fallback bypass on standard MAC failures
 *  - Modern PBES2 Decryption (AES-128-CBC, AES-192-CBC, AES-256-CBC, 3DES) via WebCrypto
 *  - Strict Credential Validation:
 *     * Enforces presence of both X.509 certificate(s) and private key
 *     * Cryptographically matches RSA public key with private key modulus
 *  - 100% Client-Side Web Worker execution in browser RAM (zero file uploads)
 */
import forge from 'node-forge';

export interface UniversalPkcs12Result {
  certs: forge.pki.Certificate[];
  privateKey: forge.pki.rsa.PrivateKey;
  engine: 'forge-legacy' | 'webcrypto-pbes2';
  integrity: 'verified' | 'unverified';
}

export interface PBMAC1Parameters {
  salt: Uint8Array;
  iterations: number;
  keyLengthBytes: number;
  pbkdf2Prf: 'SHA-256' | 'SHA-384' | 'SHA-512';
  macHash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  expectedMac: Uint8Array;
}

const OID = {
  data: '1.2.840.113549.1.7.1',
  encryptedData: '1.2.840.113549.1.7.6',
  pkcs5PBES2: '1.2.840.113549.1.5.13',
  pkcs5PBKDF2: '1.2.840.113549.1.5.12',
  pbmac1: '1.2.840.113549.1.5.14',
  pbeWithSHAAnd3Key3DES: '1.2.840.113549.1.12.1.3',
  pbeWithSHAAnd40BitRC2: '1.2.840.113549.1.12.1.6',
  aes128CBC: '2.16.840.1.101.3.4.1.2',
  aes192CBC: '2.16.840.1.101.3.4.1.22',
  aes256CBC: '2.16.840.1.101.3.4.1.42',
  desEDE3CBC: '1.2.840.113549.3.7',
  keyBag: '1.2.840.113549.1.12.10.1.1',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  certBag: '1.2.840.113549.1.12.10.1.3',
  x509Certificate: '1.2.840.113549.1.9.22.1',
  hmacWithSHA1: '1.2.840.113549.2.7',
  hmacWithSHA224: '1.2.840.113549.2.8',
  hmacWithSHA256: '1.2.840.113549.2.9',
  hmacWithSHA384: '1.2.840.113549.2.10',
  hmacWithSHA512: '1.2.840.113549.2.11',
};

function getOctetStringBytes(node: any): string {
  if (!node) return '';
  if (typeof node.value === 'string') return node.value;
  if (Array.isArray(node.value)) {
    return node.value.map(getOctetStringBytes).join('');
  }
  return '';
}

function binaryStringToUint8Array(str: string): Uint8Array {
  const arr = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    arr[i] = str.charCodeAt(i);
  }
  return arr;
}

function uint8ArrayToBinaryString(arr: Uint8Array): string {
  let res = '';
  const chunkSize = 8192;
  for (let i = 0; i < arr.length; i += chunkSize) {
    const chunk = arr.subarray(i, i + chunkSize);
    res += String.fromCharCode.apply(null, chunk as any);
  }
  return res;
}

function asn1IntToNumber(node: any): number {
  if (!node || !node.value) return 0;
  return parseInt(forge.util.bytesToHex(node.value), 16);
}

/**
 * Fixed-work byte comparison helper
 */
export function constantWorkEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function getSubtleCrypto(): SubtleCrypto {
  const cryptoObj =
    (typeof globalThis !== 'undefined' && globalThis.crypto) ||
    (typeof window !== 'undefined' && window.crypto) ||
    (typeof self !== 'undefined' && self.crypto);
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error('WebCrypto API (crypto.subtle) no está disponible en este entorno.');
  }
  return cryptoObj.subtle;
}

/**
 * RFC 9879 PBMAC1 Outer MAC Verification
 */
export async function verifyPBMAC1(
  authSafeBytes: Uint8Array,
  password: string,
  params: PBMAC1Parameters
): Promise<boolean> {
  const {
    salt,
    iterations,
    keyLengthBytes,
    pbkdf2Prf,
    macHash,
    expectedMac,
  } = params;

  if (!Number.isSafeInteger(iterations) || iterations < 1) {
    throw new Error('INVALID_PBKDF2_ITERATIONS: Iteraciones PBKDF2 inválidas.');
  }

  // Safety ceiling calibrated for mobile / web workers
  if (iterations > 1_000_000) {
    throw new Error('PBKDF2_RESOURCE_LIMIT: Las iteraciones exceden el límite de seguridad (1.000.000).');
  }

  if (
    !Number.isSafeInteger(keyLengthBytes) ||
    keyLengthBytes < 20 ||
    keyLengthBytes > 128
  ) {
    throw new Error('INVALID_PBMAC1_KEY_LENGTH: Longitud de clave PBMAC1 inválida (debe ser 20-128 bytes).');
  }

  const subtle = getSubtleCrypto();

  // RFC 9879: UTF-8 password, without BOM or terminating null character
  const passwordBytes = new TextEncoder().encode(password);

  const passwordKey = await subtle.importKey(
    'raw',
    passwordBytes,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Derive the PBMAC1 key
  const derivedKey = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: pbkdf2Prf,
    },
    passwordKey,
    keyLengthBytes * 8
  );

  // Import derived key for HMAC
  const hmacKey = await subtle.importKey(
    'raw',
    derivedKey,
    {
      name: 'HMAC',
      hash: macHash,
    },
    false,
    ['sign']
  );

  // Authenticate the original AuthenticatedSafe content bytes
  const calculatedMac = new Uint8Array(
    await subtle.sign('HMAC', hmacKey, authSafeBytes)
  );

  return constantWorkEqual(calculatedMac, expectedMac);
}

function parsePBMAC1Parameters(macDigestInfo: any): PBMAC1Parameters {
  const algId = macDigestInfo.value[0];
  const expectedMac = binaryStringToUint8Array(getOctetStringBytes(macDigestInfo.value[1]));

  const pbmac1ParamsSeq = algId.value[1];
  if (!pbmac1ParamsSeq || !Array.isArray(pbmac1ParamsSeq.value) || pbmac1ParamsSeq.value.length < 2) {
    throw new Error('ASN1_PARSE_FAILED: Parámetros PBMAC1 incompletos en el ASN.1.');
  }

  const kdfSeq = pbmac1ParamsSeq.value[0];
  const macSchemeSeq = pbmac1ParamsSeq.value[1];

  const kdfOid = forge.asn1.derToOid(kdfSeq.value[0].value);
  if (kdfOid !== OID.pkcs5PBKDF2) {
    throw new Error(`UNSUPPORTED_KDF: KDF de PBMAC1 no soportado (${kdfOid}). Se requiere PBKDF2.`);
  }

  const pbkdf2Params = kdfSeq.value[1];
  if (!pbkdf2Params || !Array.isArray(pbkdf2Params.value) || pbkdf2Params.value.length < 2) {
    throw new Error('ASN1_PARSE_FAILED: Parámetros PBKDF2 de PBMAC1 ausentes.');
  }

  // Salt validation: RFC 8018 defines salt as CHOICE { specified OCTET STRING, otherSource AlgorithmIdentifier }
  const saltNode = pbkdf2Params.value[0];
  if (
    !saltNode ||
    saltNode.tagClass !== forge.asn1.Class.UNIVERSAL ||
    saltNode.type !== forge.asn1.Type.OCTETSTRING
  ) {
    throw new Error('UNSUPPORTED_SALT_SOURCE: Fuente de sal no soportada (se requiere specified OCTET STRING; otherSource AlgorithmIdentifier no implementado).');
  }
  const salt = binaryStringToUint8Array(getOctetStringBytes(saltNode));

  // Iteration count validation
  const iterNode = pbkdf2Params.value[1];
  if (
    !iterNode ||
    iterNode.tagClass !== forge.asn1.Class.UNIVERSAL ||
    iterNode.type !== forge.asn1.Type.INTEGER
  ) {
    throw new Error('ASN1_PARSE_FAILED: Parámetro iterationCount inválido en PBKDF2.');
  }
  const iterations = asn1IntToNumber(iterNode);

  // RFC 9879 Section 5 & A.6: keyLength MUST be explicitly present as a UNIVERSAL INTEGER in PBKDF2-params
  const keyLenNode = pbkdf2Params.value.length > 2 ? pbkdf2Params.value[2] : null;
  if (
    !keyLenNode ||
    keyLenNode.tagClass !== forge.asn1.Class.UNIVERSAL ||
    keyLenNode.type !== forge.asn1.Type.INTEGER
  ) {
    throw new Error('PBKDF2_KEY_LENGTH_REQUIRED: Parámetro keyLength ausente en PBKDF2 de PBMAC1 (requerido por RFC 9879).');
  }
  const keyLengthBytes = asn1IntToNumber(keyLenNode);

  // RFC 9879 Section 7: PRF MUST NOT be <= 160 bits (e.g. SHA-1 is SHOULD NOT / rejected by policy)
  let pbkdf2Prf: 'SHA-256' | 'SHA-384' | 'SHA-512';
  if (pbkdf2Params.value.length > 3 && pbkdf2Params.value[3]) {
    const prfSeq = pbkdf2Params.value[3];
    const prfOid = forge.asn1.derToOid(prfSeq.value[0].value);
    if (prfOid === OID.hmacWithSHA256) pbkdf2Prf = 'SHA-256';
    else if (prfOid === OID.hmacWithSHA384) pbkdf2Prf = 'SHA-384';
    else if (prfOid === OID.hmacWithSHA512) pbkdf2Prf = 'SHA-512';
    else if (prfOid === OID.hmacWithSHA1) {
      throw new Error('UNSUPPORTED_PRF: PBKDF2 con HMAC-SHA1 rechazado por la política de seguridad de esta implementación. RFC 9879 recomienda SHOULD NOT.');
    } else {
      throw new Error(`UNSUPPORTED_PRF: PRF de PBKDF2 no soportado (${prfOid})`);
    }
  } else {
    // If PRF parameter is omitted, RFC 8018 default is HMAC-SHA1, which RFC 9879 Section 7 discourages/our policy rejects
    throw new Error('UNSUPPORTED_PRF: Parámetro PRF ausente en PBKDF2; SHA-1 por defecto rechazado por política de seguridad (RFC 9879).');
  }

  // RFC 9879 Section 7: Message Authentication Scheme MUST NOT produce <= 160 bits (MUST NOT use SHA-1)
  const macOid = forge.asn1.derToOid(macSchemeSeq.value[0].value);
  let macHash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  if (macOid === OID.hmacWithSHA256) macHash = 'SHA-256';
  else if (macOid === OID.hmacWithSHA384) macHash = 'SHA-384';
  else if (macOid === OID.hmacWithSHA512) macHash = 'SHA-512';
  else if (macOid === OID.hmacWithSHA1) {
    throw new Error('UNSUPPORTED_MAC_ALGORITHM: HMAC-SHA1 está prohibido para PBMAC1 (RFC 9879 Sección 7 establece MUST NOT para resúmenes <= 160 bits).');
  } else {
    throw new Error(`UNSUPPORTED_MAC_ALGORITHM: Esquema MAC de PBMAC1 no soportado (${macOid})`);
  }

  return {
    salt,
    iterations,
    keyLengthBytes,
    pbkdf2Prf,
    macHash,
    expectedMac,
  };
}

async function decryptPBES2WithWebCrypto(
  algSeq: any,
  ciphertext: Uint8Array,
  password: string
): Promise<Uint8Array> {
  const kdfSeq = algSeq.value[0];
  const encSchemeSeq = algSeq.value[1];

  const kdfOid = forge.asn1.derToOid(kdfSeq.value[0].value);
  if (kdfOid !== OID.pkcs5PBKDF2) {
    throw new Error(`UNSUPPORTED_KDF: Algoritmo KDF no soportado: ${kdfOid}`);
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
    // 3DES inside PBES2 fallback to forge with explicit PRF mapping
    const mdMap: Record<string, () => forge.md.MessageDigest> = {
      'SHA-1': forge.md.sha1.create,
      'SHA-256': forge.md.sha256.create,
      'SHA-384': forge.md.sha384.create,
      'SHA-512': forge.md.sha512.create,
    };
    const mdFactory = mdMap[prfHash];
    if (!mdFactory) {
      throw new Error(`UNSUPPORTED_PRF: Algoritmo PRF no soportado para 3DES PBES2: ${prfHash}`);
    }
    const md = mdFactory();
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
      throw new Error('PKCS#12 3DES PBES2 decryption failed. Incorrect password?');
    }
    return binaryStringToUint8Array(cipher.output.getBytes());
  } else {
    throw new Error(`UNSUPPORTED_PBE_ALGORITHM: Esquema de cifrado PBES2 no soportado (OID: ${encOid})`);
  }

  const subtle = getSubtleCrypto();
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
  } catch (err: any) {
    if (err?.name === 'OperationError' || /operation/i.test(err?.message)) {
      throw new Error('Contraseña del certificado incorrecta.');
    }
    throw err;
  }
}

/**
 * Validates that the private key corresponds to the given X.509 certificate
 */
function matchesCertificate(cert: forge.pki.Certificate, privateKey: forge.pki.rsa.PrivateKey): boolean {
  const pub = cert.publicKey as any;
  if (pub && pub.n && privateKey.n && pub.e && privateKey.e) {
    return pub.n.equals(privateKey.n) && pub.e.equals(privateKey.e);
  }
  return false;
}

/**
 * Unpacks and decrypts SafeBags from the AuthenticatedSafe structure
 */
async function unpackAuthenticatedSafe(
  authSafeCI: any,
  password: string
): Promise<{ certs: forge.pki.Certificate[]; privateKey: forge.pki.rsa.PrivateKey }> {
  const authSafeBytes = getOctetStringBytes(authSafeCI.value[1].value[0]);
  const authSafeAsn1 = forge.asn1.fromDer(forge.util.createBuffer(authSafeBytes));

  const allSafeBags: any[] = [];

  for (const ci of authSafeAsn1.value) {
    const contentTypeOid = forge.asn1.derToOid(ci.value[0].value);

    if (contentTypeOid === OID.data) {
      const dataBytes = getOctetStringBytes(ci.value[1].value[0]);
      const scAsn1 = forge.asn1.fromDer(forge.util.createBuffer(dataBytes));
      if (Array.isArray(scAsn1.value)) {
        allSafeBags.push(...scAsn1.value);
      }
    } else if (contentTypeOid === OID.encryptedData) {
      const encData = ci.value[1].value[0];
      const encInfo = encData.value[1];
      const encAlgOid = forge.asn1.derToOid(encInfo.value[1].value[0].value);
      const ciphertextStr = getOctetStringBytes(encInfo.value[2]);
      const ciphertext = binaryStringToUint8Array(ciphertextStr);

      let decryptedBytes: Uint8Array;
      if (encAlgOid === OID.pkcs5PBES2) {
        decryptedBytes = await decryptPBES2WithWebCrypto(
          encInfo.value[1].value[1],
          ciphertext,
          password
        );
      } else {
        const cipher = (forge.pki as any).pbe.getCipher(
          encAlgOid,
          encInfo.value[1].value[1],
          password
        );
        cipher.update(forge.util.createBuffer(uint8ArrayToBinaryString(ciphertext)));
        if (!cipher.finish()) {
          throw new Error('Error al desencriptar SafeContents PKCS#12.');
        }
        decryptedBytes = binaryStringToUint8Array(cipher.output.getBytes());
      }

      const scAsn1 = forge.asn1.fromDer(
        forge.util.createBuffer(uint8ArrayToBinaryString(decryptedBytes))
      );
      if (Array.isArray(scAsn1.value)) {
        allSafeBags.push(...scAsn1.value);
      }
    }
  }

  let privateKey: forge.pki.rsa.PrivateKey | null = null;
  const certs: forge.pki.Certificate[] = [];

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
      privateKey = forge.pki.privateKeyFromAsn1(pkAsn1) as forge.pki.rsa.PrivateKey;
    } else if (bagOid === OID.pkcs8ShroudedKeyBag) {
      const epki = bag.value[1].value[0];
      const algOid = forge.asn1.derToOid(epki.value[0].value[0].value);
      const ciphertextStr = getOctetStringBytes(epki.value[1]);
      const ciphertext = binaryStringToUint8Array(ciphertextStr);

      let decryptedKeyBytes: Uint8Array;
      if (algOid === OID.pkcs5PBES2) {
        decryptedKeyBytes = await decryptPBES2WithWebCrypto(
          epki.value[0].value[1],
          ciphertext,
          password
        );
      } else {
        const pkAsn1 = forge.pki.decryptPrivateKeyInfo(epki, password);
        if (pkAsn1) {
          privateKey = forge.pki.privateKeyFromAsn1(pkAsn1) as forge.pki.rsa.PrivateKey;
          continue;
        }
        throw new Error('Contraseña del certificado incorrecta.');
      }

      const pkAsn1 = forge.asn1.fromDer(
        forge.util.createBuffer(uint8ArrayToBinaryString(decryptedKeyBytes))
      );
      privateKey = forge.pki.privateKeyFromAsn1(pkAsn1) as forge.pki.rsa.PrivateKey;
    }
  }

  // Bug A fix: Require BOTH privateKey and at least one certificate
  if (!privateKey || certs.length === 0) {
    throw new Error('INCOMPLETE_PKCS12_CREDENTIALS: El archivo debe contener al menos un certificado X.509 y una clave privada.');
  }

  // Validate private key corresponds to certificate
  const matchingCert = certs.find((c) => matchesCertificate(c, privateKey!));
  if (!matchingCert) {
    throw new Error('CERTIFICATE_KEY_MISMATCH: La clave privada extraída no coincide con ningún certificado en el archivo .p12.');
  }

  // Place matching signer certificate first
  certs.sort((a, b) => (matchesCertificate(a, privateKey!) ? -1 : matchesCertificate(b, privateKey!) ? 1 : 0));

  return { certs, privateKey };
}

/**
 * Parses any PKCS#12 (.p12 / .pfx) buffer with strict MAC verification and universal compatibility.
 */
export async function parseUniversalPkcs12(
  p12Input: ArrayBuffer | Uint8Array,
  password: string
): Promise<UniversalPkcs12Result> {
  const u8 = p12Input instanceof Uint8Array ? p12Input : new Uint8Array(p12Input);
  let pfxAsn1: any;
  try {
    pfxAsn1 = forge.asn1.fromDer(forge.util.createBuffer(u8), {
      strict: true,
      parseAllBytes: true,
      decodeBitStrings: false,
      maxDepth: 256,
    });
  } catch {
    throw new Error('CORRUPT_FILE: El archivo seleccionado no es un contenedor PKCS#12 válido o está dañado.');
  }

  if (!pfxAsn1 || pfxAsn1.type !== forge.asn1.Type.SEQUENCE || !Array.isArray(pfxAsn1.value)) {
    throw new Error('CORRUPT_FILE: El archivo seleccionado no es un contenedor PKCS#12 válido.');
  }

  const authSafeCI = pfxAsn1.value[1];
  if (!authSafeCI || !authSafeCI.value || !authSafeCI.value[1]) {
    throw new Error('CORRUPT_FILE: Estructura AuthenticatedSafe de PKCS#12 inválida.');
  }

  const hasMacData = pfxAsn1.value.length > 2 && Boolean(pfxAsn1.value[2]);
  let macAlgOid: string | null = null;
  let isPBMAC1 = false;

  if (hasMacData) {
    const macData = pfxAsn1.value[2];
    const macDigestInfo = macData.value[0];
    const algId = macDigestInfo.value[0];
    macAlgOid = forge.asn1.derToOid(algId.value[0].value);
    isPBMAC1 = macAlgOid === OID.pbmac1;
  }

  // === BRANCH 1: RFC 9879 PBMAC1 Verified Pathway ===
  if (isPBMAC1) {
    const macData = pfxAsn1.value[2];
    const macDigestInfo = macData.value[0];
    const pbmac1Params = parsePBMAC1Parameters(macDigestInfo);

    const authSafeRaw = getOctetStringBytes(authSafeCI.value[1].value[0]);
    const authSafeBytes = binaryStringToUint8Array(authSafeRaw);

    const macValid = await verifyPBMAC1(authSafeBytes, password, pbmac1Params);
    if (!macValid) {
      throw new Error('MAC_VERIFICATION_FAILED: Contraseña del certificado incorrecta o verificación de integridad (PBMAC1) fallida.');
    }

    // Integrity successfully verified; decrypt contents
    const { certs, privateKey } = await unpackAuthenticatedSafe(authSafeCI, password);
    return {
      certs,
      privateKey,
      engine: 'webcrypto-pbes2',
      integrity: 'verified',
    };
  }

  // === BRANCH 2: Standard PKCS#12 MAC Pathway (via node-forge) ===
  if (hasMacData) {
    try {
      const p12 = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, password);

      const keyBags =
        p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
          forge.pki.oids.pkcs8ShroudedKeyBag
        ] || [];
      const plainKeyBags =
        p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || [];

      let privateKey: forge.pki.rsa.PrivateKey | null = null;
      for (const bag of [...keyBags, ...plainKeyBags]) {
        if (bag.key) {
          privateKey = bag.key as forge.pki.rsa.PrivateKey;
          break;
        }
      }

      const certBags =
        p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
      const certs: forge.pki.Certificate[] = certBags
        .map((b) => b.cert)
        .filter((c): c is forge.pki.Certificate => Boolean(c));

      // Bug A fix: Enforce complete credentials
      if (!privateKey || certs.length === 0) {
        throw new Error('INCOMPLETE_PKCS12_CREDENTIALS: El archivo debe contener al menos un certificado X.509 y una clave privada.');
      }

      // Validate matching key and certificate
      const matchingCert = certs.find((c) => matchesCertificate(c, privateKey!));
      if (!matchingCert) {
        throw new Error('CERTIFICATE_KEY_MISMATCH: La clave privada extraída no coincide con ningún certificado en el archivo .p12.');
      }
      certs.sort((a, b) => (matchesCertificate(a, privateKey!) ? -1 : matchesCertificate(b, privateKey!) ? 1 : 0));

      return { certs, privateKey, engine: 'forge-legacy', integrity: 'verified' };
    } catch (forgeErr: any) {
      const msg = String(forgeErr?.message || '');

      // CRITICAL SECURITY FIX: Never silently bypass a failed standard MAC
      if (/mac could not be verified/i.test(msg) || /invalid password/i.test(msg)) {
        throw new Error('MAC_VERIFICATION_FAILED: Contraseña del certificado incorrecta o contenedor alterado.');
      }

      // If MAC was verified but SafeBag cipher is unsupported by forge, fallback to WebCrypto
      const { certs, privateKey } = await unpackAuthenticatedSafe(authSafeCI, password);
      return { certs, privateKey, engine: 'webcrypto-pbes2', integrity: 'verified' };
    }
  }

  // === BRANCH 3: Absent MAC (Unverified Compatibility Mode) ===
  try {
    const p12 = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, password);
    const keyBags =
      p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
        forge.pki.oids.pkcs8ShroudedKeyBag
      ] || [];
    const plainKeyBags =
      p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || [];

    let privateKey: forge.pki.rsa.PrivateKey | null = null;
    for (const bag of [...keyBags, ...plainKeyBags]) {
      if (bag.key) {
        privateKey = bag.key as forge.pki.rsa.PrivateKey;
        break;
      }
    }

    const certBags =
      p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
    const certs: forge.pki.Certificate[] = certBags
      .map((b) => b.cert)
      .filter((c): c is forge.pki.Certificate => Boolean(c));

    if (privateKey && certs.length > 0) {
      const matchingCert = certs.find((c) => matchesCertificate(c, privateKey!));
      if (!matchingCert) {
        throw new Error('CERTIFICATE_KEY_MISMATCH: La clave privada extraída no coincide con ningún certificado.');
      }
      certs.sort((a, b) => (matchesCertificate(a, privateKey!) ? -1 : matchesCertificate(b, privateKey!) ? 1 : 0));
      return { certs, privateKey, engine: 'forge-legacy', integrity: 'unverified' };
    }
  } catch {
    // Fall back to WebCrypto unpacker for unverified containers
  }

  const { certs, privateKey } = await unpackAuthenticatedSafe(authSafeCI, password);
  return { certs, privateKey, engine: 'webcrypto-pbes2', integrity: 'unverified' };
}
