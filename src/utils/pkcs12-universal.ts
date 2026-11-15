// src/utils/pkcs12-universal.ts
/**
 * Universal PKCS#12 (.p12 / .pfx) Parser & Decryptor
 * 
 * Supports:
 *  - Legacy PBES1 (3DES, 40-bit RC2, SHA-1) via node-forge
 *  - Modern PBES2 (AES-128-CBC, AES-192-CBC, AES-256-CBC, 3DES) via WebCrypto & node-forge
 *  - PBKDF2 key derivation with SHA-1, SHA-256, SHA-384, SHA-512
 *  - Windows 11 (22H2+), macOS Sonoma/Sequoia, iOS 17+, and OpenSSL 3.x default exports
 *  - Full X.509 Certificate & RSA PrivateKey extraction for PAdES signing
 */
import forge from 'node-forge';

export interface UniversalPkcs12Result {
  certs: forge.pki.Certificate[];
  privateKey: forge.pki.rsa.PrivateKey | null;
  engine: 'forge-legacy' | 'webcrypto-pbes2';
}

export interface Pkcs12ErrorDetails {
  code:
    | 'wrong_password'
    | 'unsupported_cipher'
    | 'corrupt_file'
    | 'no_private_key'
    | 'no_certs'
    | 'unknown';
  message: string;
}

const OID = {
  data: '1.2.840.113549.1.7.1',
  encryptedData: '1.2.840.113549.1.7.6',
  pkcs5PBES2: '1.2.840.113549.1.5.13',
  pkcs5PBKDF2: '1.2.840.113549.1.5.12',
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

async function decryptPBES2WithWebCrypto(
  algSeq: any,
  ciphertext: Uint8Array,
  password: string
): Promise<Uint8Array> {
  const kdfSeq = algSeq.value[0];
  const encSchemeSeq = algSeq.value[1];

  const kdfOid = forge.asn1.derToOid(kdfSeq.value[0].value);
  if (kdfOid !== OID.pkcs5PBKDF2) {
    throw new Error(`Algoritmo KDF no soportado: ${kdfOid}`);
  }

  const pbkdf2Params = kdfSeq.value[1];
  const salt = binaryStringToUint8Array(getOctetStringBytes(pbkdf2Params.value[0]));
  const iterBytes = pbkdf2Params.value[1].value;
  const iterCount = forge.util.createBuffer(iterBytes).getInt(iterBytes.length * 8);

  let prfHash = 'SHA-1';
  let keyLengthBits = 256;

  // Detect PRF algorithm if present
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
    // 3DES inside PBES2 fallback to forge
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
      throw new Error('PKCS#12 3DES PBES2 decryption failed. Incorrect password?');
    }
    return binaryStringToUint8Array(cipher.output.getBytes());
  } else {
    throw new Error(`Esquema de cifrado PBES2 no soportado (OID: ${encOid})`);
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
 * Parses any PKCS#12 (.p12 / .pfx) buffer, automatically falling back to WebCrypto PBES2
 * when node-forge fails on modern Windows 11 / macOS / OpenSSL 3 certificates.
 */
export async function parseUniversalPkcs12(
  p12Buffer: ArrayBuffer,
  password: string
): Promise<UniversalPkcs12Result> {
  // --- STRATEGY 1: Standard node-forge Parser (Fast path for legacy 3DES/RC2 & standard files) ---
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
      return { certs, privateKey, engine: 'forge-legacy' };
    }
  } catch (forgeErr: any) {
    const msg = String(forgeErr?.message || '');
    // If forge specifically failed with MAC verification error on invalid password, check if it's really wrong password
    if (/mac could not be verified/i.test(msg) && !/unsupported/i.test(msg)) {
      // Could be wrong password, or could be SHA-256 MAC algorithm unsupported by forge
      // Let WebCrypto fallback attempt decryption; if it also fails on password, it will confirm
    }
  }

  // --- STRATEGY 2: Native WebCrypto PBES2 Universal Fallback ---
  try {
    const pfxAsn1 = forge.asn1.fromDer(forge.util.createBuffer(new Uint8Array(p12Buffer)));
    if (!pfxAsn1 || pfxAsn1.type !== forge.asn1.Type.SEQUENCE || !Array.isArray(pfxAsn1.value)) {
      throw new Error('El archivo seleccionado no es un contenedor PKCS#12 válido.');
    }

    const authSafeCI = pfxAsn1.value[1];
    if (!authSafeCI || !authSafeCI.value || !authSafeCI.value[1]) {
      throw new Error('Estructura AuthenticatedSafe de PKCS#12 inválida.');
    }

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
          // Legacy PKCS#12 PBE via forge
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

    if (!privateKey && certs.length === 0) {
      throw new Error(
        'Contraseña del certificado incorrecta o no se pudieron extraer las credenciales.'
      );
    }

    return { certs, privateKey, engine: 'webcrypto-pbes2' };
  } catch (err: any) {
    const rawMsg = String(err?.message || '');
    if (/contraseña|password|operationerror|padding/i.test(rawMsg)) {
      throw new Error('Contraseña del certificado incorrecta. Verifique su clave de exportación.');
    }
    throw new Error(
      `Error al procesar el archivo .p12/.pfx: ${rawMsg || 'Formato no soportado o archivo dañado.'}`
    );
  }
}
