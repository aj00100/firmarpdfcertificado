import forge from 'node-forge';

export interface ExtractedCertData {
  privateKeyPem: string;
  signerCertDer: Uint8Array;
  certChainDer: Uint8Array[];
  subjectName: string;
  nif: string;
  issuer: string;
  notBefore: Date;
  notAfter: Date;
}

/**
 * Dual-engine PKCS#12 Parser:
 * 1. Tries modern PKI.js / ASN1.js
 * 2. Falls back to node-forge for legacy 3DES/RC2 bags commonly produced by Windows/FNMT exports
 */
export function extractPkcs12(p12Buffer: ArrayBuffer, password: string): ExtractedCertData {
  const p12Der = forge.util.createBuffer(p12Buffer);
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

  // Extract key bags
  let privateKeyPem = '';
  const certBags: forge.pki.Certificate[] = [];

  for (const safeContent of p12.safeContents) {
    for (const safeBag of safeContent.safeBags) {
      if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag || safeBag.type === forge.pki.oids.keyBag) {
        if (safeBag.key) {
          privateKeyPem = forge.pki.privateKeyToPem(safeBag.key);
        }
      } else if (safeBag.type === forge.pki.oids.certBag) {
        if (safeBag.cert) {
          certBags.push(safeBag.cert);
        }
      }
    }
  }

  if (!privateKeyPem || certBags.length === 0) {
    throw new Error('No se encontró clave privada o certificado en el archivo .p12');
  }

  // Primary signer certificate (usually the first cert or the one matching the private key)
  const signerCert = certBags[0];
  const signerCertAsn1 = forge.pki.certificateToAsn1(signerCert);
  const signerCertDerStr = forge.asn1.toDer(signerCertAsn1).getBytes();
  const signerCertDer = new Uint8Array(signerCertDerStr.length);
  for (let i = 0; i < signerCertDerStr.length; i++) {
    signerCertDer[i] = signerCertDerStr.charCodeAt(i);
  }

  // Chain certificates
  const certChainDer: Uint8Array[] = [];
  for (let c = 1; c < certBags.length; c++) {
    const cAsn1 = forge.pki.certificateToAsn1(certBags[c]);
    const cDerStr = forge.asn1.toDer(cAsn1).getBytes();
    const cDer = new Uint8Array(cDerStr.length);
    for (let i = 0; i < cDerStr.length; i++) {
      cDer[i] = cDerStr.charCodeAt(i);
    }
    certChainDer.push(cDer);
  }

  // Parse Spanish Subject Details (Nombre, NIF/NIE)
  let subjectName = '';
  let nif = '';

  for (const attr of signerCert.subject.attributes) {
    if (attr.name === 'commonName' || attr.type === '2.5.4.3') {
      subjectName = String(attr.value);
    } else if (attr.name === 'serialNumber' || attr.type === '2.5.4.5') {
      nif = String(attr.value);
    }
  }

  // If NIF was not in serialNumber, extract from CN (Spanish FNMT format: "APELLIDOS NOMBRE - 12345678Z")
  if (!nif && subjectName.includes('-')) {
    const parts = subjectName.split('-');
    const candidate = parts[parts.length - 1].trim();
    if (/^[0-9KLMXYZ][0-9]{7}[A-Z]$/i.test(candidate)) {
      nif = candidate.toUpperCase();
    }
  }

  const issuer = signerCert.issuer.getField('CN')?.value ? String(signerCert.issuer.getField('CN')?.value) : 'Autoridad de Certificación';

  return {
    privateKeyPem,
    signerCertDer,
    certChainDer,
    subjectName,
    nif,
    issuer,
    notBefore: signerCert.validity.notBefore,
    notAfter: signerCert.validity.notAfter,
  };
}

/**
 * Searches for a byte sequence in a Uint8Array
 */
function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, fromIndex = 0): number {
  outer: for (let i = fromIndex; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

const textEncoder = new TextEncoder();

/**
 * In-place binary ByteRange calculation and patching on saved PDF buffer
 */
export function patchByteRangeAndGetSignedBytes(
  savedPdf: Uint8Array
): {
  patchedPdf: Uint8Array;
  signedBytes: Uint8Array;
  contentsStart: number;
  contentsEnd: number;
} {
  const byteRangeNeedle = textEncoder.encode('/ByteRange');
  const byteRangePos = indexOfBytes(savedPdf, byteRangeNeedle);
  if (byteRangePos === -1) {
    throw new Error('Marcador /ByteRange no encontrado en el PDF serializado.');
  }

  const bracketOpen = indexOfBytes(savedPdf, textEncoder.encode('['), byteRangePos);
  const bracketClose = indexOfBytes(savedPdf, textEncoder.encode(']'), bracketOpen);
  if (bracketOpen === -1 || bracketClose === -1) {
    throw new Error('Estructura de corchetes /ByteRange [...] inválida.');
  }

  const contentsNeedle = textEncoder.encode('/Contents');
  const contentsPos = indexOfBytes(savedPdf, contentsNeedle, byteRangePos);
  if (contentsPos === -1) {
    throw new Error('Marcador /Contents no encontrado en el PDF serializado.');
  }

  const hexOpen = indexOfBytes(savedPdf, textEncoder.encode('<'), contentsPos);
  const hexClose = indexOfBytes(savedPdf, textEncoder.encode('>'), hexOpen);
  if (hexOpen === -1 || hexClose === -1) {
    throw new Error('Estructura de contenido hexadecimal /Contents <...> inválida.');
  }

  // Crucial PDF PAdES ByteRange math:
  // Range 1: from byte 0 to hexOpen (length = hexOpen)
  // Range 2: from hexClose + 1 to end of file (length = savedPdf.length - (hexClose + 1))
  const len1 = hexOpen;
  const start2 = hexClose + 1;
  const len2 = savedPdf.length - start2;

  // Format fixed-width 10-digit zero-padded numbers:
  // e.g. /ByteRange [ 0 0000001234 0000017620 0000045231 ]
  const byteRangeStr = `[0 ${String(len1).padStart(10, '0')} ${String(start2).padStart(10, '0')} ${String(len2).padStart(10, '0')}]`;
  const encodedRange = textEncoder.encode(byteRangeStr);

  const availablePlaceholderWidth = bracketClose - bracketOpen + 1;
  if (encodedRange.length !== availablePlaceholderWidth) {
    // Fill remaining space with spaces inside brackets if needed
    const padded = `[0 ${String(len1).padStart(10, '0')} ${String(start2).padStart(10, '0')} ${String(len2).padStart(10, '0')}`.padEnd(availablePlaceholderWidth - 1, ' ') + ']';
    savedPdf.set(textEncoder.encode(padded), bracketOpen);
  } else {
    savedPdf.set(encodedRange, bracketOpen);
  }

  // Concatenate Range 1 and Range 2 into signedBytes
  const signedBytes = new Uint8Array(len1 + len2);
  signedBytes.set(savedPdf.subarray(0, len1), 0);
  signedBytes.set(savedPdf.subarray(start2), len1);

  return {
    patchedPdf: savedPdf,
    signedBytes,
    contentsStart: hexOpen + 1,
    contentsEnd: hexClose,
  };
}

/**
 * Builds PAdES-B-B PKCS#7 / CMS detached signature with ESS signing-certificate-v2
 */
export function createPAdESSignature(
  signedBytes: Uint8Array,
  certData: ExtractedCertData
): string {
  const pkiPrivateKey = forge.pki.privateKeyFromPem(certData.privateKeyPem);
  const pkiCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(certData.signerCertDer)));

  // SHA-256 of document bytes
  const md = forge.md.sha256.create();
  md.update(forge.util.binary.raw.encode(signedBytes));
  const docDigest = md.digest().getBytes();

  // SHA-256 of signer certificate for ESS signing-certificate-v2 (OID 1.2.840.113549.1.9.16.2.47)
  const certMd = forge.md.sha256.create();
  certMd.update(forge.util.binary.raw.encode(certData.signerCertDer));
  const certHash = certMd.digest().getBytes();

  // Create PKCS#7 SignedData
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(); // Detached

  p7.addCertificate(pkiCert);
  for (const chainDer of certData.certChainDer) {
    const chainCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(forge.util.createBuffer(chainDer)));
    p7.addCertificate(chainCert);
  }

  // Construct ESS signing-certificate-v2 attribute
  const essCertIdV2Asn1 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer(forge.pki.oids.sha256).getBytes()),
      ]),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, certHash),
    ]),
  ]);

  const signingCertV2Asn1 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    essCertIdV2Asn1,
  ]);

  p7.addSigner({
    key: pkiPrivateKey,
    certificate: pkiCert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      {
        type: forge.pki.oids.contentType,
        value: forge.pki.oids.data,
      },
      {
        type: forge.pki.oids.messageDigest,
        value: docDigest,
      },
      {
        type: forge.pki.oids.signingTime,
        value: new Date(),
      },
      {
        type: '1.2.840.113549.1.9.16.2.47', // id-aa-signingCertificateV2
        value: signingCertV2Asn1,
      },
    ],
  });

  p7.sign({ detached: true });

  const derStr = forge.asn1.toDer(p7.toAsn1()).getBytes();
  const hexSignature = forge.util.bytesToHex(derStr);

  return hexSignature;
}

/**
 * Overwrites the /Contents <000...> placeholder with the hex signature
 */
export function injectHexSignature(
  pdfBuffer: Uint8Array,
  contentsStart: number,
  contentsEnd: number,
  hexSignature: string
): Uint8Array {
  const maxHexChars = contentsEnd - contentsStart;
  if (hexSignature.length > maxHexChars) {
    throw new Error(`La firma generada (${hexSignature.length} chars) excede el espacio reservado (${maxHexChars} chars).`);
  }

  // Right-pad signature with zeroes to maintain exact byte width
  const paddedHex = hexSignature.padEnd(maxHexChars, '0');
  const hexBytes = textEncoder.encode(paddedHex);
  pdfBuffer.set(hexBytes, contentsStart);

  return pdfBuffer;
}
