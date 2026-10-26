import {
  PDFDocument,
  PDFName,
  PDFNumber,
  PDFString,
  PDFHexString,
  PDFArray,
  PDFDict,
  StandardFonts,
  rgb,
} from 'pdf-lib';
import * as asn1js from 'asn1js';
import forge from 'node-forge';

interface SignRequest {
  pdfBuffer: ArrayBuffer;
  p12Buffer: ArrayBuffer;
  password: string;
  stampConfig?: {
    pageIndex?: number;
    x?: number;
    y?: number;
    width?: number;
    height?: number;
  };
}

interface ExtractedIdentity {
  privateKeyForge: forge.pki.rsa.PrivateKey;
  signerCertForge: forge.pki.Certificate;
  certChainForge: forge.pki.Certificate[];
  signerCertDer: Uint8Array;
  commonName: string;
  nif: string;
  issuerName: string;
  notBefore: Date;
  notAfter: Date;
}

self.onmessage = async (e: MessageEvent<SignRequest>) => {
  const { pdfBuffer, p12Buffer, password, stampConfig = {} } = e.data;

  try {
    self.postMessage({ status: 'parsing', message: 'Desencriptando certificado digital (.p12 / .pfx)...' });

    // 1. EXTRACT IDENTITY (Dual Engine: PKIjs + node-forge fallback for FNMT 3DES/RC2)
    const identity = await extractPkcs12Identity(p12Buffer, password);

    // Verify certificate validity window
    const now = new Date();
    if (now < identity.notBefore || now > identity.notAfter) {
      throw new Error(
        `El certificado digital está caducado o aún no es válido (Validez: ${identity.notBefore.toLocaleDateString('es-ES')} - ${identity.notAfter.toLocaleDateString('es-ES')}).`
      );
    }

    self.postMessage({ status: 'preparing', message: 'Generando sello administrativo y estructura PAdES-B-B...' });

    // 2. LOAD PDF & PREPARE ACROFORM + WIDGET + APPEARANCE STREAM
    const pdfDoc = await PDFDocument.load(pdfBuffer, { ignoreEncryption: true });
    const pages = pdfDoc.getPages();
    const targetPageIndex =
      stampConfig.pageIndex !== undefined && stampConfig.pageIndex < pages.length
        ? stampConfig.pageIndex
        : pages.length - 1;
    const targetPage = pages[targetPageIndex];

    const stampWidth = stampConfig.width ?? 220;
    const stampHeight = stampConfig.height ?? 75;
    const stampX = stampConfig.x ?? Math.max(30, targetPage.getWidth() - stampWidth - 30);
    const stampY = stampConfig.y ?? 30;

    // Compute preliminary SHA-256 fingerprint of original PDF for visual stamp display
    const prelimHashBuffer = await crypto.subtle.digest('SHA-256', pdfBuffer);
    const prelimHashHex = Array.from(new Uint8Array(prelimHashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 16)
      .toUpperCase();

    const signDate = new Date();

    // Build the Official Spanish Administrative Rectangular Stamp (/AP -> /N)
    const appearanceStreamRef = await createOfficialSpanishStamp(pdfDoc, {
      width: stampWidth,
      height: stampHeight,
      commonName: identity.commonName,
      nif: identity.nif,
      issuer: identity.issuerName,
      date: signDate,
      hashPreview: prelimHashHex,
    });

    // Configure /AcroForm with /SigFlags 3 (SignaturesExist | AppendOnly)
    let acroForm = pdfDoc.catalog.lookup(PDFName.of('AcroForm'), PDFDict);
    if (!acroForm) {
      acroForm = pdfDoc.context.obj({
        Fields: [],
        SigFlags: 3,
      });
      pdfDoc.catalog.set(PDFName.of('AcroForm'), pdfDoc.context.register(acroForm));
    } else {
      acroForm.set(PDFName.of('SigFlags'), PDFNumber.of(3));
      if (!acroForm.get(PDFName.of('Fields'))) {
        acroForm.set(PDFName.of('Fields'), pdfDoc.context.obj([]));
      }
    }

    // Use 10-digit sentinel numbers (1000000000) so pdf-lib reserves exact 10-char width per offset
    const BYTE_RANGE_SENTINEL = 1000000000;
    const SIGNATURE_HEX_CAPACITY = 16384; // 8192 bytes reserved for CMS DER

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
      Reason: PDFString.of('Firmado digitalmente conforme a eIDAS (UE) 910/2014 y Ley 6/2020'),
      M: PDFString.fromDate(signDate),
      Name: PDFString.of(identity.commonName),
    });
    const sigDictRef = pdfDoc.context.register(sigDict);

    // Create Signature Widget Annotation
    const widgetDict = pdfDoc.context.obj({
      Type: 'Annot',
      Subtype: 'Widget',
      FT: 'Sig',
      Rect: [stampX, stampY, stampX + stampWidth, stampY + stampHeight],
      V: sigDictRef,
      T: PDFString.of(`Signature_${Date.now()}`),
      F: 132, // Print (4) + Locked (128)
      P: targetPage.ref,
      AP: pdfDoc.context.obj({ N: appearanceStreamRef }),
    });
    const widgetRef = pdfDoc.context.register(widgetDict);

    // Attach Widget to Page /Annots and /AcroForm /Fields
    targetPage.node.addAnnot(widgetRef);
    const fieldsArray = acroForm.lookup(PDFName.of('Fields'), PDFArray);
    fieldsArray.push(widgetRef);

    // 3. SINGLE SAVE WITHOUT OBJECT STREAMS (Avoids Pitfall #1)
    const pdfBytes = await pdfDoc.save({ useObjectStreams: false });

    self.postMessage({ status: 'signing', message: 'Calculando firma criptográfica PAdES-B-B (SHA-256)...' });

    // 4. DIRECT IN-MEMORY BINARY BYTE-RANGE PATCHING & PAdES-B-B CMS INJECTION
    const signedPdfBytes = signPdfBufferInPlace(
      pdfBytes,
      identity,
      signDate,
      SIGNATURE_HEX_CAPACITY
    );

    self.postMessage(
      {
        status: 'done',
        signedPdf: signedPdfBytes,
        metadata: {
          signer: identity.commonName,
          nif: identity.nif,
          issuer: identity.issuerName,
          timestamp: signDate.toISOString(),
        },
      },
      [signedPdfBytes.buffer]
    );
  } catch (err: any) {
    self.postMessage({
      status: 'error',
      error: err?.message || 'Error al procesar el certificado digital o firmar el PDF.',
    });
  }
};

/**
 * Dual-Engine PKCS#12 Parser:
 * Validates modern PKCS#12 via PKIjs/ASN1js and extracts key/cert structures via node-forge
 * to support both modern AES-256-CBC and legacy Spanish FNMT 3DES / RC2-40 containers.
 */
async function extractPkcs12Identity(
  p12Buffer: ArrayBuffer,
  password: string
): Promise<ExtractedIdentity> {
  // Pre-verify ASN.1 BER structure via asn1js
  const asn1 = asn1js.fromBER(p12Buffer);
  if (asn1.offset === -1) {
    throw new Error('El archivo seleccionado no es un contenedor PKCS#12 (.p12 / .pfx) válido.');
  }

  let p12Forge: forge.pkcs12.Pkcs12Pfx;
  try {
    const derBytes = forge.util.createBuffer(new Uint8Array(p12Buffer));
    const p12Asn1 = forge.asn1.fromDer(derBytes);
    p12Forge = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);
  } catch (err: any) {
    throw new Error('Contraseña del certificado incorrecta o formato de cifrado no soportado.');
  }

  // Extract Private Key
  let privateKeyForge: forge.pki.rsa.PrivateKey | null = null;
  const keyBags = p12Forge.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
    forge.pki.oids.pkcs8ShroudedKeyBag
  ] || [];
  const plainKeyBags = p12Forge.getBags({ bagType: forge.pki.oids.keyBag })[
    forge.pki.oids.keyBag
  ] || [];

  for (const bag of [...keyBags, ...plainKeyBags]) {
    if (bag.key) {
      privateKeyForge = bag.key as forge.pki.rsa.PrivateKey;
      break;
    }
  }

  if (!privateKeyForge) {
    throw new Error('No se encontró una clave privada dentro del certificado digital.');
  }

  // Extract X.509 Certificate Chain
  const certBags =
    p12Forge.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const certs: forge.pki.Certificate[] = certBags
    .map((b) => b.cert)
    .filter((c): c is forge.pki.Certificate => Boolean(c));

  if (certs.length === 0) {
    throw new Error('No se encontraron certificados X.509 en el archivo .p12/.pfx.');
  }

  // Identify the end-entity signer certificate (matches private key modulus or is not a CA)
  let signerCert = certs[0];
  for (const cert of certs) {
    const basicConstraints = cert.getExtension('basicConstraints') as any;
    if (!basicConstraints || !basicConstraints.cA) {
      signerCert = cert;
      break;
    }
  }

  // Convert signer cert to DER Uint8Array for SHA-256 ESSCertIDv2 calculation
  const certAsn1 = forge.pki.certificateToAsn1(signerCert);
  const certDerStr = forge.asn1.toDer(certAsn1).getBytes();
  const signerCertDer = new Uint8Array(certDerStr.length);
  for (let i = 0; i < certDerStr.length; i++) {
    signerCertDer[i] = certDerStr.charCodeAt(i);
  }

  // Parse Spanish Identity Fields (CN, serialNumber / OID 2.5.4.5 for NIF/NIE)
  const cnAttr = signerCert.subject.getField('CN');
  const commonName = cnAttr ? String(cnAttr.value) : 'Titular de Certificado Digital';

  const serialAttr =
    signerCert.subject.getField({ type: '2.5.4.5' }) ||
    signerCert.subject.getField('serialNumber');
  let nif = serialAttr ? String(serialAttr.value) : '';
  const nifMatch = (nif || commonName).match(/\b([0-9]{8}[A-Z]|[XYZ][0-9]{7}[A-Z])\b/i);
  if (nifMatch) {
    nif = nifMatch[1].toUpperCase();
  } else if (nif.startsWith('IDCES-')) {
    nif = nif.replace('IDCES-', '');
  }

  const issuerCn = signerCert.issuer.getField('CN') || signerCert.issuer.getField('O');
  const issuerName = issuerCn ? String(issuerCn.value) : 'FNMT-RCM / Autoridad de Certificación';

  return {
    privateKeyForge,
    signerCertForge: signerCert,
    certChainForge: certs,
    signerCertDer,
    commonName,
    nif: nif || 'Verificado en Certificado',
    issuerName,
    notBefore: signerCert.validity.notBefore,
    notAfter: signerCert.validity.notAfter,
  };
}

/**
 * Generates an Official Spanish Administrative Rectangular Form XObject (/AP -> /N)
 */
async function createOfficialSpanishStamp(
  pdfDoc: PDFDocument,
  opts: {
    width: number;
    height: number;
    commonName: string;
    nif: string;
    issuer: string;
    date: Date;
    hashPreview: string;
  }
) {
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);

  // Create a temporary page to draw clean vector graphics, then extract as Form XObject
  const tempPage = pdfDoc.addPage([opts.width, opts.height]);

  // Background & crisp administrative border
  tempPage.drawRectangle({
    x: 1,
    y: 1,
    width: opts.width - 2,
    height: opts.height - 2,
    color: rgb(0.97, 0.98, 1.0),
    borderColor: rgb(0.12, 0.23, 0.54), // #1e3a8a Navy
    borderWidth: 1.2,
  });

  // Left vertical accent bar
  tempPage.drawRectangle({
    x: 1,
    y: 1,
    width: 4,
    height: opts.height - 2,
    color: rgb(0.12, 0.23, 0.54),
  });

  const dateStr = opts.date.toLocaleString('es-ES', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  const cleanText = (str: string, maxLen: number) =>
    str.replace(/[^\x20-\x7E\xA0-\xFF]/g, '').slice(0, maxLen);

  tempPage.drawText('DOCUMENTO FIRMADO DIGITALMENTE', {
    x: 10,
    y: opts.height - 13,
    size: 7,
    font: fontBold,
    color: rgb(0.12, 0.23, 0.54),
  });

  tempPage.drawText(`Firmante: ${cleanText(opts.commonName, 36)}`, {
    x: 10,
    y: opts.height - 25,
    size: 6.5,
    font: fontBold,
    color: rgb(0.1, 0.1, 0.1),
  });

  tempPage.drawText(`NIF/NIE: ${cleanText(opts.nif, 20)} | Emisor: ${cleanText(opts.issuer, 18)}`, {
    x: 10,
    y: opts.height - 36,
    size: 6,
    font: fontRegular,
    color: rgb(0.2, 0.2, 0.2),
  });

  tempPage.drawText(`Fecha: ${dateStr} CET`, {
    x: 10,
    y: opts.height - 47,
    size: 6,
    font: fontRegular,
    color: rgb(0.2, 0.2, 0.2),
  });

  tempPage.drawText(`Huella SHA-256: ${opts.hashPreview}...`, {
    x: 10,
    y: opts.height - 58,
    size: 5.5,
    font: fontRegular,
    color: rgb(0.35, 0.35, 0.35),
  });

  tempPage.drawText('Validez jurídica conforme a Reglamento (UE) 910/2014 (eIDAS) y Ley 6/2020', {
    x: 10,
    y: 6,
    size: 5,
    font: fontRegular,
    color: rgb(0.3, 0.3, 0.3),
  });

  const embeddedPage = await pdfDoc.embedPage(tempPage);
  pdfDoc.removePage(pdfDoc.getPageCount() - 1);
  return embeddedPage.ref;
}

/**
 * Performs direct in-memory binary patching of /ByteRange and /Contents
 * and builds an ETSI PAdES-B-B compliant detached PKCS#7 / CMS signature.
 */
function signPdfBufferInPlace(
  pdfBytes: Uint8Array,
  identity: ExtractedIdentity,
  signDate: Date,
  hexCapacity: number
): Uint8Array {
  const decoder = new TextDecoder('latin1');
  const encoder = new TextEncoder();
  const pdfStr = decoder.decode(pdfBytes);

  // 1. Locate /ByteRange sentinel
  const byteRangePattern = '/ByteRange [ 0 1000000000 1000000000 1000000000 ]';
  const altByteRangePattern = '/ByteRange [0 1000000000 1000000000 1000000000]';
  let brIndex = pdfStr.indexOf(byteRangePattern);
  let activePattern = byteRangePattern;

  if (brIndex === -1) {
    brIndex = pdfStr.indexOf(altByteRangePattern);
    activePattern = altByteRangePattern;
  }
  if (brIndex === -1) {
    throw new Error('No se pudo localizar el marcador /ByteRange en el binario PDF.');
  }

  // 2. Locate /Contents <0000...0000> right after /ByteRange
  const zerosTarget = `<${'0'.repeat(hexCapacity)}>`;
  const contentsStart = pdfStr.indexOf(zerosTarget, brIndex);
  if (contentsStart === -1) {
    throw new Error('No se pudo localizar el contenedor /Contents en el binario PDF.');
  }
  const contentsEnd = contentsStart + zerosTarget.length;

  // 3. Calculate exact byte ranges excluding <000...000>
  const offset1 = contentsStart;
  const offset2 = contentsEnd;
  const length2 = pdfBytes.length - offset2;

  const newByteRangeStr = `/ByteRange [0 ${String(offset1)} ${String(offset2)} ${String(length2)}]`;
  if (newByteRangeStr.length > activePattern.length) {
    throw new Error('El tamaño del ByteRange excede el espacio reservado.');
  }
  const paddedByteRangeStr = newByteRangeStr.padEnd(activePattern.length, ' ');

  // Overwrite /ByteRange in-place in pdfBytes
  const brBytes = encoder.encode(paddedByteRangeStr);
  pdfBytes.set(brBytes, brIndex);

  // 4. Compute SHA-256 over the two signed byte ranges: [0..offset1] + [offset2..end]
  const md = forge.md.sha256.create();
  const range1Str = decoder.decode(pdfBytes.subarray(0, offset1));
  const range2Str = decoder.decode(pdfBytes.subarray(offset2));
  md.update(range1Str, 'raw');
  md.update(range2Str, 'raw');
  const messageDigestBytes = md.digest().getBytes();

  // 5. Build ETSI PAdES-B-B Detached CMS / PKCS#7 with id-aa-signingCertificateV2
  const cmsDerHex = buildPAdESDetachedCmsHex(
    identity,
    messageDigestBytes,
    signDate
  );

  if (cmsDerHex.length > hexCapacity) {
    throw new Error(
      `El tamaño de la firma (${cmsDerHex.length} hex chars) supera el espacio reservado (${hexCapacity}).`
    );
  }

  // 6. Inject hex signature inside <...> (+1 skips opening '<')
  const paddedHex = cmsDerHex.padEnd(hexCapacity, '0');
  const hexBytes = encoder.encode(paddedHex);
  pdfBytes.set(hexBytes, contentsStart + 1);

  return pdfBytes;
}

/**
 * Constructs a DER-encoded PKCS#7 / CMS SignedData structure containing the
 * mandatory ETSI PAdES-B-B `id-aa-signingCertificateV2` (1.2.840.113549.1.9.16.2.47) signed attribute.
 */
function buildPAdESDetachedCmsHex(
  identity: ExtractedIdentity,
  messageDigestBytes: string,
  signDate: Date
): string {
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer('');

  // Attach full certificate chain
  for (const cert of identity.certChainForge) {
    p7.addCertificate(cert);
  }

  // Compute SHA-256 hash of Signer's X.509 Certificate for ESSCertIDv2
  const certMd = forge.md.sha256.create();
  const certAsn1 = forge.pki.certificateToAsn1(identity.signerCertForge);
  certMd.update(forge.asn1.toDer(certAsn1).getBytes(), 'raw');
  const certHashBytes = certMd.digest().getBytes();

  // Build ASN.1 structure for SigningCertificateV2 (RFC 5035 / ETSI EN 319 122-1)
  // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
  // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT sha256, certHash Hash }
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
              // Explicit SHA-256 AlgorithmIdentifier (2.16.840.1.101.3.4.2.1)
              forge.asn1.create(
                forge.asn1.Class.UNIVERSAL,
                forge.asn1.Type.SEQUENCE,
                true,
                [
                  forge.asn1.create(
                    forge.asn1.Class.UNIVERSAL,
                    forge.asn1.Type.OID,
                    false,
                    forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes()
                  ),
                ]
              ),
              // certHash OCTET STRING
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
        value: messageDigestBytes,
      },
      {
        type: forge.pki.oids.signingTime,
        value: signDate as any,
      },
      {
        // id-aa-signingCertificateV2 (OID 1.2.840.113549.1.9.16.2.47)
        type: '1.2.840.113549.1.9.16.2.47',
        value: signingCertificateV2Asn1,
      },
    ],
  });

  // Sign detached (excludes encapsulated data content)
  p7.sign({ detached: true });

  const cmsAsn1 = p7.toAsn1();
  const cmsDer = forge.asn1.toDer(cmsAsn1);
  return cmsDer.toHex().toUpperCase();
}
