import {
  PDFDocument,
  PDFName,
  PDFNumber,
  PDFString,
  PDFHexString,
  PDFArray,
  PDFDict,
  PDFRef,
  PDFRawStream,
  PDFStream,
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
    customRole?: string;
    customReason?: string;
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

const BYTE_RANGE_SENTINEL = 1000000000;
const SIGNATURE_HEX_CAPACITY = 16384; // 8192 bytes reserved for CMS DER

self.onmessage = async (e: MessageEvent<SignRequest>) => {
  const { pdfBuffer, p12Buffer, password, stampConfig = {} } = e.data;

  try {
    self.postMessage({ status: 'parsing', message: 'Desencriptando certificado digital (.p12 / .pfx)...' });

    // 1. EXTRACT IDENTITY
    const identity = await extractPkcs12Identity(p12Buffer, password);

    const now = new Date();
    if (now < identity.notBefore || now > identity.notAfter) {
      throw new Error(
        `El certificado digital está caducado o aún no es válido (Validez: ${identity.notBefore.toLocaleDateString('es-ES')} - ${identity.notAfter.toLocaleDateString('es-ES')}).`
      );
    }

    self.postMessage({ status: 'preparing', message: 'Generando sello administrativo y estructura PAdES-B-B...' });

    const originalUint8 = new Uint8Array(pdfBuffer);
    const prelimHashBuffer = await crypto.subtle.digest('SHA-256', originalUint8);
    const prelimHashHex = Array.from(new Uint8Array(prelimHashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 16)
      .toUpperCase();

    const signDate = new Date();
    const effectiveReason =
      stampConfig.customReason?.trim() ||
      'Validez jurídica conforme a Reglamento (UE) 910/2014 (eIDAS) y Ley 6/2020';

    // Detect if the PDF already contains an active cryptographic signature
    const existingText = new TextDecoder('latin1').decode(originalUint8);
    const hasExistingSignatures = /\/ByteRange\s*\[\s*\d+\s+\d+\s+\d+\s+\d+\s*\]/.test(existingText);

    let preparedPdfBytes: Uint8Array;

    if (!hasExistingSignatures) {
      // FIRST SIGNATURE: Standard single-save without object streams so xref is classic ISO 32000-1
      preparedPdfBytes = await prepareInitialSignedPdf(
        originalUint8,
        identity,
        signDate,
        prelimHashHex,
        effectiveReason,
        stampConfig
      );
    } else {
      // CO-SIGNATURE (2nd, 3rd, Nth Signature): True ISO 32000-1 Incremental Update
      // Preserves bytes 0..originalUint8.length-1 100% untouched so all prior signatures stay GREEN
      preparedPdfBytes = await prepareIncrementalCoSignedPdf(
        originalUint8,
        existingText,
        identity,
        signDate,
        prelimHashHex,
        effectiveReason,
        stampConfig
      );
    }

    self.postMessage({ status: 'signing', message: 'Calculando firma criptográfica PAdES-B-B (SHA-256)...' });

    // 4. PATCH LAST BYTERANGE SENTINEL & INJECT DETACHED CMS SIGNATURE
    const signedPdfBytes = signPdfBufferInPlace(
      preparedPdfBytes,
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
 * First signature path: prepares clean classic xref table (useObjectStreams: false)
 */
async function prepareInitialSignedPdf(
  pdfBytes: Uint8Array,
  identity: ExtractedIdentity,
  signDate: Date,
  prelimHashHex: string,
  effectiveReason: string,
  stampConfig: NonNullable<SignRequest['stampConfig']>
): Promise<Uint8Array> {
  const pdfDoc = await PDFDocument.load(pdfBytes, { ignoreEncryption: true });
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

  const appearanceStreamRef = await createOfficialSpanishStamp(pdfDoc, {
    width: stampWidth,
    height: stampHeight,
    commonName: identity.commonName,
    nif: identity.nif,
    issuer: identity.issuerName,
    date: signDate,
    hashPreview: prelimHashHex,
    customRole: stampConfig.customRole?.trim(),
    customReason: effectiveReason,
  });

  const existingAcroForm = pdfDoc.catalog.get(PDFName.of('AcroForm'));
  let acroForm: PDFDict;
  let fieldsArray: PDFArray;
  if (!existingAcroForm) {
    fieldsArray = pdfDoc.context.obj([]);
    acroForm = pdfDoc.context.obj({
      Fields: fieldsArray,
      SigFlags: 3,
    });
    pdfDoc.catalog.set(PDFName.of('AcroForm'), pdfDoc.context.register(acroForm));
  } else {
    acroForm = pdfDoc.context.lookup(existingAcroForm, PDFDict);
    acroForm.set(PDFName.of('SigFlags'), PDFNumber.of(3));
    const existingFields = acroForm.get(PDFName.of('Fields'));
    if (!existingFields) {
      fieldsArray = pdfDoc.context.obj([]);
      acroForm.set(PDFName.of('Fields'), fieldsArray);
    } else {
      fieldsArray = pdfDoc.context.lookup(existingFields, PDFArray);
    }
  }

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
    Reason: PDFString.of(effectiveReason),
    M: PDFString.fromDate(signDate),
    Name: PDFString.of(identity.commonName),
  });
  const sigDictRef = pdfDoc.context.register(sigDict);

  const widgetDict = pdfDoc.context.obj({
    Type: 'Annot',
    Subtype: 'Widget',
    FT: 'Sig',
    Rect: [stampX, stampY, stampX + stampWidth, stampY + stampHeight],
    V: sigDictRef,
    T: PDFString.of(`Signature_${Date.now()}`),
    F: 132,
    P: targetPage.ref,
    AP: pdfDoc.context.obj({ N: appearanceStreamRef }),
  });
  const widgetRef = pdfDoc.context.register(widgetDict);

  targetPage.node.addAnnot(widgetRef);
  fieldsArray.push(widgetRef);

  return await pdfDoc.save({ useObjectStreams: false });
}

/**
 * Co-signature path: True ISO 32000-1 Incremental Update
 * Appends a new revision at EOF without altering a single byte of the existing signed PDF.
 */
async function prepareIncrementalCoSignedPdf(
  originalBytes: Uint8Array,
  originalText: string,
  identity: ExtractedIdentity,
  signDate: Date,
  prelimHashHex: string,
  effectiveReason: string,
  stampConfig: NonNullable<SignRequest['stampConfig']>
): Promise<Uint8Array> {
  // 1. Find previous startxref offset from the end of the original PDF
  const startXrefMatches = [...originalText.matchAll(/startxref\s+(\d+)/g)];
  if (startXrefMatches.length === 0) {
    throw new Error('No se encontró la tabla startxref en el PDF firmado original.');
  }
  const prevXrefOffset = parseInt(startXrefMatches[startXrefMatches.length - 1][1], 10);

  // 2. Load the original PDF read-only to inspect object numbers and dictionaries
  const pdfDoc = await PDFDocument.load(originalBytes, { ignoreEncryption: true });
  const pages = pdfDoc.getPages();
  const targetPageIndex =
    stampConfig.pageIndex !== undefined && stampConfig.pageIndex < pages.length
      ? stampConfig.pageIndex
      : pages.length - 1;
  const targetPage = pages[targetPageIndex];
  const targetPageRef = targetPage.ref;

  const stampWidth = stampConfig.width ?? 220;
  const stampHeight = stampConfig.height ?? 75;
  const stampX = stampConfig.x ?? Math.max(30, targetPage.getWidth() - stampWidth - 30);
  const stampY = stampConfig.y ?? 30;

  // Determine the highest existing object number in the original PDF
  let maxObjNum = pdfDoc.context.largestObjectNumber;
  const objHeaderRegex = /(\d+)\s+\d+\s+obj\b/g;
  for (const m of originalText.matchAll(objHeaderRegex)) {
    const num = parseInt(m[1], 10);
    if (num > maxObjNum) maxObjNum = num;
  }

  let nextObjNum = maxObjNum + 1;
  const allocRef = () => PDFRef.of(nextObjNum++, 0);

  // 3. Build the visual stamp in an isolated scratch document and clone its objects with fresh IDs
  const scratchDoc = await PDFDocument.create();
  const scratchStampRef = await createOfficialSpanishStamp(scratchDoc, {
    width: stampWidth,
    height: stampHeight,
    commonName: identity.commonName,
    nif: identity.nif,
    issuer: identity.issuerName,
    date: signDate,
    hashPreview: prelimHashHex,
    customRole: stampConfig.customRole?.trim(),
    customReason: effectiveReason,
  });

  // Materialize lazy page embedders into concrete indirect objects
  await scratchDoc.save();

  // Collect reachable objects from scratchStampRef inside scratchDoc
  const scratchMap = new Map<number, PDFRef>();
  const reachableScratchNums: number[] = [];

  function collectScratchRefs(val: any) {
    if (!val) return;
    if (val instanceof PDFRef) {
      if (!scratchMap.has(val.objectNumber)) {
        scratchMap.set(val.objectNumber, allocRef());
        reachableScratchNums.push(val.objectNumber);
        const lookedUp = scratchDoc.context.lookup(val);
        collectScratchRefs(lookedUp);
      }
      return;
    }
    if (val instanceof PDFDict) {
      for (const [, entryVal] of val.entries()) collectScratchRefs(entryVal);
    } else if (val instanceof PDFArray) {
      for (let i = 0; i < val.size(); i++) collectScratchRefs(val.get(i));
    } else if (val instanceof PDFRawStream || val instanceof PDFStream) {
      collectScratchRefs(val.dict);
    }
  }

  collectScratchRefs(scratchStampRef);

  function remapScratchRefs(val: any): any {
    if (val instanceof PDFRef) {
      return scratchMap.get(val.objectNumber) || val;
    }
    if (val instanceof PDFDict) {
      for (const [k, v] of val.entries()) {
        val.set(k, remapScratchRefs(v));
      }
      return val;
    }
    if (val instanceof PDFArray) {
      for (let i = 0; i < val.size(); i++) {
        val.set(i, remapScratchRefs(val.get(i)));
      }
      return val;
    }
    if (val instanceof PDFRawStream || val instanceof PDFStream) {
      remapScratchRefs(val.dict);
      return val;
    }
    return val;
  }

  const incrementalObjects: Array<{ ref: PDFRef; obj: any }> = [];

  for (const oldNum of reachableScratchNums) {
    const newRef = scratchMap.get(oldNum)!;
    const rawObj = scratchDoc.context.lookup(PDFRef.of(oldNum, 0));
    remapScratchRefs(rawObj);
    incrementalObjects.push({ ref: newRef, obj: rawObj });
  }

  const mappedAppearanceRef = scratchMap.get(scratchStampRef.objectNumber)!;

  // 4. Create new Signature Dictionary & Widget Annotation
  const sigDictRef = allocRef();
  const widgetRef = allocRef();

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
    Reason: PDFString.of(effectiveReason),
    M: PDFString.fromDate(signDate),
    Name: PDFString.of(identity.commonName),
  });

  const widgetDict = pdfDoc.context.obj({
    Type: 'Annot',
    Subtype: 'Widget',
    FT: 'Sig',
    Rect: [stampX, stampY, stampX + stampWidth, stampY + stampHeight],
    V: sigDictRef,
    T: PDFString.of(`Signature_${Date.now()}_${nextObjNum}`),
    F: 132,
    P: targetPageRef,
    AP: pdfDoc.context.obj({ N: mappedAppearanceRef }),
  });

  incrementalObjects.push({ ref: sigDictRef, obj: sigDict });
  incrementalObjects.push({ ref: widgetRef, obj: widgetDict });

  // 5. Update Target Page (/Annots)
  const annotsEntry = targetPage.node.get(PDFName.of('Annots'));
  if (annotsEntry instanceof PDFRef) {
    const annotsArray = pdfDoc.context.lookup(annotsEntry, PDFArray);
    annotsArray.push(widgetRef);
    incrementalObjects.push({ ref: annotsEntry, obj: annotsArray });
  } else {
    targetPage.node.addAnnot(widgetRef);
    incrementalObjects.push({ ref: targetPageRef, obj: targetPage.node });
  }

  // 6. Update Catalog /AcroForm (/Fields)
  let rootRef: PDFRef | null = null;
  for (const [ref, obj] of pdfDoc.context.enumerateIndirectObjects()) {
    if (obj === pdfDoc.catalog) {
      rootRef = ref;
      break;
    }
  }
  if (!rootRef) {
    const rootMatch = originalText.match(/\/Root\s+(\d+)\s+(\d+)\s+R/);
    if (rootMatch) {
      rootRef = PDFRef.of(parseInt(rootMatch[1], 10), parseInt(rootMatch[2], 10));
    }
  }
  if (!rootRef) {
    throw new Error('No se pudo localizar la referencia /Root en el PDF original.');
  }

  const acroFormEntry = pdfDoc.catalog.get(PDFName.of('AcroForm'));
  if (acroFormEntry instanceof PDFRef) {
    const acroFormDict = pdfDoc.context.lookup(acroFormEntry, PDFDict);
    acroFormDict.set(PDFName.of('SigFlags'), PDFNumber.of(3));
    const fieldsEntry = acroFormDict.get(PDFName.of('Fields'));
    if (fieldsEntry instanceof PDFRef) {
      const fieldsArr = pdfDoc.context.lookup(fieldsEntry, PDFArray);
      fieldsArr.push(widgetRef);
      incrementalObjects.push({ ref: fieldsEntry, obj: fieldsArr });
      incrementalObjects.push({ ref: acroFormEntry, obj: acroFormDict });
    } else {
      const fieldsArr = pdfDoc.context.lookup(fieldsEntry, PDFArray);
      fieldsArr.push(widgetRef);
      incrementalObjects.push({ ref: acroFormEntry, obj: acroFormDict });
    }
  } else if (acroFormEntry instanceof PDFDict) {
    acroFormEntry.set(PDFName.of('SigFlags'), PDFNumber.of(3));
    const fieldsArr = acroFormEntry.lookup(PDFName.of('Fields'), PDFArray);
    fieldsArr.push(widgetRef);
    incrementalObjects.push({ ref: rootRef, obj: pdfDoc.catalog });
  } else {
    const newAcroRef = allocRef();
    const newAcroDict = pdfDoc.context.obj({
      Fields: [widgetRef],
      SigFlags: 3,
    });
    pdfDoc.catalog.set(PDFName.of('AcroForm'), newAcroRef);
    incrementalObjects.push({ ref: newAcroRef, obj: newAcroDict });
    incrementalObjects.push({ ref: rootRef, obj: pdfDoc.catalog });
  }

  // Sort modified/new objects by object number for clean xref subsection emission
  incrementalObjects.sort((a, b) => a.ref.objectNumber - b.ref.objectNumber);

  // 7. Serialize Incremental Update Buffer
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [originalBytes];
  let currentOffset = originalBytes.length;

  const pushBytes = (bytes: Uint8Array) => {
    chunks.push(bytes);
    currentOffset += bytes.length;
  };
  const pushStr = (str: string) => pushBytes(encoder.encode(str));

  // Ensure newline before starting incremental section
  if (
    originalBytes[originalBytes.length - 1] !== 0x0a &&
    originalBytes[originalBytes.length - 1] !== 0x0d
  ) {
    pushStr('\n');
  }

  const xrefOffsets = new Map<number, number>();

  for (const item of incrementalObjects) {
    xrefOffsets.set(item.ref.objectNumber, currentOffset);
    pushStr(`${item.ref.objectNumber} ${item.ref.generationNumber} obj\n`);
    const objSize = item.obj.sizeInBytes();
    const objBuf = new Uint8Array(objSize);
    item.obj.copyBytesInto(objBuf, 0);
    pushBytes(objBuf);
    pushStr('\nendobj\n');
  }

  // 8. Build Incremental Cross-Reference Table (xref subsections)
  const newXrefOffset = currentOffset;
  pushStr('xref\n');

  let idx = 0;
  while (idx < incrementalObjects.length) {
    const startObjNum = incrementalObjects[idx].ref.objectNumber;
    let endIdx = idx;
    while (
      endIdx + 1 < incrementalObjects.length &&
      incrementalObjects[endIdx + 1].ref.objectNumber ===
        incrementalObjects[endIdx].ref.objectNumber + 1
    ) {
      endIdx++;
    }
    const count = endIdx - idx + 1;
    pushStr(`${startObjNum} ${count}\n`);
    for (let k = idx; k <= endIdx; k++) {
      const objNum = incrementalObjects[k].ref.objectNumber;
      const genNum = incrementalObjects[k].ref.generationNumber;
      const offset = xrefOffsets.get(objNum)!;
      // Exact 20-byte ISO 32000-1 xref entry: "oooooooooo ggggg n \n"
      const entry = `${String(offset).padStart(10, '0')} ${String(genNum).padStart(5, '0')} n \n`;
      pushStr(entry);
    }
    idx = endIdx + 1;
  }

  // 9. Build Incremental Trailer with /Prev pointing to the previous xref table
  const infoMatch = originalText.match(/\/Info\s+(\d+\s+\d+\s+R)/);
  const idMatch = originalText.match(/\/ID\s*(\[\s*<[^>]+>\s*<[^>]+>\s*\])/);

  let trailerStr = `trailer\n<<\n/Size ${nextObjNum}\n/Root ${rootRef.objectNumber} ${rootRef.generationNumber} R\n/Prev ${prevXrefOffset}\n`;
  if (infoMatch) {
    trailerStr += `/Info ${infoMatch[1]}\n`;
  }
  if (idMatch) {
    trailerStr += `/ID ${idMatch[1]}\n`;
  }
  trailerStr += `>>\nstartxref\n${newXrefOffset}\n%%EOF\n`;
  pushStr(trailerStr);

  // Concatenate all chunks into a single Uint8Array
  const finalBuffer = new Uint8Array(currentOffset);
  let writePos = 0;
  for (const chunk of chunks) {
    finalBuffer.set(chunk, writePos);
    writePos += chunk.length;
  }

  return finalBuffer;
}

async function extractPkcs12Identity(
  p12Buffer: ArrayBuffer,
  password: string
): Promise<ExtractedIdentity> {
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

  const certBags =
    p12Forge.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const certs: forge.pki.Certificate[] = certBags
    .map((b) => b.cert)
    .filter((c): c is forge.pki.Certificate => Boolean(c));

  if (certs.length === 0) {
    throw new Error('No se encontraron certificados X.509 en el archivo .p12/.pfx.');
  }

  let signerCert = certs[0];
  for (const cert of certs) {
    const basicConstraints = cert.getExtension('basicConstraints') as any;
    if (!basicConstraints || !basicConstraints.cA) {
      signerCert = cert;
      break;
    }
  }

  const certAsn1 = forge.pki.certificateToAsn1(signerCert);
  const certDerStr = forge.asn1.toDer(certAsn1).getBytes();
  const signerCertDer = new Uint8Array(certDerStr.length);
  for (let i = 0; i < certDerStr.length; i++) {
    signerCertDer[i] = certDerStr.charCodeAt(i);
  }

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
    customRole?: string;
    customReason?: string;
  }
) {
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);

  const tempPage = pdfDoc.addPage([opts.width, opts.height]);

  tempPage.drawRectangle({
    x: 1,
    y: 1,
    width: opts.width - 2,
    height: opts.height - 2,
    color: rgb(0.97, 0.98, 1.0),
    borderColor: rgb(0.12, 0.23, 0.54),
    borderWidth: 1.2,
  });

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

  const thirdLine = opts.customRole
    ? `NIF: ${cleanText(opts.nif, 14)} | Cargo/Entidad: ${cleanText(opts.customRole, 35)}`
    : `NIF/NIE: ${cleanText(opts.nif, 20)} | Emisor: ${cleanText(opts.issuer, 18)}`;

  tempPage.drawText(thirdLine, {
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

  const bottomLine =
    opts.customReason || 'Validez jurídica conforme a Reglamento (UE) 910/2014 (eIDAS) y Ley 6/2020';

  tempPage.drawText(cleanText(bottomLine, 56), {
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

function signPdfBufferInPlace(
  pdfBytes: Uint8Array,
  identity: ExtractedIdentity,
  signDate: Date,
  hexCapacity: number
): Uint8Array {
  const decoder = new TextDecoder('latin1');
  const encoder = new TextEncoder();
  const pdfStr = decoder.decode(pdfBytes);

  // Use lastIndexOf so we always target the newly appended signature dictionary
  const byteRangePattern = '/ByteRange [ 0 1000000000 1000000000 1000000000 ]';
  const altByteRangePattern = '/ByteRange [0 1000000000 1000000000 1000000000]';
  let brIndex = pdfStr.lastIndexOf(byteRangePattern);
  let activePattern = byteRangePattern;

  if (brIndex === -1) {
    brIndex = pdfStr.lastIndexOf(altByteRangePattern);
    activePattern = altByteRangePattern;
  }
  if (brIndex === -1) {
    throw new Error('No se pudo localizar el marcador /ByteRange en el binario PDF.');
  }

  const zerosTarget = `<${'0'.repeat(hexCapacity)}>`;
  const contentsStart = pdfStr.indexOf(zerosTarget, brIndex);
  if (contentsStart === -1) {
    throw new Error('No se pudo localizar el contenedor /Contents en el binario PDF.');
  }
  const contentsEnd = contentsStart + zerosTarget.length;

  const offset1 = contentsStart;
  const offset2 = contentsEnd;
  const length2 = pdfBytes.length - offset2;

  const newByteRangeStr = `/ByteRange [0 ${String(offset1)} ${String(offset2)} ${String(length2)}]`;
  if (newByteRangeStr.length > activePattern.length) {
    throw new Error('El tamaño del ByteRange excede el espacio reservado.');
  }
  const paddedByteRangeStr = newByteRangeStr.padEnd(activePattern.length, ' ');

  const brBytes = encoder.encode(paddedByteRangeStr);
  pdfBytes.set(brBytes, brIndex);

  const part1Bytes = forge.util.createBuffer(pdfBytes.subarray(0, offset1)).getBytes();
  const part2Bytes = forge.util.createBuffer(pdfBytes.subarray(offset2)).getBytes();

  const cmsDerHex = buildPAdESDetachedCmsHex(
    identity,
    part1Bytes,
    part2Bytes,
    signDate
  );

  if (cmsDerHex.length > hexCapacity) {
    throw new Error(
      `El tamaño de la firma (${cmsDerHex.length} hex chars) supera el espacio reservado (${hexCapacity}).`
    );
  }

  const paddedHex = cmsDerHex.padEnd(hexCapacity, '0');
  const hexBytes = encoder.encode(paddedHex);
  pdfBytes.set(hexBytes, contentsStart + 1);

  return pdfBytes;
}

function buildPAdESDetachedCmsHex(
  identity: ExtractedIdentity,
  part1Bytes: string,
  part2Bytes: string,
  signDate: Date
): string {
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
                forge.asn1.Type.OID,
                false,
                forge.asn1.oidToDer('2.16.840.1.101.3.4.2.1').getBytes()
              ),
            ]
          ),
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OCTETSTRING,
            false,
            certHashBytes
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
      },
      {
        type: forge.pki.oids.signingTime,
        value: signDate as any,
      },
      {
        type: '1.2.840.113549.1.9.16.2.47',
        value: signingCertificateV2Asn1,
      },
    ],
  });

  p7.sign({ detached: true });

  const cmsAsn1 = p7.toAsn1();
  const cmsDer = forge.asn1.toDer(cmsAsn1);
  return cmsDer.toHex().toUpperCase();
}
